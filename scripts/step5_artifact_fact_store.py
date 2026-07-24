#!/usr/bin/env python3
"""Per-run immutable facts from SHA-bound Step5 runtime artifacts."""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import zipfile
from collections import Counter, OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
import tempfile
from typing import Any, Mapping

from path_runtime import short_temporary_directory


@dataclass(frozen=True)
class ArtifactIdentity:
    coord: str
    path: str
    sha256: str
    artifact_entry: str
    target_jdk: str


@dataclass(frozen=True)
class ClassLocation:
    logical_name: str
    binary_name: str
    physical_entry: str
    multi_release_version: str | int


@dataclass(frozen=True)
class ArtifactInventory:
    identity: ArtifactIdentity
    classes: tuple[ClassLocation, ...]
    resources: tuple[str, ...]
    physical_classes: tuple[str, ...] = ()
    failure: str = ""
    multi_release: bool = False
    target_jdk_resolved: bool = False
    file_identity: tuple[int, int, int, int, int] = ()


@dataclass(frozen=True)
class FactOutcome:
    status: str
    value: Any
    reason: str = ""
    parser: str = ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_handle(handle) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    handle.seek(0)
    return digest.hexdigest()


def _file_identity(stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat_result.st_size),
        int(stat_result.st_mtime_ns),
        int(stat_result.st_ctime_ns),
    )


def _target_jdk_major(value: str) -> int | None:
    try:
        raw = str(value or "").strip()
        return int(raw.split(".", 1)[1]) if raw.startswith("1.") else int(raw.split(".", 1)[0])
    except ValueError:
        return None


def _effective_class_locations(
    names: tuple[str, ...], target_jdk: str, *, multi_release_enabled: bool,
) -> tuple[ClassLocation, ...]:
    base: dict[str, str] = {}
    versioned: dict[str, list[tuple[int, str]]] = {}
    for raw_name in names:
        name = str(raw_name)
        if not name.endswith(".class"):
            continue
        match = re.match(r"^META-INF/versions/(\d+)/(.*\.class)$", name)
        if match:
            if multi_release_enabled:
                versioned.setdefault(match.group(2), []).append((int(match.group(1)), name))
        elif not name.startswith("META-INF/"):
            base[name] = name

    target = _target_jdk_major(target_jdk)
    result: list[ClassLocation] = []
    for logical_name in sorted(set(base) | set(versioned)):
        selected: list[tuple[str, str | int]] = []
        if target is None:
            if logical_name in base:
                selected.append((base[logical_name], "base"))
            selected.extend(
                (entry, version)
                for version, entry in sorted(versioned.get(logical_name, ()))
            )
        else:
            selected_entry = base.get(logical_name)
            selected_version = "base"
            for version, entry in sorted(versioned.get(logical_name, ())):
                if version <= target:
                    selected_entry = entry
                    selected_version = version
            if selected_entry:
                selected.append((selected_entry, selected_version))
        for physical_entry, selected_version in selected:
            result.append(ClassLocation(
                logical_name=logical_name,
                binary_name=logical_name[:-6].replace("/", "."),
                physical_entry=physical_entry,
                multi_release_version=selected_version,
            ))
    return tuple(result)


class Step5ArtifactFactStore:
    """Shares immutable archive inventories inside one Step5 process."""

    def __init__(
        self,
        identities: Mapping[str, ArtifactIdentity],
        identity_failures: Mapping[str, str] | None = None,
    ):
        self._identities = dict(identities)
        self._identity_failures = dict(identity_failures or {})
        self._inventories: dict[str, ArtifactInventory] = {}
        self._inventory_inflight: dict[str, threading.Event] = {}
        self._facts: dict[tuple[Any, ...], FactOutcome] = {}
        self._fact_inflight: dict[tuple[Any, ...], threading.Event] = {}
        self._metrics: dict[str, int | float] = {
            "inventory_builds": 0,
            "inventory_hits": 0,
            "inventory_elapsed_sec": 0.0,
            "class_bytes_reads": 0,
            "class_bytes_read": 0,
            "resource_bytes_reads": 0,
            "resource_bytes_read": 0,
            "fact_hits": 0,
            "fact_misses": 0,
            "fact_failures": 0,
            "fact_build_elapsed_sec": 0.0,
            "javap_requests": 0,
            "javap_starts": 0,
            "javap_shared_hits": 0,
            "javap_failures": 0,
            "stream_cache_peak_bytes": 0,
            "stream_cache_evictions": 0,
        }
        self._lock = threading.Lock()

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, Any] | None):
        catalog = catalog or {}
        target_jdk = str(catalog.get("target_jdk") or "")
        identities: dict[str, ArtifactIdentity] = {}
        identity_failures: dict[str, str] = {}
        entries = [
            ("", item) for item in (catalog.get("entries") or ())
        ]
        if not entries:
            entries = list((catalog.get("by_coord") or {}).items())
        for catalog_coord, item in entries:
            coord = str(
                (item or {}).get("coord") or catalog_coord or ""
            ).strip()
            if not coord:
                continue
            identity = ArtifactIdentity(
                coord=coord,
                path=str(item.get("jar_path") or ""),
                sha256=str(item.get("sha256") or "").lower(),
                artifact_entry=str(item.get("artifact_entry") or ""),
                target_jdk=target_jdk,
            )
            previous = identities.get(coord)
            if previous is None:
                identities[coord] = identity
            elif previous != identity:
                identity_failures[coord] = f"artifact_coord_identity_conflict:{coord}"
        return cls(identities, identity_failures)

    def inventory(self, coord: str) -> ArtifactInventory:
        coord = str(coord or "").strip()
        while True:
            with self._lock:
                cached = self._inventories.get(coord)
                if cached is not None:
                    self._metrics["inventory_hits"] += 1
                    return cached
                event = self._inventory_inflight.get(coord)
                owner = event is None
                if owner:
                    event = threading.Event()
                    self._inventory_inflight[coord] = event
            if owner:
                break
            event.wait()

        identity = self._identities.get(coord) or ArtifactIdentity(coord, "", "", "", "")
        started_at = time.perf_counter()
        try:
            if coord in self._identity_failures:
                raise ValueError(self._identity_failures[coord])
            inventory = self._build_inventory(identity)
        except Exception as exc:  # failure remains explicit and shared
            inventory = ArtifactInventory(
                identity=identity,
                classes=(),
                resources=(),
                physical_classes=(),
                failure=f"{type(exc).__name__}: {exc}",
            )
        with self._lock:
            self._inventories[coord] = inventory
            self._metrics["inventory_builds"] += 1
            self._metrics["inventory_elapsed_sec"] += time.perf_counter() - started_at
            self._inventory_inflight.pop(coord, None)
            event.set()
        return inventory

    def _identity(self, coord: str) -> ArtifactIdentity:
        identity = self._identities.get(str(coord or "").strip())
        if identity is None:
            raise KeyError(f"artifact_coord_missing:{coord}")
        return identity

    def _verified_inventory(self, coord: str) -> ArtifactInventory:
        inventory = self.inventory(coord)
        if inventory.failure:
            raise ValueError(inventory.failure)
        self._assert_path_identity(inventory)
        return inventory

    def verified_inventory(self, coord: str) -> ArtifactInventory:
        """Return an inventory only while its catalog path still identifies it."""
        return self._verified_inventory(coord)

    @contextmanager
    def open_verified_artifact(self, coord: str):
        """Yield one SHA-bound file descriptor and reject path changes on exit."""
        inventory = self._verified_inventory(coord)
        with self._open_verified_artifact(inventory) as handle:
            try:
                yield handle
            finally:
                if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
                    raise ValueError("artifact_changed_after_inventory")
                self._assert_path_identity(inventory)

    @staticmethod
    def _assert_path_identity(inventory: ArtifactInventory) -> None:
        try:
            current = _file_identity(Path(inventory.identity.path).stat())
        except OSError as exc:
            raise ValueError(f"artifact_changed_after_inventory:{exc}") from exc
        if current != inventory.file_identity:
            raise ValueError("artifact_changed_after_inventory")

    @staticmethod
    def _open_verified_artifact(inventory: ArtifactInventory):
        handle = Path(inventory.identity.path).open("rb")
        if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
            handle.close()
            raise ValueError("artifact_changed_after_inventory")
        return handle

    def class_bytes(self, coord: str, location: ClassLocation) -> FactOutcome:
        try:
            inventory = self._verified_inventory(coord)
            if location not in inventory.classes:
                raise KeyError(f"class_location_not_in_inventory:{location.physical_entry}")
            with self._open_verified_artifact(inventory) as handle:
                with zipfile.ZipFile(handle) as archive:
                    content = archive.read(location.physical_entry)
                if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
                    raise ValueError("artifact_changed_after_inventory")
            self._assert_path_identity(inventory)
            with self._lock:
                self._metrics["class_bytes_reads"] += 1
                self._metrics["class_bytes_read"] += len(content)
            return FactOutcome("complete", content, "", "zipfile")
        except Exception as exc:
            return FactOutcome("failed", None, f"{type(exc).__name__}: {exc}", "zipfile")

    def iter_class_bytes(self, coord: str):
        """Yield effective classes in inventory order from one ZIP open."""
        for location, content, _reader in self.iter_class_bytes_with_reader(coord):
            yield location, content

    def iter_class_bytes_with_reader(self, coord: str):
        """Stream classes while allowing bounded reads from the same verified ZIP."""
        inventory = self._verified_inventory(coord)
        with self._open_verified_artifact(inventory) as handle:
            cache_limit = 4 * 1024 * 1024
            cached = OrderedDict()
            cached_bytes = 0
            try:
                with zipfile.ZipFile(handle) as archive:
                    def read_archive(location):
                        content = archive.read(location.physical_entry)
                        with self._lock:
                            self._metrics["class_bytes_reads"] += 1
                            self._metrics["class_bytes_read"] += len(content)
                        return content

                    def read_location(location):
                        nonlocal cached_bytes
                        if location not in inventory.classes:
                            raise KeyError(
                                "class_location_not_in_inventory:"
                                f"{location.physical_entry}"
                            )
                        if location in cached:
                            content = cached.pop(location)
                            cached[location] = content
                            return content
                        content = read_archive(location)
                        if len(content) <= cache_limit:
                            while cached and cached_bytes + len(content) > cache_limit:
                                _discarded_location, discarded = cached.popitem(last=False)
                                cached_bytes -= len(discarded)
                                with self._lock:
                                    self._metrics["stream_cache_evictions"] += 1
                            cached[location] = content
                            cached_bytes += len(content)
                            with self._lock:
                                self._metrics["stream_cache_peak_bytes"] = max(
                                    self._metrics["stream_cache_peak_bytes"], cached_bytes,
                                )
                        return content

                    for location in inventory.classes:
                        content = cached.pop(location, None)
                        if content is not None:
                            cached_bytes -= len(content)
                        else:
                            content = read_archive(location)
                        yield location, content, read_location
            finally:
                if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
                    raise ValueError("artifact_changed_after_inventory")
                self._assert_path_identity(inventory)

    def iter_physical_class_bytes(self, coord: str):
        """Yield all physical class entries in stable name order from one ZIP open."""
        inventory = self._verified_inventory(coord)
        with self._open_verified_artifact(inventory) as handle:
            try:
                with zipfile.ZipFile(handle) as archive:
                    for entry in inventory.physical_classes:
                        content = archive.read(entry)
                        with self._lock:
                            self._metrics["class_bytes_reads"] += 1
                            self._metrics["class_bytes_read"] += len(content)
                        yield entry, content
            finally:
                if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
                    raise ValueError("artifact_changed_after_inventory")
                self._assert_path_identity(inventory)

    def resource_bytes(
        self, coord: str, resource_name: str, *, retain: bool = True,
    ) -> FactOutcome:
        """Return one immutable resource, with absence/failure kept explicit."""
        identity = self._identity(coord)
        try:
            self._verified_inventory(coord)
        except Exception as exc:
            return FactOutcome(
                "failed", None, f"{type(exc).__name__}: {exc}", "zipfile",
            )
        resource_name = str(resource_name or "")
        key = (
            "resource", identity.sha256, identity.target_jdk, resource_name,
        )

        def produce():
            inventory = self._verified_inventory(coord)
            if resource_name not in inventory.resources:
                raise KeyError(f"resource_not_in_inventory:{resource_name}")
            with self._open_verified_artifact(inventory) as handle:
                with zipfile.ZipFile(handle) as archive:
                    content = archive.read(resource_name)
                if _file_identity(os.fstat(handle.fileno())) != inventory.file_identity:
                    raise ValueError("artifact_changed_after_inventory")
            self._assert_path_identity(inventory)
            with self._lock:
                self._metrics["resource_bytes_reads"] += 1
                self._metrics["resource_bytes_read"] += len(content)
            return content

        if retain:
            return self._single_flight(key, produce, parser="zipfile")
        try:
            return FactOutcome("complete", produce(), "", "zipfile")
        except Exception as exc:
            with self._lock:
                self._metrics["fact_failures"] += 1
            return FactOutcome(
                "failed", None, f"{type(exc).__name__}: {exc}", "zipfile",
            )

    def _single_flight(self, key, producer, *, parser: str) -> FactOutcome:
        while True:
            with self._lock:
                cached = self._facts.get(key)
                if cached is not None:
                    self._metrics["fact_hits"] += 1
                    return cached
                event = self._fact_inflight.get(key)
                owner = event is None
                if owner:
                    event = threading.Event()
                    self._fact_inflight[key] = event
                    self._metrics["fact_misses"] += 1
            if owner:
                break
            event.wait()
        started_at = time.perf_counter()
        try:
            value = producer()
            outcome = FactOutcome("complete", value, "", parser)
        except Exception as exc:
            outcome = FactOutcome(
                "failed", None, f"{type(exc).__name__}: {exc}", parser,
            )
        with self._lock:
            if outcome.status != "complete":
                self._metrics["fact_failures"] += 1
            self._metrics["fact_build_elapsed_sec"] += time.perf_counter() - started_at
            self._facts[key] = outcome
            self._fact_inflight.pop(key, None)
            event.set()
        return outcome

    def class_fact(self, coord, location, namespace, producer) -> FactOutcome:
        identity = self._identity(coord)
        key = (
            "class", identity.sha256, identity.target_jdk,
            location.physical_entry, str(namespace or ""),
        )

        def produce():
            content = self.class_bytes(coord, location)
            if content.status != "complete":
                raise ValueError(content.reason)
            return producer(content.value)

        return self._single_flight(key, produce, parser="classfile")

    def class_fact_from_bytes(
        self, coord, location, namespace, content, producer,
    ) -> FactOutcome:
        """Publish/consume a class fact when the caller already streams class bytes."""
        identity = self._identity(coord)
        try:
            inventory = self._verified_inventory(coord)
        except Exception as exc:
            return FactOutcome(
                "failed", None, f"{type(exc).__name__}: {exc}", "classfile",
            )
        if location not in inventory.classes:
            return FactOutcome(
                "failed", None,
                f"class_location_not_in_inventory:{location.physical_entry}",
                "classfile",
            )
        key = (
            "class", identity.sha256, identity.target_jdk,
            location.physical_entry, str(namespace or ""),
        )
        return self._single_flight(
            key, lambda: producer(content), parser="classfile",
        )

    def javap_fact(
        self, coord, location, profile, producer, *, retain: bool = True,
    ) -> FactOutcome:
        identity = self._identity(coord)
        try:
            self._verified_inventory(coord)
        except Exception as exc:
            with self._lock:
                self._metrics["javap_requests"] += 1
                self._metrics["javap_failures"] += 1
            return FactOutcome(
                "failed", None, f"{type(exc).__name__}: {exc}", "javap",
            )
        key = (
            "javap", identity.sha256, identity.target_jdk,
            location.physical_entry, str(profile or ""),
        )
        with self._lock:
            self._metrics["javap_requests"] += 1
            already_cached = key in self._facts or key in self._fact_inflight
            if already_cached:
                self._metrics["javap_shared_hits"] += 1

        def produce():
            with self._lock:
                self._metrics["javap_starts"] += 1
            inventory = self._verified_inventory(coord)
            canonical_location = next((
                item for item in inventory.classes
                if item.physical_entry == location.physical_entry
            ), None)
            if canonical_location is None:
                raise KeyError(
                    f"class_location_not_in_inventory:{location.physical_entry}"
                )
            content = self.class_bytes(coord, canonical_location)
            if content.status != "complete":
                raise ValueError(content.reason)
            binary_name = str(location.binary_name or "")
            if not re.fullmatch(r"[A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)*", binary_name):
                raise ValueError(f"invalid_class_binary_name:{binary_name}")
            with short_temporary_directory(prefix="s5-javap") as tmp:
                class_path = Path(tmp).joinpath(*binary_name.split(".")).with_suffix(".class")
                class_path.parent.mkdir(parents=True, exist_ok=True)
                class_path.write_bytes(content.value)
                result = producer(replace(identity, path=tmp), location, profile)
            self._assert_path_identity(inventory)
            return result

        if retain:
            outcome = self._single_flight(key, produce, parser="javap")
        else:
            started_at = time.perf_counter()
            with self._lock:
                self._metrics["fact_misses"] += 1
            try:
                outcome = FactOutcome("complete", produce(), "", "javap")
            except Exception as exc:
                outcome = FactOutcome(
                    "failed", None, f"{type(exc).__name__}: {exc}", "javap",
                )
            with self._lock:
                if outcome.status != "complete":
                    self._metrics["fact_failures"] += 1
                self._metrics["fact_build_elapsed_sec"] += (
                    time.perf_counter() - started_at
                )
        if outcome.status != "complete":
            with self._lock:
                self._metrics["javap_failures"] += 1
        return outcome

    def metrics(self) -> dict[str, int | float]:
        with self._lock:
            metrics = {
                key: round(value, 6) if isinstance(value, float) else value
                for key, value in self._metrics.items()
            }
            metrics["retained_facts"] = len(self._facts)
            return metrics

    @staticmethod
    def _build_inventory(identity: ArtifactIdentity) -> ArtifactInventory:
        path = Path(identity.path)
        if not path.is_file():
            raise FileNotFoundError(f"artifact_missing:{path}")
        with path.open("rb") as handle:
            before_identity = _file_identity(os.fstat(handle.fileno()))
            digest = _sha256_handle(handle)
            if not re.fullmatch(r"[0-9a-f]{64}", identity.sha256):
                raise ValueError("artifact_sha256_invalid")
            if digest != identity.sha256:
                raise ValueError(
                    f"artifact_sha256_mismatch:expected={identity.sha256}:actual={digest}"
                )
            with zipfile.ZipFile(handle) as archive:
                names = tuple(archive.namelist())
                duplicates = sorted(
                    name for name, count in Counter(names).items() if count > 1
                )
                if duplicates:
                    raise ValueError(
                        "artifact_duplicate_entries:" + ",".join(duplicates[:20])
                    )
                try:
                    manifest = archive.read("META-INF/MANIFEST.MF").decode(
                        "utf-8", errors="replace"
                    )
                except KeyError:
                    manifest = ""
                multi_release = bool(re.search(
                    r"(?im)^Multi-Release\s*:\s*true\s*$", manifest,
                ))
                classes = _effective_class_locations(
                    names, identity.target_jdk, multi_release_enabled=multi_release,
                )
                resources = tuple(sorted(
                    name for name in names if not name.endswith(".class")
                ))
                physical_classes = tuple(sorted(
                    name for name in names if name.endswith(".class")
                ))
            after_identity = _file_identity(os.fstat(handle.fileno()))
            if after_identity != before_identity:
                raise ValueError("artifact_changed_during_inventory")
        if _file_identity(path.stat()) != before_identity:
            raise ValueError("artifact_changed_during_inventory")
        return ArtifactInventory(
            identity=identity,
            classes=classes,
            resources=resources,
            physical_classes=physical_classes,
            multi_release=multi_release,
            target_jdk_resolved=_target_jdk_major(identity.target_jdk) is not None,
            file_identity=before_identity,
        )


__all__ = [
    "ArtifactIdentity",
    "ArtifactInventory",
    "ClassLocation",
    "FactOutcome",
    "Step5ArtifactFactStore",
]
