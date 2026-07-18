#!/usr/bin/env python3
"""Per-run immutable facts from SHA-bound Step5 runtime artifacts."""

from __future__ import annotations

import hashlib
import re
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


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
    multi_release_version: str


@dataclass(frozen=True)
class ArtifactInventory:
    identity: ArtifactIdentity
    classes: tuple[ClassLocation, ...]
    resources: tuple[str, ...]
    physical_classes: tuple[str, ...] = ()
    failure: str = ""


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
        selected: list[tuple[str, str]] = []
        if target is None:
            if logical_name in base:
                selected.append((base[logical_name], "base"))
            selected.extend(
                (entry, str(version))
                for version, entry in sorted(versioned.get(logical_name, ()))
            )
        else:
            selected_entry = base.get(logical_name)
            selected_version = "base"
            for version, entry in sorted(versioned.get(logical_name, ())):
                if version <= target:
                    selected_entry = entry
                    selected_version = str(version)
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

    def __init__(self, identities: Mapping[str, ArtifactIdentity]):
        self._identities = dict(identities)
        self._inventories: dict[str, ArtifactInventory] = {}
        self._inventory_inflight: dict[str, threading.Event] = {}
        self._facts: dict[tuple[Any, ...], FactOutcome] = {}
        self._fact_inflight: dict[tuple[Any, ...], threading.Event] = {}
        self._metrics: dict[str, int | float] = {
            "inventory_builds": 0,
            "inventory_hits": 0,
            "class_bytes_reads": 0,
            "class_bytes_read": 0,
            "resource_bytes_reads": 0,
            "resource_bytes_read": 0,
            "fact_hits": 0,
            "fact_misses": 0,
            "fact_failures": 0,
            "javap_requests": 0,
            "javap_starts": 0,
            "javap_shared_hits": 0,
            "javap_failures": 0,
        }
        self._lock = threading.Lock()

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, Any] | None):
        catalog = catalog or {}
        target_jdk = str(catalog.get("target_jdk") or "")
        identities: dict[str, ArtifactIdentity] = {}
        entries = list(catalog.get("entries") or ())
        if not entries:
            entries = list((catalog.get("by_coord") or {}).values())
        for item in entries:
            coord = str((item or {}).get("coord") or "").strip()
            if not coord or coord in identities:
                continue
            identities[coord] = ArtifactIdentity(
                coord=coord,
                path=str(item.get("jar_path") or ""),
                sha256=str(item.get("sha256") or "").lower(),
                artifact_entry=str(item.get("artifact_entry") or ""),
                target_jdk=target_jdk,
            )
        return cls(identities)

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
        try:
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
            self._inventory_inflight.pop(coord, None)
            event.set()
        return inventory

    def _identity(self, coord: str) -> ArtifactIdentity:
        identity = self._identities.get(str(coord or "").strip())
        if identity is None:
            raise KeyError(f"artifact_coord_missing:{coord}")
        return identity

    def class_bytes(self, coord: str, location: ClassLocation) -> FactOutcome:
        try:
            identity = self._identity(coord)
            inventory = self.inventory(coord)
            if inventory.failure:
                raise ValueError(inventory.failure)
            if location not in inventory.classes:
                raise KeyError(f"class_location_not_in_inventory:{location.physical_entry}")
            with zipfile.ZipFile(identity.path) as archive:
                content = archive.read(location.physical_entry)
            with self._lock:
                self._metrics["class_bytes_reads"] += 1
                self._metrics["class_bytes_read"] += len(content)
            return FactOutcome("complete", content, "", "zipfile")
        except Exception as exc:
            return FactOutcome("failed", None, f"{type(exc).__name__}: {exc}", "zipfile")

    def iter_class_bytes(self, coord: str):
        """Yield effective classes in inventory order from one ZIP open."""
        identity = self._identity(coord)
        inventory = self.inventory(coord)
        if inventory.failure:
            raise ValueError(inventory.failure)
        with zipfile.ZipFile(identity.path) as archive:
            for location in inventory.classes:
                content = archive.read(location.physical_entry)
                with self._lock:
                    self._metrics["class_bytes_reads"] += 1
                    self._metrics["class_bytes_read"] += len(content)
                yield location, content

    def iter_physical_class_bytes(self, coord: str):
        """Yield all physical class entries in stable name order from one ZIP open."""
        identity = self._identity(coord)
        inventory = self.inventory(coord)
        if inventory.failure:
            raise ValueError(inventory.failure)
        with zipfile.ZipFile(identity.path) as archive:
            for entry in inventory.physical_classes:
                content = archive.read(entry)
                with self._lock:
                    self._metrics["class_bytes_reads"] += 1
                    self._metrics["class_bytes_read"] += len(content)
                yield entry, content

    def resource_bytes(self, coord: str, resource_name: str) -> FactOutcome:
        """Return one immutable resource, with absence/failure kept explicit."""
        identity = self._identity(coord)
        resource_name = str(resource_name or "")
        key = (
            "resource", identity.sha256, identity.target_jdk, resource_name,
        )

        def produce():
            inventory = self.inventory(coord)
            if inventory.failure:
                raise ValueError(inventory.failure)
            if resource_name not in inventory.resources:
                raise KeyError(f"resource_not_in_inventory:{resource_name}")
            with zipfile.ZipFile(identity.path) as archive:
                content = archive.read(resource_name)
            with self._lock:
                self._metrics["resource_bytes_reads"] += 1
                self._metrics["resource_bytes_read"] += len(content)
            return content

        return self._single_flight(key, produce, parser="zipfile")

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

    def javap_fact(self, coord, location, profile, producer) -> FactOutcome:
        identity = self._identity(coord)
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
            return producer(identity, location, profile)

        outcome = self._single_flight(key, produce, parser="javap")
        if outcome.status != "complete":
            with self._lock:
                self._metrics["javap_failures"] += 1
        return outcome

    def metrics(self) -> dict[str, int | float]:
        with self._lock:
            return dict(self._metrics)

    @staticmethod
    def _build_inventory(identity: ArtifactIdentity) -> ArtifactInventory:
        path = Path(identity.path)
        if not path.is_file():
            raise FileNotFoundError(f"artifact_missing:{path}")
        before = _sha256_file(path)
        if not re.fullmatch(r"[0-9a-f]{64}", identity.sha256):
            raise ValueError("artifact_sha256_invalid")
        if before != identity.sha256:
            raise ValueError(f"artifact_sha256_mismatch:expected={identity.sha256}:actual={before}")
        with zipfile.ZipFile(path) as archive:
            names = tuple(archive.namelist())
            try:
                manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            except KeyError:
                manifest = ""
            multi_release = bool(re.search(r"(?im)^Multi-Release\s*:\s*true\s*$", manifest))
            classes = _effective_class_locations(
                names, identity.target_jdk, multi_release_enabled=multi_release,
            )
            resources = tuple(sorted(name for name in names if not name.endswith(".class")))
            physical_classes = tuple(sorted(name for name in names if name.endswith(".class")))
        after = _sha256_file(path)
        if after != before:
            raise ValueError("artifact_changed_during_inventory")
        return ArtifactInventory(identity, classes, resources, physical_classes)


__all__ = [
    "ArtifactIdentity",
    "ArtifactInventory",
    "ClassLocation",
    "FactOutcome",
    "Step5ArtifactFactStore",
]
