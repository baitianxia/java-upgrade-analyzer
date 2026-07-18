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
    failure: str = ""


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
                failure=f"{type(exc).__name__}: {exc}",
            )
        with self._lock:
            self._inventories[coord] = inventory
            self._inventory_inflight.pop(coord, None)
            event.set()
        return inventory

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
        after = _sha256_file(path)
        if after != before:
            raise ValueError("artifact_changed_during_inventory")
        return ArtifactInventory(identity, classes, resources)


__all__ = [
    "ArtifactIdentity",
    "ArtifactInventory",
    "ClassLocation",
    "Step5ArtifactFactStore",
]
