#!/usr/bin/env python3
"""Content-bound target JDK platform image and lazy ASM platform facts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable
import zipfile

from binary_asm_helper import BinaryClassInput, BinaryFactRun, extract_class_facts
from binary_first_contract import BinaryFirstContractError, canonical_identity
from jdk_preflight import jdk_tool_path


class PlatformImageError(BinaryFirstContractError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _parse_release(path: Path) -> dict[str, str]:
    result = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        result[key.strip()] = value.strip().strip('"')
    return result


def _java_major(version: str) -> int:
    match = re.match(r"(?:1\.)?(\d+)", str(version or ""))
    if not match:
        raise PlatformImageError("PLATFORM_JAVA_VERSION_INVALID", str(version))
    return int(match.group(1))


@dataclass(frozen=True)
class PlatformClassFact:
    class_name: str
    module_name: str
    class_variant_identity: str
    class_bytes_sha256: str
    fact: dict[str, Any]


@dataclass(frozen=True)
class _PlatformClassLocation:
    module_name: str
    container: Path
    entry_name: str | None


_JDK8_BOOT_ARCHIVE_NAMES = (
    "resources.jar",
    "rt.jar",
    "sunrsasign.jar",
    "jsse.jar",
    "jce.jar",
    "charsets.jar",
    "jfr.jar",
)
_JDK8_BOOT_MODULE = "jdk8-bootstrap"
_JDK8_EXTENSION_MODULE_PREFIX = "jdk8-extension."


class JdkPlatformImage:
    def __init__(self, jdk_home: str | Path, *, asm_jar: str | Path | None = None):
        self.jdk_home = Path(jdk_home).expanduser().resolve()
        self.asm_jar = asm_jar
        self.release_file = self.jdk_home / "release"
        self.modules_file = self.jdk_home / "lib" / "modules"
        self.java_executable = jdk_tool_path(self.jdk_home, "java")
        self.jmods_dir = self.jdk_home / "jmods"
        required = (self.release_file, self.java_executable)
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise PlatformImageError(
                "PLATFORM_IMAGE_FILE_MISSING", f"missing target JDK files: {missing}"
            )
        self.release = _parse_release(self.release_file)
        self.java_major = _java_major(self.release.get("JAVA_VERSION", ""))
        if self.java_major < 8:
            raise PlatformImageError(
                "PLATFORM_JAVA_VERSION_UNSUPPORTED",
                f"target JDK {self.java_major} is outside the supported JDK 8+ range",
            )

        self.legacy_boot_archives: tuple[Path, ...] = ()
        self.legacy_extension_archives: tuple[Path, ...] = ()
        self.legacy_classes_dir: Path | None = None
        self.legacy_extension_dir: Path | None = None
        if self.java_major == 8:
            self.platform_image_format = "jdk8-classpath"
            legacy_lib = self.jdk_home / "jre" / "lib"
            runtime_archive = legacy_lib / "rt.jar"
            if not runtime_archive.is_file():
                raise PlatformImageError(
                    "PLATFORM_IMAGE_FILE_MISSING",
                    f"missing target JDK 8 runtime archive: {runtime_archive}",
                )
            self.legacy_boot_archives = tuple(
                path
                for name in _JDK8_BOOT_ARCHIVE_NAMES
                if (path := legacy_lib / name).is_file()
            )
            self.legacy_extension_dir = legacy_lib / "ext"
            if self.legacy_extension_dir.is_dir():
                self.legacy_extension_archives = tuple(
                    sorted(
                        path
                        for path in self.legacy_extension_dir.iterdir()
                        if path.is_file() and path.suffix.lower() == ".jar"
                    )
                )
            classes_dir = self.jdk_home / "jre" / "classes"
            if classes_dir.is_dir():
                self.legacy_classes_dir = classes_dir
            content_entries = [
                {
                    "path": path.relative_to(self.jdk_home).as_posix(),
                    "sha256": _sha256_file(path),
                }
                for path in (*self.legacy_boot_archives, *self.legacy_extension_archives)
            ]
            if self.legacy_classes_dir is not None:
                content_entries.extend(
                    {
                        "path": path.relative_to(self.jdk_home).as_posix(),
                        "sha256": _sha256_file(path),
                    }
                    for path in sorted(self.legacy_classes_dir.rglob("*.class"))
                )
            self.module_image_sha256 = _identity(
                "jdk8_platform_image_content", content_entries
            )
        else:
            self.platform_image_format = "jimage-jmods"
            if not self.modules_file.is_file():
                raise PlatformImageError(
                    "PLATFORM_IMAGE_FILE_MISSING",
                    f"missing target JDK module image: {self.modules_file}",
                )
            if not self.jmods_dir.is_dir():
                raise PlatformImageError(
                    "PLATFORM_JMODS_MISSING",
                    "a full target JDK with jmods is required for closed platform facts",
                )
            self.module_image_sha256 = _sha256_file(self.modules_file)
        self.identity = _identity(
            "runtime_platform_image_identity",
            {
                "release_sha256": _sha256_file(self.release_file),
                "platform_image_format": self.platform_image_format,
                "module_image_sha256": self.module_image_sha256,
                "java_launcher_sha256": _sha256_file(self.java_executable),
                "java_version": self.release.get("JAVA_VERSION", "unknown"),
                "implementor": self.release.get("IMPLEMENTOR", "unknown"),
                "os_arch": self.release.get("OS_ARCH", "unknown"),
                "modules": self.release.get("MODULES", "unknown"),
            },
        )
        self._class_index: dict[str, _PlatformClassLocation] | None = None
        self._module_exports: dict[str, frozenset[str]] | None = None
        self._facts: dict[str, PlatformClassFact] = {}
        self._failures: dict[str, dict[str, Any]] = {}
        self.parser_identity = ""

    def _build_index(self) -> None:
        if self._class_index is not None:
            return
        index: dict[str, _PlatformClassLocation] = {}
        duplicates = set()
        if self.platform_image_format == "jimage-jmods":
            archives = tuple(
                (jmod.stem, jmod, "classes/")
                for jmod in sorted(self.jmods_dir.glob("*.jmod"))
            )
        else:
            archives = tuple(
                (_JDK8_BOOT_MODULE, archive, "")
                for archive in self.legacy_boot_archives
            ) + tuple(
                (f"{_JDK8_EXTENSION_MODULE_PREFIX}{archive.stem}", archive, "")
                for archive in self.legacy_extension_archives
            )
        for module_name, archive_path, class_prefix in archives:
            try:
                with zipfile.ZipFile(archive_path) as archive:
                    for info in archive.infolist():
                        if (
                            not info.filename.startswith(class_prefix)
                            or not info.filename.endswith(".class")
                        ):
                            continue
                        class_name = info.filename[len(class_prefix):-len(".class")]
                        if class_name == "module-info" or class_name.startswith("META-INF/"):
                            continue
                        if class_name in index:
                            duplicates.add(class_name)
                        else:
                            index[class_name] = _PlatformClassLocation(
                                module_name, archive_path, info.filename
                            )
            except zipfile.BadZipFile as error:
                raise PlatformImageError(
                    "PLATFORM_JMOD_INVALID"
                    if self.platform_image_format == "jimage-jmods"
                    else "PLATFORM_ARCHIVE_INVALID",
                    f"{archive_path}: {error}",
                ) from error
        if self.legacy_classes_dir is not None:
            for class_file in sorted(self.legacy_classes_dir.rglob("*.class")):
                class_name = class_file.relative_to(self.legacy_classes_dir).as_posix()[:-len(".class")]
                if class_name in index:
                    duplicates.add(class_name)
                else:
                    index[class_name] = _PlatformClassLocation(
                        _JDK8_BOOT_MODULE, class_file, None
                    )
        if duplicates:
            raise PlatformImageError(
                "PLATFORM_CLASS_DUPLICATE", f"duplicate platform classes: {sorted(duplicates)[:20]}"
            )
        self._class_index = index

    def class_names(self) -> frozenset[str]:
        self._build_index()
        return frozenset(self._class_index or {})

    def _read_class(self, class_name: str) -> tuple[str, bytes] | None:
        self._build_index()
        location = (self._class_index or {}).get(class_name)
        if location is None:
            return None
        try:
            if location.entry_name is None:
                return location.module_name, location.container.read_bytes()
            with zipfile.ZipFile(location.container) as archive:
                return location.module_name, archive.read(location.entry_name)
        except (zipfile.BadZipFile, KeyError, OSError) as error:
            raise PlatformImageError(
                "PLATFORM_CLASS_READ_FAILED", f"{class_name}: {error}"
            ) from error

    def ensure_classes(self, class_names: Iterable[str]) -> dict[str, PlatformClassFact]:
        pending = {
            str(name or "").replace(".", "/") for name in class_names if str(name or "").strip()
        }
        while True:
            batch_names = sorted(
                name for name in pending
                if name not in self._facts and name not in self._failures
            )
            if not batch_names:
                break
            inputs = []
            modules = {}
            for name in batch_names:
                loaded = self._read_class(name)
                if loaded is None:
                    self._failures[name] = {
                        "failure_kind": "platform_class_missing",
                        "class_name": name,
                    }
                    continue
                module_name, content = loaded
                modules[name] = module_name
                inputs.append(BinaryClassInput(
                    f"platform-image:{self.identity}:{module_name}",
                    f"classes/{name}.class",
                    content,
                ))
            if not inputs:
                break
            run: BinaryFactRun = extract_class_facts(
                inputs,
                asm_jar=self.asm_jar,
                jdk_home=self.jdk_home,
            )
            self.parser_identity = run.parser_identity
            for record in run.records:
                class_name = str(record.get("class_name") or "")
                if record.get("frame_type") != "class_fact":
                    expected_name = str(record.get("class_entry") or "").removeprefix("classes/").removesuffix(".class")
                    self._failures[expected_name] = record
                    continue
                module_name = modules.get(class_name)
                if not module_name:
                    self._failures[class_name] = {
                        "failure_kind": "platform_module_binding_missing",
                    }
                    continue
                variant_identity = _identity(
                    "platform_class_variant_identity",
                    {
                        "runtime_platform_image_identity": self.identity,
                        "module_name": module_name,
                        "class_name": class_name,
                        "class_bytes_sha256": record["class_bytes_sha256"],
                    },
                )
                self._facts[class_name] = PlatformClassFact(
                    class_name,
                    module_name,
                    variant_identity,
                    record["class_bytes_sha256"],
                    record,
                )
                if record.get("super_name"):
                    pending.add(record["super_name"])
                pending.update(record.get("interfaces") or ())
        return {name: self._facts[name] for name in pending if name in self._facts}

    def get_class(self, class_name: str) -> PlatformClassFact | None:
        name = str(class_name or "").replace(".", "/")
        self.ensure_classes((name,))
        return self._facts.get(name)

    def failure(self, class_name: str) -> dict[str, Any] | None:
        name = str(class_name or "").replace(".", "/")
        self.ensure_classes((name,))
        return self._failures.get(name)

    def module_exports(self) -> dict[str, frozenset[str]]:
        if self._module_exports is not None:
            return self._module_exports
        self._build_index()
        if self.platform_image_format == "jdk8-classpath":
            # JDK 8 predates JPMS. Every public platform type is visible across
            # packages, so expose all indexed packages for each internal
            # container label used by provider evidence.
            packages: dict[str, set[str]] = {}
            for class_name, location in (self._class_index or {}).items():
                package = class_name.rpartition("/")[0]
                packages.setdefault(location.module_name, set()).add(package)
            self._module_exports = {
                module_name: frozenset(names)
                for module_name, names in packages.items()
            }
            return self._module_exports
        # JMODs all use the same logical name, so the class index intentionally
        # cannot represent module-info. Read these descriptors per module.
        exports = {}
        inputs = []
        input_modules = {}
        for jmod in sorted(self.jmods_dir.glob("*.jmod")):
            try:
                with zipfile.ZipFile(jmod) as archive:
                    content = archive.read("classes/module-info.class")
            except (zipfile.BadZipFile, KeyError, OSError):
                continue
            label = f"{jmod.stem}/module-info.class"
            inputs.append(BinaryClassInput(
                f"platform-image:{self.identity}:{jmod.stem}", label, content
            ))
            input_modules[label] = jmod.stem
        if inputs:
            run = extract_class_facts(
                inputs,
                asm_jar=self.asm_jar,
                jdk_home=self.jdk_home,
            )
            self.parser_identity = run.parser_identity
            for record in run.records:
                module = record.get("module") or {}
                module_name = str(module.get("name") or input_modules.get(record.get("class_entry"), ""))
                exported = set()
                for directive in module.get("directives") or ():
                    if directive and directive[0] == "exports" and len(directive) >= 4 and not directive[3]:
                        exported.add(str(directive[1]))
                if module_name:
                    exports[module_name] = frozenset(exported)
        self._module_exports = exports
        return exports

    def manifest(self) -> dict[str, Any]:
        self._build_index()
        return {
            "schema": "java-upgrade-analyzer.platform-image.v1",
            "runtime_platform_image_identity": self.identity,
            "java_major": self.java_major,
            "java_version": self.release.get("JAVA_VERSION"),
            "platform_image_format": self.platform_image_format,
            "module_image_sha256": self.module_image_sha256,
            "indexed_class_count": len(self._class_index or {}),
            "loaded_class_count": len(self._facts),
            "failed_class_count": len(self._failures),
            "parser_identity": self.parser_identity,
        }


__all__ = ["JdkPlatformImage", "PlatformClassFact", "PlatformImageError"]
