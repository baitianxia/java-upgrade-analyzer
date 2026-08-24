#!/usr/bin/env python3
"""Materialize a binary-first runtime config from retained Step1 artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
from typing import Any, Mapping
import zipfile

from binary_artifact_diff import (
    BinaryArtifactDiffError,
    _manifest_is_multi_release,
    select_runtime_resource_entries,
)
from jdk_preflight import JdkPreflightError, resolve_jdk_release


class BinaryRuntimeMaterializationError(RuntimeError):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = str(reason_code)
        self.detail = str(detail)
        super().__init__(f"{self.reason_code}: {self.detail}")


_MR_JVM_PROPERTIES = {
    "jdk.util.jar.enableMultiRelease",
    "jdk.util.jar.version",
}


def _jvm_argument_tokens(raw: Any, *, source: str) -> list[str]:
    if isinstance(raw, str):
        try:
            return shlex.split(raw)
        except ValueError as error:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_JVM_ARGUMENTS_INVALID",
                f"{source}:{error}",
            ) from error
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw]
    return []


def _declared_multi_release_jvm_properties(
    side: str,
    provenance: Mapping[str, Any],
    runtime_overrides: Mapping[str, Any],
) -> dict[str, str]:
    """Collect the MR-JAR switches from supported evidence/override shapes."""

    properties: dict[str, str] = {}
    sources: tuple[Mapping[str, Any], ...] = (provenance, runtime_overrides)
    for source in sources:
        for key in ("runtime_system_properties", "jvm_system_properties"):
            raw = source.get(key)
            if isinstance(raw, Mapping):
                for name, value in raw.items():
                    if str(name) in _MR_JVM_PROPERTIES:
                        properties[str(name)] = str(value).strip()
        for key in ("runtime_jvm_arguments", "jvm_arguments"):
            raw = source.get(key)
            arguments = _jvm_argument_tokens(raw, source=key)
            for argument in arguments:
                if not argument.startswith("-D"):
                    continue
                name, separator, value = argument[2:].partition("=")
                if name in _MR_JVM_PROPERTIES:
                    properties[name] = value.strip() if separator else ""
    for key in (
        f"{side}_runtime_system_properties",
        f"{side}_jvm_system_properties",
    ):
        raw = runtime_overrides.get(key)
        if isinstance(raw, Mapping):
            for name, value in raw.items():
                if str(name) in _MR_JVM_PROPERTIES:
                    properties[str(name)] = str(value).strip()
    for key in (f"{side}_runtime_jvm_arguments", f"{side}_jvm_arguments"):
        raw = runtime_overrides.get(key)
        arguments = _jvm_argument_tokens(raw, source=key)
        for argument in arguments:
            if argument.startswith("-D"):
                name, separator, value = argument[2:].partition("=")
                if name in _MR_JVM_PROPERTIES:
                    properties[name] = value.strip() if separator else ""
    return properties


def _load_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_INVALID", f"{path}: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_INVALID", f"{path}: root_not_object"
        )
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _existing_sha(
    path_value: Any, expected: Any, *, label: str
) -> tuple[Path, str]:
    expected_digest = str(expected or "")
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_IDENTITY_INVALID",
            f"{label}: {expected_digest!r}",
        )
    path = Path(str(path_value or "")).expanduser().resolve()
    if not path.is_file():
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_MISSING", f"{label}: {path}"
        )
    actual = _sha256(path)
    if actual != expected_digest:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_DIGEST_MISMATCH",
            f"{label}: expected={expected_digest}; actual={actual}",
        )
    return path, actual


def _container_entry_digests(
    outer_path: Path, entry_names: list[str]
) -> dict[str, str]:
    requested = tuple(dict.fromkeys(str(name or "") for name in entry_names))
    if any(not name for name in requested):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CONTAINER_ENTRY_MISSING", str(outer_path)
        )
    try:
        with zipfile.ZipFile(outer_path) as archive:
            infos_by_name: dict[str, list[zipfile.ZipInfo]] = {
                name: [] for name in requested
            }
            for info in archive.infolist():
                if not info.is_dir() and info.filename in infos_by_name:
                    infos_by_name[info.filename].append(info)
            digests = {}
            for name, infos in infos_by_name.items():
                if not infos:
                    raise BinaryRuntimeMaterializationError(
                        "BINARY_RUNTIME_CONTAINER_ENTRY_MISSING",
                        f"{outer_path}!/{name}",
                    )
                if len(infos) != 1:
                    raise BinaryRuntimeMaterializationError(
                        "BINARY_RUNTIME_CONTAINER_ENTRY_DUPLICATE",
                        f"{outer_path}!/{name}: count={len(infos)}",
                    )
                digest = hashlib.sha256()
                with archive.open(infos[0], "r") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                digests[name] = digest.hexdigest()
            return digests
    except BinaryRuntimeMaterializationError:
        raise
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CONTAINER_UNREADABLE",
            f"{outer_path}: {type(error).__name__}: {error}",
        ) from error


def _zip_content_inventory(path: Path) -> dict[str, str]:
    """Hash every retained business entry and reject ambiguous ZIP names."""

    try:
        with zipfile.ZipFile(path) as archive:
            result: dict[str, str] = {}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.filename in result:
                    raise BinaryRuntimeMaterializationError(
                        "BINARY_RUNTIME_BUSINESS_ENTRY_DUPLICATE",
                        f"{path}!/{info.filename}",
                    )
                digest = hashlib.sha256()
                with archive.open(info, "r") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                result[info.filename] = digest.hexdigest()
            return result
    except BinaryRuntimeMaterializationError:
        raise
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_BUSINESS_ARTIFACT_UNREADABLE",
            f"{path}: {type(error).__name__}: {error}",
        ) from error


def _outer_business_content_inventory(outer_path: Path) -> dict[str, str]:
    """Reconstruct Step1's logical business-content view from deployed bytes."""

    try:
        with zipfile.ZipFile(outer_path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            prefixes = ("BOOT-INF/classes/", "WEB-INF/classes/")
            has_application_layout = any(
                info.filename.startswith(prefixes) for info in infos
            )
            selected: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                name = info.filename
                if has_application_layout:
                    prefix = next(
                        (value for value in prefixes if name.startswith(value)),
                        "",
                    )
                    if prefix:
                        logical_name = name[len(prefix):]
                    elif name.upper() == "META-INF/MANIFEST.MF":
                        logical_name = name
                    else:
                        continue
                else:
                    upper_name = name.upper()
                    packaging_only = (
                        upper_name.startswith("META-INF/MAVEN/")
                        or re.fullmatch(
                            r"META-INF/[^/]+\.(?:SF|RSA|DSA|EC)", upper_name
                        ) is not None
                    )
                    if packaging_only or name.startswith(
                        ("BOOT-INF/", "WEB-INF/", "lib/")
                    ):
                        continue
                    logical_name = name
                # Exact application prefixes end in '/', which ZipInfo treats
                # as directory records and which ``infos`` excludes. Plain
                # file entry names are non-empty, so a retained logical name
                # cannot be empty here.
                if logical_name in selected:
                    raise BinaryRuntimeMaterializationError(
                        "BINARY_RUNTIME_BUSINESS_ENTRY_DUPLICATE",
                        f"{outer_path}!/{logical_name}",
                    )
                selected[logical_name] = info
            result = {}
            for logical_name, info in selected.items():
                digest = hashlib.sha256()
                with archive.open(info, "r") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                result[logical_name] = digest.hexdigest()
            return result
    except BinaryRuntimeMaterializationError:
        raise
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CONTAINER_UNREADABLE",
            f"{outer_path}: {type(error).__name__}: {error}",
        ) from error


def _verify_business_content_binding(
    business_path: Path, outer_path: Path, *, side: str
) -> None:
    retained = _zip_content_inventory(business_path)
    deployed = _outer_business_content_inventory(outer_path)
    # Step1 historically omitted a non-MR outer manifest from its derived
    # business JAR.  Continue accepting that harmless representation, while
    # rejecting the same omission when it would erase MR runtime semantics.
    deployed_manifests = [
        name for name in deployed
        if name.upper() == "META-INF/MANIFEST.MF"
    ]
    retained_manifests = [
        name for name in retained
        if name.upper() == "META-INF/MANIFEST.MF"
    ]
    if len(deployed_manifests) == 1 and not retained_manifests:
        try:
            with zipfile.ZipFile(outer_path) as outer:
                outer_is_multi_release = _manifest_is_multi_release(outer)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            outer_is_multi_release = True
        if not outer_is_multi_release:
            deployed.pop(deployed_manifests[0], None)
    if retained == deployed:
        return
    retained_names = set(retained)
    deployed_names = set(deployed)
    changed = sorted(
        name for name in retained_names & deployed_names
        if retained[name] != deployed[name]
    )
    raise BinaryRuntimeMaterializationError(
        "BINARY_RUNTIME_BUSINESS_CONTENT_MISMATCH",
        f"{side}: missing={sorted(retained_names - deployed_names)[:5]}; "
        f"unexpected={sorted(deployed_names - retained_names)[:5]}; "
        f"changed={changed[:5]}",
    )


def _coord_with_version(item: Mapping[str, Any]) -> tuple[str, str]:
    coord = str(item.get("coord") or "").strip()
    version = str(item.get("version") or "").strip()
    if not coord or not version:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_COORDINATE_MISSING", str(item.get("lib_entry") or "")
        )
    parts = coord.split(":")
    if len(parts) not in {2, 3}:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_COORDINATE_INVALID", coord
        )
    lineage = coord
    return f"{coord}:{version}", lineage


def _runtime_classpath_index(item: Mapping[str, Any]) -> int:
    value = item.get("runtime_classpath_index")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CLASSPATH_INDEX_INVALID",
            f"{item.get('side')}:{item.get('lib_entry')}: {value!r}",
        )
    return value


def _nonnegative_evidence_count(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
            f"{label}: {value!r}",
        )
    return value


def _validate_evidence_structure(
    manifest: Mapping[str, Any], provenance: Mapping[str, Any]
) -> None:
    items = manifest.get("items")
    business = manifest.get("business_artifacts")
    closures = manifest.get("runtime_closure")
    provenance_sides = provenance.get("sides")
    if (
        not isinstance(items, list)
        or not all(isinstance(item, Mapping) for item in items)
        or not isinstance(business, list)
        or not all(isinstance(item, Mapping) for item in business)
        or not isinstance(closures, Mapping)
        or set(closures) != {"base", "current"}
        or not isinstance(provenance_sides, list)
        or not all(isinstance(item, Mapping) for item in provenance_sides)
    ):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID", "root collections"
        )
    valid_sides = {"base", "current"}
    if any(
        str(item.get("side") or "") not in valid_sides
        for item in (*items, *business, *provenance_sides)
    ):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID", "item side"
        )
    for item in items:
        purposes = item.get("purposes")
        if (
            not isinstance(purposes, list)
            or not all(isinstance(value, str) and value for value in purposes)
            or len(purposes) != len(set(purposes))
        ):
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{item.get('side')}:{item.get('lib_entry')}: purposes",
            )
    for side in sorted(valid_sides):
        closure = closures.get(side)
        if not isinstance(closure, Mapping):
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{side}: runtime_closure",
            )
        status = closure.get("coverage_status")
        gaps = closure.get("coverage_gaps")
        if (
            status not in {"complete", "partial"}
            or not isinstance(gaps, list)
            or not all(isinstance(value, str) and value for value in gaps)
            or (status == "complete" and gaps)
        ):
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{side}: closure status/gaps",
            )
        expected = _nonnegative_evidence_count(
            closure.get("expected_dependency_count"),
            label=f"{side}:expected_dependency_count",
        )
        retained = _nonnegative_evidence_count(
            closure.get("retained_dependency_count"),
            label=f"{side}:retained_dependency_count",
        )
        business_count = _nonnegative_evidence_count(
            closure.get("business_artifact_count"),
            label=f"{side}:business_artifact_count",
        )
        binary_runtime_count = sum(
            1 for item in items
            if item.get("side") == side
            and "binary_runtime" in item.get("purposes", ())
        )
        if (
            retained != binary_runtime_count
            or business_count != 1
            or retained > expected
        ):
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{side}: expected={expected}; retained={retained}; "
                f"runtime_items={binary_runtime_count}; business={business_count}",
            )
        if status == "complete" and retained != expected:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{side}: expected={expected}; retained={retained}; "
                f"runtime_items={binary_runtime_count}; business={business_count}",
            )
        if status == "partial" and not gaps:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                f"{side}: expected={expected}; retained={retained}; "
                f"runtime_items={binary_runtime_count}; business={business_count}",
            )


def _properties(content: bytes) -> dict[str, str]:
    """Parse the ``Properties.load(InputStream)`` language used by Spring.

    In particular, separators and whitespace may be escaped, continued lines
    discard leading whitespace, ``\\uXXXX`` is decoded, and duplicate keys are
    last-wins.  A malformed Unicode escape is not recoverable evidence and is
    surfaced to the caller as a coverage gap.
    """

    def unescape(value: str) -> str:
        output = []
        index = 0
        escaped = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}
        while index < len(value):
            character = value[index]
            if character != "\\":
                output.append(character)
                index += 1
                continue
            index += 1
            # Logical-line reconstruction consumes every odd trailing slash as
            # a continuation marker. Any slash reaching this parser therefore
            # has a following escaped character (possibly another slash).
            character = value[index]
            if character == "u":
                digits = value[index + 1:index + 5]
                if len(digits) != 4 or re.fullmatch(r"[0-9a-fA-F]{4}", digits) is None:
                    raise ValueError("malformed Java Properties Unicode escape")
                output.append(chr(int(digits, 16)))
                index += 5
                continue
            output.append(escaped.get(character, character))
            index += 1
        return "".join(output)

    text_value = content.decode("iso-8859-1").replace(
        "\r\n", "\n"
    ).replace("\r", "\n")
    logical_lines = []
    pending = ""
    continuing = False
    for physical in text_value.split("\n"):
        fragment = physical.lstrip(" \t\f") if continuing else physical
        pending += fragment
        trailing_slashes = len(pending) - len(pending.rstrip("\\"))
        if trailing_slashes % 2:
            pending = pending[:-1]
            continuing = True
            continue
        logical_lines.append(pending)
        pending = ""
        continuing = False
    if pending or continuing:
        logical_lines.append(pending)

    result = {}
    whitespace = " \t\f"
    for line in logical_lines:
        key_start = 0
        while key_start < len(line) and line[key_start] in whitespace:
            key_start += 1
        if key_start == len(line) or line[key_start] in "#!":
            continue
        separator = len(line)
        escaped_separator = False
        preceding_backslash = False
        for index in range(key_start, len(line)):
            character = line[index]
            if not preceding_backslash and (
                character in "=:" or character in whitespace
            ):
                separator = index
                escaped_separator = character in "=:"
                break
            if character == "\\":
                preceding_backslash = not preceding_backslash
            else:
                preceding_backslash = False
        value_start = separator
        if value_start < len(line):
            if line[value_start] in whitespace:
                while value_start < len(line) and line[value_start] in whitespace:
                    value_start += 1
                if value_start < len(line) and line[value_start] in "=:":
                    value_start += 1
            else:
                # The scan can stop before len(line) only on whitespace, ':'
                # or '='. The whitespace case is handled above, so this is an
                # explicit key/value separator.
                value_start += 1
            while value_start < len(line) and line[value_start] in whitespace:
                value_start += 1
        raw_key = line[key_start:separator]
        raw_value = line[value_start:]
        result[unescape(raw_key)] = unescape(raw_value)
    return result


def _manifest_attributes(content: bytes) -> dict[str, str]:
    """Parse the main section of a JAR manifest, including folded values."""
    text = content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    logical_lines: list[str] = []
    for physical in text.split("\n"):
        if not physical:
            break
        if physical.startswith(" ") and logical_lines:
            logical_lines[-1] += physical[1:]
        else:
            logical_lines.append(physical)
    attributes: dict[str, str] = {}
    for line in logical_lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip():
            attributes[key.strip().lower()] = value.strip()
    return attributes


def _archive_security_markers(path: Path) -> tuple[str, ...]:
    """Detect JAR signer and package-sealing semantics.

    A rewritten outer business container is still rejected because repacking
    cannot preserve its signature contract. Retained dependency JARs keep
    their exact bytes; their markers are handled artifact-by-artifact by the
    runtime reconciler instead of aborting materialization for the whole side.
    """

    markers = set()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            for info in infos:
                if re.fullmatch(
                    r"META-INF/[^/]+\.(?:SF|RSA|DSA|EC)",
                    info.filename.upper(),
                ):
                    markers.add(f"signature_entry:{info.filename}")
            manifests = [
                info for info in infos
                if info.filename.upper() == "META-INF/MANIFEST.MF"
            ]
            if len(manifests) > 1:
                markers.add("manifest_ambiguous")
            elif manifests:
                text = archive.read(manifests[0]).decode(
                    "utf-8", errors="replace"
                )
                unfolded = []
                for line in text.replace("\r\n", "\n").replace(
                    "\r", "\n"
                ).split("\n"):
                    if line.startswith(" ") and unfolded:
                        unfolded[-1] += line[1:]
                    else:
                        unfolded.append(line)
                for line in unfolded:
                    key, separator, value = line.partition(":")
                    if not separator:
                        continue
                    normalized_key = key.strip().lower()
                    normalized_value = value.strip().lower()
                    if normalized_key == "sealed" and normalized_value == "true":
                        markers.add("sealed_manifest_section")
                    if normalized_key.endswith("-digest"):
                        markers.add("signed_manifest_digest")
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_SECURITY_EVIDENCE_UNREADABLE",
            f"{path}: {type(error).__name__}: {error}",
        ) from error
    return tuple(sorted(markers))


def _packaged_main_class(outer_path: Path, business_path: Path) -> tuple[str, list[str]]:
    """Resolve only a manifest-declared class present in retained business bytes."""
    try:
        with zipfile.ZipFile(outer_path) as outer:
            attributes = _manifest_attributes(outer.read("META-INF/MANIFEST.MF"))
        with zipfile.ZipFile(business_path) as business:
            business_entries = {
                info.filename for info in business.infolist() if not info.is_dir()
            }
    except KeyError:
        return "", ["packaged_main_class_manifest_missing"]
    except (OSError, zipfile.BadZipFile, UnicodeError) as error:
        return "", [f"packaged_main_class_unreadable:{type(error).__name__}"]
    candidates = [
        attributes.get("start-class", ""),
        attributes.get("main-class", ""),
    ]
    for candidate in candidates:
        class_name = str(candidate or "").strip().replace("/", ".")
        if class_name and class_name.replace(".", "/") + ".class" in business_entries:
            return class_name, []
    if any(candidates):
        return "", ["packaged_main_class_not_in_business_artifact"]
    return "", ["packaged_main_class_not_declared"]


def _jdk_feature(jdk_home: Path) -> int | None:
    try:
        values = resolve_jdk_release(jdk_home)["values"]
    except (JdkPreflightError, OSError, UnicodeError):
        return None
    match = re.match(r"(?:1\.)?(\d+)", values.get("JAVA_VERSION", ""))
    return int(match.group(1)) if match else None


def _packaged_runtime_configuration(
    path: Path,
    *,
    target_jvm_major: int | None,
) -> tuple[dict[str, str], list[str]]:
    """Read only unambiguous packaged Properties inputs; YAML remains explicit gap."""
    properties: dict[str, str] = {}
    gaps = []
    try:
        with zipfile.ZipFile(path) as archive:
            selected, target_required = select_runtime_resource_entries(
                archive, target_jvm_major
            )
            if target_required:
                gaps.append("packaged_multi_release_target_jvm_unknown")
            names = set(selected)
            property_names = sorted(
                name for name in names
                if name in {"application.properties", "config/application.properties"}
            )
            yaml_names = sorted(
                name for name in names
                if name in {
                    "application.yml", "application.yaml",
                    "config/application.yml", "config/application.yaml",
                }
            )
            if len(property_names) > 1:
                gaps.append("packaged_default_properties_precedence_ambiguous")
            elif property_names:
                properties.update(_properties(
                    archive.read(selected[property_names[0]])
                ))
            if yaml_names:
                gaps.append("packaged_yaml_condition_inputs_not_materialized")
            profiles = [
                value.strip() for value in properties.get("spring.profiles.active", "").split(",")
                if value.strip()
            ]
            for profile in profiles:
                variants = sorted(
                    name for name in names
                    if name in {
                        f"application-{profile}.properties",
                        f"config/application-{profile}.properties",
                    }
                )
                if len(variants) == 1:
                    properties.update(_properties(
                        archive.read(selected[variants[0]])
                    ))
                elif len(variants) > 1:
                    gaps.append(f"packaged_profile_properties_precedence_ambiguous:{profile}")
    except BinaryArtifactDiffError as error:
        gaps.append(f"packaged_multi_release_selection_failed:{error.reason_code}")
    except ValueError as error:
        properties.clear()
        gaps.append(
            f"packaged_properties_parse_failed:{type(error).__name__}"
        )
    except (OSError, zipfile.BadZipFile, UnicodeError) as error:
        gaps.append(f"packaged_configuration_unreadable:{type(error).__name__}")
    return properties, sorted(set(gaps))


def _dependency_runtime_configuration_gaps(
    path: Path,
    *,
    target_jvm_major: int | None,
    artifact_label: str,
) -> list[str]:
    """Report classpath configuration inputs this materializer cannot merge.

    Spring configuration precedence spans the runtime classpath.  Business
    configuration is materialized above, but silently ignoring matching files
    in dependency JARs would make conditional activation look exact when it is
    not.  Preserve the fast path for ordinary dependencies and scope the gap
    to the exact artifact and logical resource names.
    """

    gaps = []
    try:
        with zipfile.ZipFile(path) as archive:
            selected, target_required = select_runtime_resource_entries(
                archive, target_jvm_major
            )
            configuration_names = sorted(
                name for name in selected
                if re.fullmatch(
                    r"(?:config/)?application(?:-[^/]+)?\."
                    r"(?:properties|ya?ml)",
                    name,
                    re.IGNORECASE,
                )
            )
            gaps.extend(
                f"dependency_packaged_configuration_not_materialized:"
                f"{artifact_label}:{name}"
                for name in configuration_names
            )
            if target_required:
                gaps.append(
                    f"dependency_multi_release_target_jvm_unknown:"
                    f"{artifact_label}"
                )
    except BinaryArtifactDiffError as error:
        gaps.append(
            f"dependency_multi_release_selection_failed:{artifact_label}:"
            f"{error.reason_code}"
        )
    except (OSError, RuntimeError, zipfile.BadZipFile):
        gaps.append(
            f"dependency_packaged_configuration_unreadable:{artifact_label}"
        )
    return sorted(set(gaps))


def _side_config(
    side: str,
    manifest: Mapping[str, Any],
    provenance: Mapping[str, Any],
    runtime_overrides: Mapping[str, Any],
) -> dict[str, Any]:
    # ``materialize_binary_pipeline_config`` validates collection types, sides,
    # purpose lists, and the two closure records before entering this function.
    # Use those established invariants directly so malformed evidence is
    # rejected at one boundary instead of silently converted to empty rows.
    business_rows = [
        dict(item)
        for item in manifest["business_artifacts"]
        if str(item["side"]) == side
    ]
    if len(business_rows) != 1:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_BUSINESS_ARTIFACT_CARDINALITY",
            f"{side}: expected=1; actual={len(business_rows)}",
        )
    business = business_rows[0]
    business_path, business_digest = _existing_sha(
        business.get("retained_path"), business.get("sha256"),
        label=f"{side}:business",
    )
    outer_path, outer_digest = _existing_sha(
        business.get("outer_artifact_path"),
        business.get("outer_artifact_sha256"),
        label=f"{side}:outer",
    )
    _verify_business_content_binding(business_path, outer_path, side=side)
    outer_security_markers = _archive_security_markers(outer_path)
    if "manifest_ambiguous" in outer_security_markers:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_MANIFEST_AMBIGUOUS",
            f"{side}:outer:case-insensitive manifest candidates",
        )
    if outer_security_markers:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_SIGNED_OR_SEALED_UNSUPPORTED",
            f"{side}:outer:{','.join(outer_security_markers)}",
        )
    provenance_rows = [
        dict(item)
        for item in provenance["sides"]
        if str(item["side"]) == side
    ]
    if len(provenance_rows) != 1:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_PROVENANCE_CARDINALITY", side
        )
    side_provenance = provenance_rows[0]
    provenance_digest = str(
        side_provenance.get("artifact_sha256") or ""
    ).lower()
    if provenance_digest != outer_digest:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_PROVENANCE_ARTIFACT_IDENTITY_MISMATCH",
            f"{side}: expected={outer_digest}; provenance={provenance_digest}",
        )
    provenance_path = Path(
        str(side_provenance.get("artifact_path") or "")
    ).expanduser().resolve()
    if provenance_path != outer_path:
        _existing_sha(
            provenance_path,
            provenance_digest,
            label=f"{side}:provenance_outer",
        )
    jdk_home = str(
        runtime_overrides.get(f"{side}_jdk_home")
        or side_provenance.get("jdk_home")
        or ""
    ).strip()
    if not jdk_home:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_JDK_HOME_MISSING", side
        )
    target_jvm_major = _jdk_feature(Path(jdk_home).expanduser().resolve())
    mr_jvm_properties = _declared_multi_release_jvm_properties(
        side, side_provenance, runtime_overrides
    )
    unsupported_mr_properties = {
        name: value
        for name, value in mr_jvm_properties.items()
        if name == "jdk.util.jar.version"
        or (
            name == "jdk.util.jar.enableMultiRelease"
            and value != "true"
        )
    }
    if unsupported_mr_properties:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
            f"{side}:" + ",".join(
                f"{name}={value}"
                for name, value in sorted(unsupported_mr_properties.items())
            ),
        )

    module = str(side_provenance.get("target_module") or "").strip() or "application"
    artifacts = [{
        "path": str(business_path),
        "content_sha256": business_digest,
        "outer_artifact_path": str(outer_path),
        "outer_artifact_sha256": outer_digest,
        "container_entry": "BOOT-INF/classes/"
        if business.get("container_and_launcher_kind")
        == "spring-boot-executable-jar"
        else (
            "WEB-INF/classes/"
            if business.get("container_and_launcher_kind") == "servlet-war"
            else "<artifact>"
        ),
        "logical_location": "application/business-classes.jar",
        "loader_realm": "application-loader",
        "path_kind": "business_classes",
        "slot": 0,
        "coord": f"application:{module}:{side}",
        "lineage": "application:business",
        "runtime_code_source_origin_identity": (
            f"sha256:{outer_digest}#business-classes"
        ),
    }]
    dependency_rows = [
        dict(item)
        for item in manifest["items"]
        if str(item["side"]) == side
        and "binary_runtime" in set(item["purposes"])
    ]
    classpath_indexes = [_runtime_classpath_index(item) for item in dependency_rows]
    if len(classpath_indexes) != len(set(classpath_indexes)):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CLASSPATH_INDEX_DUPLICATE",
            f"{side}: {classpath_indexes}",
        )
    lib_entries = [str(item.get("lib_entry") or "") for item in dependency_rows]
    if len(lib_entries) != len(set(lib_entries)):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_CONTAINER_ENTRY_DECLARATION_DUPLICATE",
            f"{side}: {lib_entries}",
        )
    dependency_rows.sort(
        key=lambda item: (
            _runtime_classpath_index(item),
            str(item.get("lib_entry") or ""),
        )
    )
    container_digests = _container_entry_digests(
        outer_path,
        [str(item.get("lib_entry") or "") for item in dependency_rows],
    ) if dependency_rows else {}
    dependency_configuration_gaps = []
    for slot, item in enumerate(dependency_rows, start=1):
        declared_outer_digest = str(
            item.get("outer_artifact_sha256") or ""
        ).lower()
        if declared_outer_digest != outer_digest:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_CONTAINER_IDENTITY_MISMATCH",
                f"{side}:{item.get('lib_entry')}: "
                f"expected_outer={outer_digest}; declared_outer={declared_outer_digest}",
            )
        path, nested_digest = _existing_sha(
            item.get("retained_path"), item.get("nested_jar_sha256"),
            label=f"{side}:{item.get('lib_entry')}",
        )
        dependency_security_markers = _archive_security_markers(path)
        if "manifest_ambiguous" in dependency_security_markers:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_MANIFEST_AMBIGUOUS",
                f"{side}:{item.get('lib_entry')}:"
                "case-insensitive manifest candidates",
            )
        # Retained dependency JARs are not rewritten here, so signature and
        # sealing markers do not make the runtime path unmaterializable.  The
        # reconciler already scopes unsupported signer/package-sealing
        # semantics to definitions from that one artifact as ``security_failed``.
        # Rejecting the whole Step4 at this boundary only discarded analyzable
        # facts from unrelated dependencies (for example xom and bcprov).
        dependency_configuration_gaps.extend(
            _dependency_runtime_configuration_gaps(
                path,
                target_jvm_major=target_jvm_major,
                artifact_label=str(item.get("coord") or item["lib_entry"]),
            )
        )
        # A successful container digest lookup proves a non-empty declared
        # entry name, so the fallback used before that check is unreachable.
        lib_entry = str(item["lib_entry"])
        container_digest = container_digests[lib_entry]
        if container_digest != nested_digest:
            raise BinaryRuntimeMaterializationError(
                "BINARY_RUNTIME_CONTAINER_ENTRY_DIGEST_MISMATCH",
                f"{side}:{lib_entry}: retained={nested_digest}; "
                f"container={container_digest}",
            )
        coord, lineage = _coord_with_version(item)
        artifacts.append({
            "path": str(path),
            "content_sha256": nested_digest,
            "outer_artifact_path": str(outer_path),
            "outer_artifact_sha256": outer_digest,
            "container_entry": lib_entry,
            "logical_location": f"dependencies/{slot:05d}-{path.name}",
            "loader_realm": "application-loader",
            "path_kind": "classpath",
            "slot": slot,
            "coord": coord,
            "lineage": lineage,
            "runtime_code_source_origin_identity": (
                f"sha256:{outer_digest}#{lib_entry}"
            ),
        })
    if _sha256(outer_path) != outer_digest:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_CHANGED_DURING_MATERIALIZATION",
            f"{side}:outer:{outer_path}",
        )

    side_coverage = dict(manifest["runtime_closure"][side])
    closure_status = str(side_coverage["coverage_status"])
    packaged_properties, business_configuration_gaps = (
        _packaged_runtime_configuration(
            business_path,
            target_jvm_major=target_jvm_major,
        )
    )
    configuration_gaps = sorted(set(
        dependency_configuration_gaps + business_configuration_gaps
    ))
    packaged_main_class, main_class_gaps = _packaged_main_class(
        outer_path, business_path
    )
    supplied_properties = dict(
        runtime_overrides.get(f"{side}_resolved_configuration_properties")
        or runtime_overrides.get("resolved_configuration_properties")
        or {}
    )
    resolved_properties = {
        **packaged_properties,
        **{str(key): str(value) for key, value in supplied_properties.items()},
    }
    active_profiles = list(
        runtime_overrides.get("active_profile_identities")
        or tuple(
            item.strip()
            for item in resolved_properties.get("spring.profiles.active", "").split(",")
            if item.strip()
        )
        or ("default",)
    )
    external_configs = list(
        runtime_overrides.get("external_config_snapshot_identities") or ()
    )
    agent_profiles = list(
        runtime_overrides.get("agent_transformer_plugin_profile_identities") or ()
    )
    runtime_profile = {
        "container_and_launcher_kind": str(
            business.get("container_and_launcher_kind") or "java-classpath"
        ),
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "multi_release_jar_runtime_policy": {
                "policy_identity": "openjdk-jarfile-default-properties-v1",
                "target_runtime_feature": target_jvm_major,
                "jdk.util.jar.enableMultiRelease": mr_jvm_properties.get(
                    "jdk.util.jar.enableMultiRelease", "true"
                ),
                "jdk.util.jar.version": "target-runtime-feature",
                "non_default_behavior": "fail_closed",
            },
            "realms": [{
                "identity": "platform-loader",
                "kind": "platform",
                "delegation": "parent_first",
                "module_mode": "named-platform",
            }, {
                "identity": "application-loader",
                "kind": "application",
                "parent": "platform-loader",
                "delegation": "parent_first",
                "module_mode": "unnamed",
            }],
        },
        "runtime_security_and_package_sealing_policy_identity": (
            "standard-unsealed-unsigned-v1"
        ),
        "active_profile_identities": active_profiles,
        "resolved_configuration_properties": resolved_properties,
        "runtime_configuration_coverage_status": (
            "complete"
            if not configuration_gaps and (not external_configs or supplied_properties)
            else "partial"
        ),
        "external_config_snapshot_identities": external_configs,
        "agent_transformer_plugin_profile_identities": agent_profiles,
        "business_entrypoint_profile": {
            "discovery_mode": "binary_auto",
            "coverage_status": "complete" if not main_class_gaps else "partial",
            "coverage_gaps": sorted(set(main_class_gaps)),
            "methods": [],
            **({"main_class": packaged_main_class} if packaged_main_class else {}),
        },
        "runtime_class_closure_coverage_status": closure_status,
        "resource_selection_coverage_status": (
            "complete"
            if not configuration_gaps and (not external_configs or supplied_properties)
            else "partial"
        ),
        "runtime_configuration_coverage_gaps": sorted(set(
            configuration_gaps
            + (["external_configuration_snapshot_content_missing"]
               if external_configs and not supplied_properties else [])
        )),
        "entrypoint_discovery_coverage_gaps": sorted(set(main_class_gaps)),
    }
    input_mode = str(
        side_provenance.get("input_mode")
        or side_provenance.get("source_mode")
        or "provided_artifact"
    )
    if input_mode not in {"checkout_build", "provided_artifact"}:
        input_mode = "provided_artifact"
    build_executed = (
        bool(side_provenance.get("build_executed_by_system"))
        if input_mode == "checkout_build"
        else False
    )
    build_status = (
        str(side_provenance.get("build_execution_status") or "succeeded")
        if input_mode == "checkout_build"
        else "not_executed"
    )
    return {
        "jdk_home": str(Path(jdk_home).expanduser().resolve()),
        "jdk_preflight_identity": str(
            (
                ((runtime_overrides.get("step0_preflight") or {}).get("sides") or {})
                .get(side, {})
                .get("jdk", {})
                .get("jdk_preflight_identity", "")
            )
        ),
        "artifacts": artifacts,
        "runtime_profile": runtime_profile,
        "build_identity": {
            "artifact_build_provenance": {
                **side_provenance,
                "input_mode": input_mode,
                "build_executed_by_system": build_executed,
                "build_execution_status": build_status,
                "binary_runtime_materialization": {
                    "source_manifest_schema": manifest.get("schema"),
                    "business_artifact_sha256": business.get("sha256"),
                    "dependency_artifact_sha256": [
                        item.get("nested_jar_sha256") for item in dependency_rows
                    ],
                    "runtime_closure_coverage": side_coverage,
                },
            },
        },
    }


def materialize_binary_pipeline_config(
    report_dir: str | Path,
    *,
    runtime_overrides: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    dependencies = report / "evidence" / "dependencies"
    manifest = _load_object(dependencies / "dependency_jars.json")
    provenance = _load_object(dependencies / "build_provenance.json")
    # v3 is the first Step1 manifest that proves a two-sided, ordered runtime
    # closure.  Treating an older changed-artifact-only manifest as complete
    # would silently drop unchanged dependencies from binary reachability.
    if manifest.get("schema") != "java-upgrade-analyzer.step1-dependency-jars.v3":
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_MANIFEST_SCHEMA_INVALID", str(manifest.get("schema"))
        )
    if provenance.get("schema") != "java-upgrade-analyzer.build-provenance.v2":
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_PROVENANCE_SCHEMA_INVALID",
            str(provenance.get("schema")),
        )
    _validate_evidence_structure(manifest, provenance)
    overrides = dict(runtime_overrides or {})
    base = _side_config("base", manifest, provenance, overrides)
    current = _side_config("current", manifest, provenance, overrides)
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "base": base,
        "current": current,
        "runtime_comparison": {
            "comparison_intent": "release_snapshot",
            "profile_correspondence_policy_version": "auto-materialized-v1",
            "controlled_profile_fields": [
                "loader_topology",
                "container_and_launcher_kind",
            ],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
            "changed_or_unknown_profile_fields": [],
        },
        "runtime_materialization": {
            "authority": "step1-retained-final-artifact-closure",
            "manifest": str((dependencies / "dependency_jars.json").resolve()),
            "provenance": str((dependencies / "build_provenance.json").resolve()),
        },
    }


__all__ = [
    "BinaryRuntimeMaterializationError",
    "materialize_binary_pipeline_config",
]
