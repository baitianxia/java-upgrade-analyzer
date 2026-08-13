#!/usr/bin/env python3
"""Executable, content-bound validation for one explicitly selected JDK Home."""

from __future__ import annotations

import hashlib
from functools import lru_cache
import json
import os
from pathlib import Path
import re
from typing import Any

from binary_tool_execution import execute_binary_tool
from path_runtime import short_temporary_directory


PROBE_CLASS = "JuaJdkPreflightProbe"
PROBE_OUTPUT = "JUA_JDK_PREFLIGHT_OK"
PROBE_SOURCE = (
    "public final class JuaJdkPreflightProbe {"
    " public static void main(String[] args) {"
    '  System.out.print("JUA_JDK_PREFLIGHT_OK");'
    " }"
    "}\n"
)


class JdkPreflightError(RuntimeError):
    def __init__(self, reason_code: str, detail: str, *, diagnostic=None):
        super().__init__(detail)
        self.reason_code = str(reason_code)
        self.diagnostic = dict(diagnostic or {})


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _release_values(path: Path) -> dict[str, str]:
    values = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise JdkPreflightError(
            "JDK_RELEASE_UNREADABLE", f"cannot read {path}: {error}"
        ) from error
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip().strip('"')
    return values


def _java_major(value: str) -> int:
    text = str(value or "").strip()
    legacy = re.match(r"1\.(\d+)", text)
    modern = re.match(r"(\d+)", text)
    match = legacy or modern
    if not match:
        raise JdkPreflightError(
            "JDK_RELEASE_VERSION_INVALID", f"cannot parse JAVA_VERSION={value!r}"
        )
    return int(match.group(1))


def jdk_tool_path(jdk_home: str | Path, name: str) -> Path:
    """Resolve a JDK tool from the selected home, never from process PATH."""
    home = Path(jdk_home).expanduser().resolve()
    names = (f"{name}.exe", name) if os.name == "nt" else (name, f"{name}.exe")
    for candidate_name in names:
        candidate = home / "bin" / candidate_name
        if candidate.is_file():
            return candidate
    # Return the native expected spelling so diagnostics identify the exact path.
    return home / "bin" / names[0]


def _tool_fingerprint(path: Path, version_output: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "sha256": _sha256_file(path),
        "size_bytes": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "version_output": str(version_output or "").strip()[-4000:],
    }


def _run_tool(command, *, stage: str, reason_prefix: str, require_stdout=False):
    result = execute_binary_tool(
        command,
        stage=stage,
        reason_prefix=reason_prefix,
        timeout_seconds=30,
        require_stdout=require_stdout,
    )
    if not result.succeeded:
        diagnostic = result.failure.to_mapping()
        raise JdkPreflightError(
            result.failure.reason_code,
            json.dumps(diagnostic, ensure_ascii=False, sort_keys=True),
            diagnostic=diagnostic,
        )
    return result


def _preflight_jdk_home_uncached(jdk_home: str | Path) -> dict[str, Any]:
    """Exercise every JDK tool later used by Step4 and bind the observation."""
    home = Path(jdk_home).expanduser().resolve()
    release_file = home / "release"
    if not home.is_dir():
        raise JdkPreflightError("JDK_HOME_MISSING", str(home))
    if not release_file.is_file():
        raise JdkPreflightError("JDK_RELEASE_MISSING", str(release_file))

    release = _release_values(release_file)
    major = _java_major(release.get("JAVA_VERSION", ""))
    platform_files: list[Path] = []
    if major == 8:
        runtime_archive = home / "jre" / "lib" / "rt.jar"
        if not runtime_archive.is_file():
            raise JdkPreflightError("JDK8_RUNTIME_IMAGE_MISSING", str(runtime_archive))
        legacy_lib = home / "jre" / "lib"
        platform_files.extend(
            path
            for path in (
                legacy_lib / name
                for name in (
                    "resources.jar", "rt.jar", "sunrsasign.jar", "jsse.jar",
                    "jce.jar", "charsets.jar", "jfr.jar",
                )
            )
            if path.is_file()
        )
        extension_dir = legacy_lib / "ext"
        if extension_dir.is_dir():
            platform_files.extend(sorted(extension_dir.glob("*.jar")))
        classes_dir = home / "jre" / "classes"
        if classes_dir.is_dir():
            platform_files.extend(sorted(classes_dir.rglob("*.class")))
    elif major > 8:
        modules = home / "lib" / "modules"
        jmods = home / "jmods"
        jmod_files = sorted(jmods.glob("*.jmod")) if jmods.is_dir() else []
        missing = [str(path) for path in (modules, jmods) if not path.exists()]
        if missing or not modules.is_file() or not jmods.is_dir() or not jmod_files:
            raise JdkPreflightError(
                "JDK_MODULE_IMAGE_INCOMPLETE",
                f"missing or invalid target platform paths: {missing or [modules, jmods]}",
            )
        platform_files.extend((modules, *jmod_files))
    else:
        raise JdkPreflightError("JDK_VERSION_UNSUPPORTED", f"JDK {major}")

    tools = {name: jdk_tool_path(home, name) for name in ("java", "javac", "javap")}
    missing_tools = [str(path) for path in tools.values() if not path.is_file()]
    if missing_tools:
        raise JdkPreflightError(
            "JDK_REQUIRED_TOOL_MISSING",
            f"selected JDK Home is missing required tools: {missing_tools}",
            diagnostic={"jdk_home": str(home), "missing_tools": missing_tools},
        )

    version_results = {
        "java": _run_tool(
            [str(tools["java"]), "-version"],
            stage="step0.jdk.java_version",
            reason_prefix="JDK_JAVA_VERSION",
        ),
        "javac": _run_tool(
            [str(tools["javac"]), "-version"],
            stage="step0.jdk.javac_version",
            reason_prefix="JDK_JAVAC_VERSION",
        ),
        "javap": _run_tool(
            [str(tools["javap"]), "-version"],
            stage="step0.jdk.javap_version",
            reason_prefix="JDK_JAVAP_VERSION",
        ),
    }

    with short_temporary_directory(prefix="jdk-preflight") as temp_text:
        temp = Path(temp_text)
        source = temp / f"{PROBE_CLASS}.java"
        source.write_text(PROBE_SOURCE, encoding="utf-8")
        _run_tool(
            [
                str(tools["javac"]), "-encoding", "UTF-8",
                "-source", "8", "-target", "8", "-d", str(temp), str(source),
            ],
            stage="step0.jdk.compile_probe",
            reason_prefix="JDK_JAVAC_PROBE",
        )
        class_file = temp / f"{PROBE_CLASS}.class"
        if not class_file.is_file():
            raise JdkPreflightError(
                "JDK_JAVAC_PROBE_OUTPUT_MISSING", str(class_file)
            )
        javap_probe = _run_tool(
            [str(tools["javap"]), "-classpath", str(temp), "-p", "-s", PROBE_CLASS],
            stage="step0.jdk.javap_probe",
            reason_prefix="JDK_JAVAP_PROBE",
            require_stdout=True,
        )
        if PROBE_CLASS not in str(javap_probe.stdout or ""):
            raise JdkPreflightError(
                "JDK_JAVAP_PROBE_OUTPUT_INVALID",
                str(javap_probe.stdout or "")[-1000:],
            )
        java_probe = _run_tool(
            [str(tools["java"]), "-cp", str(temp), PROBE_CLASS],
            stage="step0.jdk.java_probe",
            reason_prefix="JDK_JAVA_PROBE",
            require_stdout=True,
        )
        if str(java_probe.stdout or "").strip() != PROBE_OUTPUT:
            raise JdkPreflightError(
                "JDK_JAVA_PROBE_OUTPUT_INVALID",
                str(java_probe.stdout or "")[-1000:],
            )

    tool_records = {}
    for name, path in tools.items():
        version_result = version_results[name]
        version_output = "\n".join(
            value for value in (str(version_result.stdout or "").strip(), str(version_result.stderr or "").strip())
            if value
        )
        tool_records[name] = _tool_fingerprint(path, version_output)
    identity_payload = {
        "jdk_home": str(home),
        "release_sha256": _sha256_file(release_file),
        "java_major": major,
        "tools": tool_records,
        "platform": {
            "format": "jdk8-classpath" if major == 8 else "jimage-jmods",
            "content": [
                {
                    "path": str(path),
                    "sha256": _sha256_file(path),
                    "size_bytes": int(path.stat().st_size),
                }
                for path in platform_files
            ],
        },
        "probe": "compile-javap-execute-v1",
    }
    identity = hashlib.sha256(
        json.dumps(
            identity_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema": "java-upgrade-analyzer.jdk-preflight.v1",
        **identity_payload,
        "jdk_preflight_identity": identity,
        "status": "passed",
    }


def _preflight_input_signature(home: Path) -> tuple[tuple[str, int, int], ...]:
    candidates = [
        home / "release",
        *(jdk_tool_path(home, name) for name in ("java", "javac", "javap")),
        home / "lib" / "modules",
    ]
    jmods = home / "jmods"
    if jmods.is_dir():
        candidates.extend(sorted(jmods.glob("*.jmod")))
    legacy_lib = home / "jre" / "lib"
    if legacy_lib.is_dir():
        candidates.extend(sorted(legacy_lib.glob("*.jar")))
        extension_dir = legacy_lib / "ext"
        if extension_dir.is_dir():
            candidates.extend(sorted(extension_dir.glob("*.jar")))
    classes_dir = home / "jre" / "classes"
    if classes_dir.is_dir():
        candidates.extend(sorted(classes_dir.rglob("*.class")))
    signature = []
    for path in candidates:
        try:
            stat = path.stat()
            signature.append((str(path), int(stat.st_size), int(stat.st_mtime_ns)))
        except OSError:
            signature.append((str(path), -1, -1))
    return tuple(signature)


@lru_cache(maxsize=16)
def _cached_preflight(
    home_text: str,
    _input_signature: tuple[tuple[str, int, int], ...],
) -> dict[str, Any]:
    return _preflight_jdk_home_uncached(home_text)


def preflight_jdk_home(jdk_home: str | Path) -> dict[str, Any]:
    """Exercise and content-bind all JDK inputs used by later phases."""
    home = Path(jdk_home).expanduser().resolve()
    return _cached_preflight(str(home), _preflight_input_signature(home))


__all__ = [
    "JdkPreflightError",
    "jdk_tool_path",
    "preflight_jdk_home",
]
