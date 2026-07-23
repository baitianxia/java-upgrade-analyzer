#!/usr/bin/env python3
"""Validate the supported interpreter, parser packages, and Java toolchain."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import importlib
from importlib import metadata
from pathlib import Path
import platform
import re
import subprocess
import sys

from compat import find_executable, gradle_cmd


SUPPORTED_PYTHON = {(3, 12), (3, 13), (3, 14)}
SUPPORTED_PLATFORMS = {"Linux", "Darwin", "Windows"}
SUPPORTED_JDK_MAJORS = {11, 17, 21}
MINIMUM_MAVEN = (3, 8)
MINIMUM_GRADLE = (7, 6)
REQUIREMENTS_FILE = Path(__file__).resolve().parents[1] / "requirements-runtime.txt"


def _load_required_packages(path=REQUIREMENTS_FILE):
    packages = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        declaration = line.strip()
        if not declaration or declaration.startswith("#"):
            continue
        name, separator, version = declaration.partition("==")
        if not separator or not name or not version:
            raise ValueError(f"runtime dependency must use an exact == pin: {declaration}")
        packages[name] = version
    return packages


REQUIRED_PACKAGES = _load_required_packages()


@dataclass(frozen=True)
class ContractCheck:
    component: str
    status: str
    observed: str
    expected: str
    reason: str = ""


def _check(component, ok, observed, expected, reason=""):
    return ContractCheck(
        component=component,
        status="passed" if ok else "failed",
        observed=str(observed or "missing"),
        expected=expected,
        reason="" if ok else reason,
    )


def _run(command, timeout=15):
    executable = find_executable(command[0])
    if executable is None:
        return None, ""
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{exc.__class__.__name__}: {exc}"
    return completed.returncode == 0, (completed.stdout or "").strip()


def _version_tuple(text):
    match = re.search(r"(?<!\d)(\d+)(?:\.(\d+))?(?:\.(\d+))?", text or "")
    if not match:
        return ()
    return tuple(int(part or 0) for part in match.groups())


def _jdk_major(text):
    content = text or ""
    explicit = re.search(
        r"(?:openjdk|java)\s+version\s+\"([^\"]+)\"|"
        r"(?:javac|javap|jdeps)\s+([0-9][0-9._+-]*)",
        content,
        re.IGNORECASE,
    )
    if explicit:
        version = _version_tuple(explicit.group(1) or explicit.group(2))
    else:
        candidates = re.findall(r"(?<!\d)\d+(?:\.\d+){0,2}", content)
        version = _version_tuple(candidates[-1]) if candidates else ()
    if not version:
        return None
    return version[1] if version[0] == 1 and len(version) > 1 else version[0]


def validate_runtime_contract(*, require_maven=True, require_gradle=False, project_dir=None):
    checks = []
    python_version = sys.version_info[:2]
    python_implementation = platform.python_implementation()
    checks.append(_check(
        "python",
        python_implementation == "CPython" and python_version in SUPPORTED_PYTHON,
        f"{python_implementation} {platform.python_version()}",
        "CPython 3.12.x, 3.13.x, or 3.14.x",
        "unsupported_python; run the bootstrap with CPython 3.12-3.14",
    ))
    system = platform.system()
    checks.append(_check(
        "platform", system in SUPPORTED_PLATFORMS, system,
        "Linux, macOS, or Windows", "unsupported_platform",
    ))

    for distribution, expected in REQUIRED_PACKAGES.items():
        try:
            observed = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            observed = ""
        checks.append(_check(
            f"python_package:{distribution}", observed == expected, observed,
            expected, "missing_or_unpinned_runtime_dependency",
        ))
    for module_name in ("tree_sitter", "tree_sitter_java"):
        try:
            importlib.import_module(module_name)
            import_error = ""
        except Exception as exc:
            import_error = f"{exc.__class__.__name__}: {exc}"
        checks.append(_check(
            f"python_import:{module_name}", not import_error,
            "importable" if not import_error else import_error,
            "module imports successfully", "runtime_dependency_import_failed",
        ))

    commands = {
        "git": ["git", "--version"],
        "java": ["java", "-version"],
        "javac": ["javac", "-version"],
        "javap": ["javap", "-version"],
        "jdeps": ["jdeps", "-version"],
    }
    if require_maven:
        commands["mvn"] = ["mvn", "-version"]
    if require_gradle:
        commands["gradle"] = gradle_cmd(project_dir) + ["--version", "--no-daemon"]

    outputs = {}
    for name, command in commands.items():
        ok, output = _run(command)
        outputs[name] = output
        checks.append(_check(
            f"tool:{name}", ok is True, output.splitlines()[0] if output else "",
            "installed and executable", "tool_missing_or_not_executable",
        ))

    jdk_versions = {
        name: _jdk_major(outputs.get(name, ""))
        for name in ("java", "javac", "javap", "jdeps")
        if outputs.get(name)
    }
    observed_majors = {value for value in jdk_versions.values() if value is not None}
    checks.append(_check(
        "jdk_toolchain",
        len(jdk_versions) == 4
        and len(observed_majors) == 1
        and next(iter(observed_majors), None) in SUPPORTED_JDK_MAJORS,
        ", ".join(f"{name}={value or 'unknown'}" for name, value in sorted(jdk_versions.items())),
        "java/javac/javap/jdeps from one JDK 11, 17, or 21 toolchain",
        "unsupported_or_mixed_jdk_toolchain",
    ))

    if require_maven and outputs.get("mvn"):
        maven_version = _version_tuple(outputs["mvn"])
        java_match = re.search(r"Java version:\s*([^,\s]+)", outputs["mvn"], re.IGNORECASE)
        maven_java = _jdk_major(java_match.group(1)) if java_match else None
        active_java = next(iter(observed_majors), None) if len(observed_majors) == 1 else None
        checks.append(_check(
            "maven_runtime",
            maven_version[:2] >= MINIMUM_MAVEN and maven_java == active_java,
            f"maven={'.'.join(map(str, maven_version)) or 'unknown'}, java={maven_java or 'unknown'}",
            "Maven >= 3.8 using the active JDK",
            "unsupported_maven_or_mismatched_java_runtime",
        ))
    if require_gradle and outputs.get("gradle"):
        gradle_output = outputs["gradle"]
        gradle_match = re.search(r"(?m)^Gradle\s+([^\s]+)", gradle_output)
        gradle_version = _version_tuple(gradle_match.group(1)) if gradle_match else ()
        java_match = re.search(
            r"(?m)^(?:Launcher JVM|JVM):\s*([^\r\n]+)",
            gradle_output,
            re.IGNORECASE,
        )
        gradle_java = _jdk_major(java_match.group(1)) if java_match else None
        active_java = next(iter(observed_majors), None) if len(observed_majors) == 1 else None
        checks.append(_check(
            "gradle_runtime",
            gradle_version[:2] >= MINIMUM_GRADLE and gradle_java == active_java,
            f"gradle={'.'.join(map(str, gradle_version)) or 'unknown'}, java={gradle_java or 'unknown'}",
            "Gradle >= 7.6 using the active JDK",
            "unsupported_gradle_or_mismatched_java_runtime",
        ))
    return checks


def contract_payload(*, require_maven=True, require_gradle=False, project_dir=None):
    checks = validate_runtime_contract(
        require_maven=require_maven,
        require_gradle=require_gradle,
        project_dir=project_dir,
    )
    return {
        "status": "passed" if all(item.status == "passed" for item in checks) else "failed",
        "checks": [asdict(item) for item in checks],
    }
