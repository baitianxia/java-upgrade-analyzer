#!/usr/bin/env python3
"""Validate the supported interpreter, parser packages, and Java toolchain."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import importlib
from importlib import metadata
from pathlib import Path
import platform
import re
import sys

from compat import find_executable, gradle_cmd, mvn_cmd, run_cmd


MINIMUM_PYTHON = (3, 10)
CI_VERIFIED_PYTHON = {(3, 12), (3, 13), (3, 14)}
REQUIRED_PYTHON_IMPLEMENTATION = "CPython"
SUPPORTED_PLATFORMS = {"Linux", "Darwin", "Windows"}
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


def python_runtime_expectation():
    verified = ", ".join(
        f"{major}.{minor}.x" for major, minor in sorted(CI_VERIFIED_PYTHON)
    )
    return (
        f"{REQUIRED_PYTHON_IMPLEMENTATION} {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} "
        f"or newer (CI-verified: {verified})"
    )


def is_python_runtime_compatible(implementation=None, version=None):
    implementation = implementation or platform.python_implementation()
    version = tuple(version or sys.version_info[:2])[:2]
    return (
        implementation == REQUIRED_PYTHON_IMPLEMENTATION
        and version >= MINIMUM_PYTHON
    )


def python_runtime_warning(implementation=None, version=None, version_text=None):
    implementation = implementation or platform.python_implementation()
    version = tuple(version or sys.version_info[:2])[:2]
    if not is_python_runtime_compatible(implementation, version):
        return None
    if version in CI_VERIFIED_PYTHON:
        return None
    observed_version = version_text or platform.python_version()
    return {
        "component": "python",
        "status": "warning",
        "observed": f"{implementation} {observed_version}",
        "expected": python_runtime_expectation(),
        "reason": "python_version_not_ci_verified",
    }


def _run(command, timeout=15):
    executable = find_executable(command[0])
    if executable is None:
        return None, ""
    stdout, stderr, rc = run_cmd(
        [executable, *command[1:]], timeout=timeout,
    )
    output = "\n".join(part.strip() for part in (stdout, stderr) if part.strip())
    return rc == 0, output


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


def validate_runtime_contract(
    *,
    require_java_tools=False,
    require_maven=False,
    require_gradle=False,
    project_dir=None,
):
    """Validate analyzer dependencies and only the explicitly requested tools.

    Project JDK/Maven/Gradle versions are intentionally not policy-gated here.
    The project wrapper, user-selected JAVA_HOME, and the real build command are
    the source of truth; incompatibilities must be reported by that command.
    """
    checks = []
    python_version = sys.version_info[:2]
    python_implementation = platform.python_implementation()
    python_ok = is_python_runtime_compatible(
        python_implementation,
        python_version,
    )
    if python_implementation != REQUIRED_PYTHON_IMPLEMENTATION:
        python_reason = "unsupported_python_implementation; use CPython"
    elif python_version < MINIMUM_PYTHON:
        python_reason = "python_below_minimum; use CPython 3.10 or newer"
    else:
        python_reason = ""
    checks.append(_check(
        "python",
        python_ok,
        f"{python_implementation} {platform.python_version()}",
        python_runtime_expectation(),
        python_reason,
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

    commands = {"git": ["git", "--version"]}
    if require_java_tools:
        commands.update({
            "java": ["java", "-version"],
            "javac": ["javac", "-version"],
            "javap": ["javap", "-version"],
            "jdeps": ["jdeps", "-version"],
        })
    if require_maven:
        commands["mvn"] = mvn_cmd(project_dir) + ["-version"]
    if require_gradle:
        commands["gradle"] = gradle_cmd(project_dir) + ["--version", "--no-daemon"]

    for name, command in commands.items():
        ok, output = _run(command)
        checks.append(_check(
            f"tool:{name}", ok is True, output.splitlines()[0] if output else "",
            "installed and executable", "tool_missing_or_not_executable",
        ))

    return checks


def contract_payload(
    *,
    require_java_tools=False,
    require_maven=False,
    require_gradle=False,
    project_dir=None,
):
    checks = validate_runtime_contract(
        require_java_tools=require_java_tools,
        require_maven=require_maven,
        require_gradle=require_gradle,
        project_dir=project_dir,
    )
    return {
        "status": "passed" if all(item.status == "passed" for item in checks) else "failed",
        "checks": [asdict(item) for item in checks],
        "warnings": [warning] if (warning := python_runtime_warning()) else [],
    }
