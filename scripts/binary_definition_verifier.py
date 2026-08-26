#!/usr/bin/env python3
"""Run isolated, non-initializing class definition checks on the target JVM."""

from __future__ import annotations

from functools import lru_cache
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import time
import weakref
from typing import Any, Mapping

from binary_asm_helper import _read_frame
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_platform_image import JdkPlatformImage
from binary_tool_execution import execute_binary_tool, tool_failure_is_retryable
from jdk_preflight import jdk_tool_path
from path_runtime import make_short_temp_dir, short_temporary_directory


JAVA_HELPER = Path(__file__).resolve().parent / "java" / "ClassDefinitionVerifier.java"
SCHEMA = "target-jvm-definition-v2"
_BUNDLE_MAGIC = b"JUACLSB2"
_MAX_BUNDLE_CLASS_NAME_BYTES = 1024 * 1024
_MAX_BUNDLE_CLASS_BYTES = 0x7FFF_FFFF
_VERIFY_MAX_ATTEMPTS = 2
_VERIFY_INVOCATION_TIMEOUT_SECONDS = 300.0
_VERIFY_PHASE_TIME_BUDGET_SECONDS = 1800.0


class ClassDefinitionVerifierError(BinaryFirstContractError):
    pass


def _is_valid_internal_class_name(value: Any) -> bool:
    """Match the JVMS 4.2.1/4.2.2 internal-name grammar.

    An internal name is a slash-separated sequence of non-empty unqualified
    names.  The JVM excludes only ``.``, ``;``, ``[`` and the separator ``/``
    from each component; source-language identifier rules do not apply.
    """

    if type(value) is not str or not value:
        return False
    return all(
        component
        and not any(character in component for character in ".;[")
        for component in value.split("/")
    )


def _remove_owned_helper_directory(
    path: Path,
    owner_pid: int,
    getpid=os.getpid,
    rmtree=shutil.rmtree,
) -> None:
    if getpid() == owner_pid:
        rmtree(path, ignore_errors=True)


class _OwnedHelperDirectory:
    def __init__(self, prefix: str) -> None:
        self.path = make_short_temp_dir(prefix=prefix)
        self._finalizer = weakref.finalize(
            self,
            _remove_owned_helper_directory,
            self.path,
            os.getpid(),
        )

    def cleanup(self) -> None:
        self._finalizer()


class _CompiledDefinitionHelper:
    def __init__(
        self,
        output: Path,
        temporary_directory: _OwnedHelperDirectory,
    ) -> None:
        self.output = output
        self._temporary_directory = temporary_directory


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@lru_cache(maxsize=8)
def _compile_helper(
    javac_text: str,
    source_sha256: str,
) -> _CompiledDefinitionHelper:
    temporary = _OwnedHelperDirectory("definition-verifier")
    output = temporary.path
    try:
        completed = execute_binary_tool(
            [
                javac_text,
                "-encoding", "UTF-8",
                "-source", "8",
                "-target", "8",
                "-d", str(output),
                str(JAVA_HELPER),
            ],
            stage="binary_definition.compile_helper",
            reason_prefix="CLASS_DEFINITION_HELPER_COMPILE",
            timeout_seconds=60,
        )
        if not completed.succeeded:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_HELPER_COMPILE_FAILED",
                json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
            )
        if not (output / "ClassDefinitionVerifier.class").is_file():
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_HELPER_COMPILE_INCOMPLETE", "helper class missing"
            )
        return _CompiledDefinitionHelper(output, temporary)
    except BaseException:
        temporary.cleanup()
        raise


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_compile_helper.cache_clear)


def verifier_identity(platform: JdkPlatformImage) -> str:
    verification_flags = ["-Xverify:all", "initialize=false", "reflection-member-linkage"]
    if platform.platform_image_format == "jdk8-classpath":
        verification_flags.append("isolated-jdk8-extension-directory")
    return canonical_identity(
        "class_definition_verifier_identity",
        {
            "schema": SCHEMA,
            "helper_sha256": _sha256_file(JAVA_HELPER),
            "runtime_platform_image_identity": platform.identity,
            "target_java_launcher_sha256": _sha256_file(platform.java_executable),
            "verification_flags": verification_flags,
        },
        schema_version="1",
    )


def _write_class_bundle(
    path: Path,
    names: list[str],
    selected_class_bytes: Mapping[str, bytes],
) -> dict[str, str]:
    """Write one bounded random-access class bundle for the target JVM.

    A single bundle preserves the exact selected class bytes while avoiding a
    directory entry and later recursive deletion for every class.  The Java
    verifier independently validates the magic, count, sorted unique names,
    record bounds, and absence of trailing bytes before defining any class.
    """

    if len(names) > 0x7FFF_FFFF:
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_BUNDLE_COUNT_INVALID",
            "class bundle count exceeds the verifier limit",
        )
    expected_hashes: dict[str, str] = {}
    with path.open("xb") as handle:
        handle.write(_BUNDLE_MAGIC)
        handle.write(struct.pack(">I", len(names)))
        for name in names:
            if not _is_valid_internal_class_name(name):
                raise ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_NAME_INVALID", name
                )
            try:
                name_bytes = name.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_NAME_INVALID", name
                ) from error
            content = bytes(selected_class_bytes[name])
            if (
                len(name_bytes) > _MAX_BUNDLE_CLASS_NAME_BYTES
                or not content
                or len(content) > _MAX_BUNDLE_CLASS_BYTES
            ):
                raise ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_BUNDLE_RECORD_INVALID", name
                )
            expected_hashes[name] = hashlib.sha256(content).hexdigest()
            handle.write(struct.pack(">II", len(name_bytes), len(content)))
            handle.write(name_bytes)
            handle.write(content)
    return expected_hashes


def _parse_verifier_output(
    stdout: bytes,
    names: list[str],
    selected_class_bytes: Mapping[str, bytes],
    expected_hashes: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    stream = io.BytesIO(stdout)
    raw_header, present = _read_frame(stream, max_frame_bytes=4 * 1024 * 1024)
    if not present:
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_PROTOCOL_HEADER_MISSING", "verifier emitted no frames"
        )
    header = json.loads(raw_header)
    if header != {
        "frame_type": "definition_output_header",
        "schema": SCHEMA,
        "class_count": len(names),
    }:
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_PROTOCOL_HEADER_INVALID", str(header)
        )
    records = {}
    footer = None
    while True:
        raw, present = _read_frame(stream, max_frame_bytes=4 * 1024 * 1024)
        if not present:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_PROTOCOL_FOOTER_MISSING", "definition footer missing"
            )
        record = json.loads(raw)
        if record.get("frame_type") == "definition_output_footer":
            footer = record
            break
        if record.get("frame_type") != "class_definition":
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_PROTOCOL_FRAME_INVALID", str(record.get("frame_type"))
            )
        name = str(record.get("class_name") or "")
        if name not in selected_class_bytes or name not in expected_hashes or name in records:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_PROTOCOL_CLASS_SET_INVALID", name
            )
        actual_sha = expected_hashes[name]
        if record.get("class_bytes_sha256") != actual_sha:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_PROTOCOL_SHA_MISMATCH", name
            )
        records[name] = record
    if stream.read(1):
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_PROTOCOL_STRAY_BYTES", "bytes follow verifier footer"
        )
    ready = sum(item.get("status") == "definition_ready" for item in records.values())
    expected_footer = {
        "frame_type": "definition_output_footer",
        "class_count": len(names),
        "definition_ready_count": ready,
        "failure_count": len(names) - ready,
    }
    if footer != expected_footer or set(records) != set(names):
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_PROTOCOL_CONSERVATION_FAILED",
            f"footer={footer}; expected={expected_footer}; missing={sorted(set(names)-set(records))}",
        )
    return records


def _verification_process_failure(
    name: str,
    class_bytes_sha256: str,
    error: ClassDefinitionVerifierError,
    *,
    status: str = "verification_failed",
    isolation_status: str = "single_class_failure",
) -> dict[str, Any]:
    stable_message = {
        "CLASS_DEFINITION_NAME_INVALID": "internal class name is invalid",
        "CLASS_DEFINITION_VERIFIER_TIMEOUT": (
            "target JVM verifier exceeded its bounded execution budget"
        ),
        "CLASS_DEFINITION_VERIFIER_FAILED": (
            "target JVM verifier failed after retry and binary isolation"
        ),
    }.get(
        error.reason_code,
        "target JVM verifier could not produce class-specific evidence",
    )
    return {
        "frame_type": "class_definition",
        "class_name": name,
        "class_bytes_sha256": class_bytes_sha256,
        "status": status,
        "failure_phase": "verifier_process",
        "failure_kind": error.reason_code,
        # Never persist command lines, temporary bundle paths, elapsed
        # timeout fractions, or OS error text into reconciliation identity.
        "failure_message": stable_message,
        "isolation_status": isolation_status,
    }


def _execute_verifier_range(
    *,
    platform: JdkPlatformImage,
    helper_dir: Path,
    java_options: list[str],
    bundle_path: Path,
    names: list[str],
    start: int,
    end: int,
    selected_class_bytes: Mapping[str, bytes],
    expected_hashes: Mapping[str, str],
    deadline: float,
    invocation_budget_seconds: float,
) -> dict[str, dict[str, Any]]:
    subset = names[start:end]
    last_failure = None
    invocation_deadline = min(
        deadline,
        time.perf_counter() + max(0.01, invocation_budget_seconds),
    )
    for attempt in range(1, _VERIFY_MAX_ATTEMPTS + 1):
        remaining = invocation_deadline - time.perf_counter()
        if remaining <= 0.01:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_VERIFIER_TIMEOUT",
                f"definition verifier budget exhausted for range {start}:{end}",
            )
        completed = execute_binary_tool(
            [
                str(platform.java_executable),
                *java_options,
                "-cp", str(helper_dir),
                "ClassDefinitionVerifier",
                str(bundle_path),
                str(start),
                str(end),
            ],
            stage="binary_definition.verify",
            reason_prefix="CLASS_DEFINITION_VERIFIER",
            timeout_seconds=remaining,
            text=False,
            require_stdout=True,
        )
        if completed.succeeded:
            try:
                return _parse_verifier_output(
                    completed.stdout,
                    subset,
                    selected_class_bytes,
                    expected_hashes,
                )
            except ClassDefinitionVerifierError:
                raise
            except (
                BinaryFirstContractError,
                UnicodeError,
                ValueError,
                TypeError,
                KeyError,
            ) as error:
                raise ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_PROTOCOL_INVALID",
                    f"{type(error).__name__}: {error}",
                ) from error
        last_failure = completed.failure
        # A timed-out multi-class process is already the isolation signal.
        # Re-running the same poisoned range would consume another full
        # invocation allowance before bisection can make progress. Single
        # classes still receive the normal transient retry.
        if (
            last_failure is not None
            and last_failure.failure_kind == "timeout"
            and len(subset) > 1
        ):
            break
        if not tool_failure_is_retryable(last_failure):
            break
    reason = (
        "CLASS_DEFINITION_VERIFIER_TIMEOUT"
        if last_failure is not None and last_failure.failure_kind == "timeout"
        else "CLASS_DEFINITION_VERIFIER_FAILED"
    )
    detail = (
        last_failure.to_mapping()
        if last_failure is not None
        else {"failure_kind": "missing_failure_detail"}
    )
    detail.update({
        "attempt_count": attempt,
        "range_start": start,
        "range_end": end,
    })
    raise ClassDefinitionVerifierError(
        reason,
        json.dumps(detail, ensure_ascii=False),
    )


def verify_class_definitions(
    platform: JdkPlatformImage,
    selected_class_bytes: Mapping[str, bytes],
    *,
    timeout_seconds: float = _VERIFY_INVOCATION_TIMEOUT_SECONDS,
    phase_time_budget_seconds: float = _VERIFY_PHASE_TIME_BUDGET_SECONDS,
) -> dict[str, dict[str, Any]]:
    source_sha = _sha256_file(JAVA_HELPER)
    javac = jdk_tool_path(platform.jdk_home, "javac")
    if not javac.is_file():
        raise ClassDefinitionVerifierError(
            "TARGET_JAVAC_MISSING", "a full target JDK is required to compile the verifier"
        )
    compiled_helper = _compile_helper(str(javac), source_sha)
    helper_dir = compiled_helper.output
    all_names = sorted(selected_class_bytes)
    invalid_names = [
        name for name in all_names if not _is_valid_internal_class_name(name)
    ]
    invalid_name_set = set(invalid_names)
    names = [name for name in all_names if name not in invalid_name_set]
    verifier_id = verifier_identity(platform)
    isolated: dict[str, dict[str, Any]] = {}
    for name in invalid_names:
        content = bytes(selected_class_bytes[name])
        error = ClassDefinitionVerifierError(
            "CLASS_DEFINITION_NAME_INVALID", name
        )
        isolated[name] = {
            **_verification_process_failure(
                name,
                hashlib.sha256(content).hexdigest(),
                error,
                isolation_status="invalid_name_isolated",
            ),
            "class_definition_verifier_identity": verifier_id,
        }

    invocation_timeout = float(timeout_seconds)
    phase_budget = float(phase_time_budget_seconds)
    if invocation_timeout <= 0 or phase_budget <= 0:
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_VERIFIER_TIMEOUT",
            f"invocation={timeout_seconds}; phase={phase_time_budget_seconds}",
        )
    deadline = time.perf_counter() + phase_budget
    with short_temporary_directory(prefix="definition-input") as temp_text:
        bundle_path = Path(temp_text) / "classes.bundle"
        expected_hashes = _write_class_bundle(
            bundle_path, names, selected_class_bytes
        )
        java_options = ["-Xverify:all"]
        if platform.platform_image_format == "jdk8-classpath":
            java_options.append(
                f"-Djava.ext.dirs={platform.legacy_extension_dir or ''}"
            )

        def verify_range(start: int, end: int) -> dict[str, dict[str, Any]]:
            size = end - start
            remaining = deadline - time.perf_counter()
            if remaining <= 0.01:
                timeout = ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_VERIFIER_TIMEOUT",
                    f"definition verifier phase budget exhausted at {start}:{end}",
                )
                return {
                    name: _verification_process_failure(
                        name,
                        expected_hashes[name],
                        timeout,
                        status="verification_unavailable",
                        isolation_status=(
                            "range_unverified_phase_budget_exhausted"
                        ),
                    )
                    for name in names[start:end]
                }
            # A realm has a larger phase allowance than any one JVM. A
            # healthy large range retains the historical 300-second process
            # allowance, while a crash or timeout leaves deterministic budget
            # for recursive isolation.
            invocation_budget = min(invocation_timeout, remaining)
            try:
                return _execute_verifier_range(
                    platform=platform,
                    helper_dir=helper_dir,
                    java_options=java_options,
                    bundle_path=bundle_path,
                    names=names,
                    start=start,
                    end=end,
                    selected_class_bytes=selected_class_bytes,
                    expected_hashes=expected_hashes,
                    deadline=deadline,
                    invocation_budget_seconds=invocation_budget,
                )
            except ClassDefinitionVerifierError as error:
                if error.reason_code not in {
                    "CLASS_DEFINITION_VERIFIER_TIMEOUT",
                    "CLASS_DEFINITION_VERIFIER_FAILED",
                }:
                    raise
                if size <= 0:
                    raise
                if size == 1:
                    name = names[start]
                    return {
                        name: _verification_process_failure(
                            name, expected_hashes[name], error
                        )
                    }
                midpoint = start + size // 2
                return {
                    **verify_range(start, midpoint),
                    **verify_range(midpoint, end),
                }

        records = verify_range(0, len(names))
    return {
        **isolated,
        **{
            name: {
                **record,
                "class_definition_verifier_identity": verifier_id,
            }
            for name, record in records.items()
        },
    }


__all__ = [
    "ClassDefinitionVerifierError",
    "verifier_identity",
    "verify_class_definitions",
]
