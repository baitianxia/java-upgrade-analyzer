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
import weakref
from typing import Any, Mapping

from binary_asm_helper import _read_frame
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_platform_image import JdkPlatformImage
from binary_tool_execution import execute_binary_tool
from jdk_preflight import jdk_tool_path
from path_runtime import make_short_temp_dir, short_temporary_directory


JAVA_HELPER = Path(__file__).resolve().parent / "java" / "ClassDefinitionVerifier.java"
SCHEMA = "target-jvm-definition-v2"
_BUNDLE_MAGIC = b"JUACLSB2"
_MAX_BUNDLE_CLASS_NAME_BYTES = 1024 * 1024
_MAX_BUNDLE_CLASS_BYTES = 0x7FFF_FFFF


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


def verify_class_definitions(
    platform: JdkPlatformImage,
    selected_class_bytes: Mapping[str, bytes],
    *,
    timeout_seconds: int = 300,
) -> dict[str, dict[str, Any]]:
    source_sha = _sha256_file(JAVA_HELPER)
    javac = jdk_tool_path(platform.jdk_home, "javac")
    if not javac.is_file():
        raise ClassDefinitionVerifierError(
            "TARGET_JAVAC_MISSING", "a full target JDK is required to compile the verifier"
        )
    compiled_helper = _compile_helper(str(javac), source_sha)
    helper_dir = compiled_helper.output
    names = sorted(selected_class_bytes)
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
        completed = execute_binary_tool(
            [
                str(platform.java_executable),
                *java_options,
                "-cp", str(helper_dir),
                "ClassDefinitionVerifier",
                str(bundle_path),
            ],
            stage="binary_definition.verify",
            reason_prefix="CLASS_DEFINITION_VERIFIER",
            timeout_seconds=timeout_seconds,
            text=False,
            require_stdout=True,
        )
    if not completed.succeeded:
        reason = (
            "CLASS_DEFINITION_VERIFIER_TIMEOUT"
            if completed.failure.failure_kind == "timeout"
            else "CLASS_DEFINITION_VERIFIER_FAILED"
        )
        raise ClassDefinitionVerifierError(
            reason,
            json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
        )
    stream = io.BytesIO(completed.stdout)
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
        if name not in selected_class_bytes or name in records:
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
    verifier_id = verifier_identity(platform)
    return {
        name: {**record, "class_definition_verifier_identity": verifier_id}
        for name, record in records.items()
    }


__all__ = [
    "ClassDefinitionVerifierError",
    "verifier_identity",
    "verify_class_definitions",
]
