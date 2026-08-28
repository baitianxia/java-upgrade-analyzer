#!/usr/bin/env python3
"""Pinned ASM helper launcher and fail-closed framed protocol validator."""

from __future__ import annotations

import atexit
import base64
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import stat
import struct
import subprocess
import threading
import time
import weakref
from typing import Any, Callable, Iterable, Mapping

from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_tool_execution import execute_binary_tool
from jdk_preflight import jdk_tool_path
from compat import (
    finalize_parallel_process_tree_cleanup,
    managed_popen,
    release_process_tree,
    terminate_process_tree,
)
from path_runtime import make_short_temp_dir, short_temporary_directory


ASM_VERSION = "9.9.1"
ASM_SHA256 = "6f3828a215c920059a5efa2fb55c233d6c54ec5cadca99ce1b1bdd10077c7ddd"
MAX_SUPPORTED_CLASS_MAJOR = 70  # Java 26, the maximum declared by ASM 9.9.1.
PROTOCOL_SCHEMA = "binary-fact-frame-v1"
OUTPUT_SCHEMA = "binary-class-fact-v1"
VISITOR_POLICY_VERSION = "asm-lossless-facts-v3"
JAVA_HELPER = Path(__file__).resolve().parent / "java" / "BinaryFactExtractor.java"
SUPPORT_MANIFEST = Path(__file__).resolve().parent / "binary_first_support_manifest.json"
PARSER_IMPLEMENTATION_SOURCE_PATHS = (
    "artifact_safety.py",
    "binary_artifact_diff.py",
    "binary_asm_helper.py",
    "binary_first_contract.py",
    "binary_snapshot_cache.py",
    "binary_tool_execution.py",
    "compat.py",
    "jdk_preflight.py",
    "java/BinaryFactExtractor.java",
    "path_runtime.py",
)

DEFAULT_MAX_CLASS_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FRAME_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100_000
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_HEAP_MEGABYTES = 512
DEFAULT_MAX_PERSISTENT_SESSIONS = 6
MAX_PERSISTENT_SESSIONS = 8


class BinaryAsmError(BinaryFirstContractError):
    pass


def _remove_owned_helper_directory(
    path: Path,
    owner_pid: int,
    getpid: Callable[[], int] = os.getpid,
    rmtree: Callable[..., None] = shutil.rmtree,
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


@dataclass(frozen=True)
class _CompiledAsmHelper:
    output: Path
    java: str
    _temporary_directory: _OwnedHelperDirectory | None


@dataclass(frozen=True)
class CompiledAsmHelperBinding:
    """Content proof for one parent-compiled ASM helper directory."""

    asm_path: Path
    helper_sha256: str
    javac_path: str
    java_path: str
    output_path: Path
    class_files: tuple[tuple[str, int, str], ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "asm_path": str(self.asm_path),
            "helper_sha256": self.helper_sha256,
            "javac_path": self.javac_path,
            "java_path": self.java_path,
            "output_path": str(self.output_path),
            "class_files": [list(item) for item in self.class_files],
        }


@dataclass(frozen=True)
class BinaryClassInput:
    artifact_instance_identity: str
    class_entry: str
    class_bytes: bytes

    def __post_init__(self):
        if not str(self.artifact_instance_identity or "").strip():
            raise BinaryAsmError("ASM_ARTIFACT_IDENTITY_MISSING", "artifact identity is required")
        if not str(self.class_entry or "").strip():
            raise BinaryAsmError("ASM_CLASS_ENTRY_MISSING", "class entry is required")
        if not isinstance(self.class_bytes, bytes):
            raise BinaryAsmError("ASM_CLASS_BYTES_INVALID", "class_bytes must be bytes")


@dataclass(frozen=True)
class BinaryFactRun:
    parser_identity: str
    helper_sha256: str
    asm_jar_sha256: str
    records: tuple[dict[str, Any], ...]
    input_record_count: int
    fact_record_count: int
    failure_record_count: int
    class_input_digest: str
    fact_output_digest: str
    coverage_status: str
    stderr: str


@dataclass(frozen=True)
class ParserIdentityBinding:
    """Run-scoped, content-verified parser authority.

    The binding lets one pipeline run reuse the same parser identity without
    rereading the immutable implementation closure for every artifact. Its
    factory verifies all source, policy and ASM bytes; the pipeline verifies
    them again before a result can leave the run.
    """

    asm_path: Path
    parser_identity: str
    helper_sha256: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _parser_implementation_source_digests() -> dict[str, str]:
    scripts_dir = Path(__file__).resolve().parent
    return {
        relative: _sha256_file(scripts_dir / relative)
        for relative in PARSER_IMPLEMENTATION_SOURCE_PATHS
    }


def _artifact_diff_support_identity() -> str:
    try:
        support = json.loads(SUPPORT_MANIFEST.read_text(encoding="utf-8"))
        artifact_diff_support = support["artifact_diff_support_manifest"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError) as error:
        raise BinaryAsmError(
            "ASM_ARTIFACT_DIFF_SUPPORT_MANIFEST_INVALID", str(error)
        ) from error
    if not isinstance(artifact_diff_support, dict):
        raise BinaryAsmError(
            "ASM_ARTIFACT_DIFF_SUPPORT_MANIFEST_INVALID",
            "artifact_diff_support_manifest must be an object",
        )
    return canonical_identity(
        "artifact_diff_support_manifest_identity",
        artifact_diff_support,
        schema_version="1",
    )


def _parser_identity_from_inputs(
    implementation_source_digests: Mapping[str, str],
    artifact_diff_support_identity: str,
) -> str:
    if set(implementation_source_digests) != set(
        PARSER_IMPLEMENTATION_SOURCE_PATHS
    ):
        raise BinaryAsmError(
            "ASM_IMPLEMENTATION_SOURCE_SET_INVALID",
            "parser implementation source set is incomplete",
        )
    helper_sha = implementation_source_digests[
        "java/BinaryFactExtractor.java"
    ]
    return canonical_identity(
        "binary_asm_parser_identity",
        {
            "protocol_schema": PROTOCOL_SCHEMA,
            "output_schema": OUTPUT_SCHEMA,
            "asm_version": ASM_VERSION,
            "asm_jar_sha256": ASM_SHA256,
            "helper_sha256": helper_sha,
            "visitor_policy_version": VISITOR_POLICY_VERSION,
            "max_supported_class_major": MAX_SUPPORTED_CLASS_MAJOR,
            "implementation_sources": [
                {
                    "path": relative,
                    "sha256": str(
                        implementation_source_digests[relative]
                    ),
                }
                for relative in PARSER_IMPLEMENTATION_SOURCE_PATHS
            ],
            "artifact_diff_support_manifest_identity": (
                artifact_diff_support_identity
            ),
        },
        schema_version="1",
    )


_CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS = (
    _parser_implementation_source_digests()
)
_CAPTURED_ARTIFACT_DIFF_SUPPORT_IDENTITY = _artifact_diff_support_identity()


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _framed_digest_update(digest, payload: bytes) -> None:
    digest.update(struct.pack(">I", len(payload)))
    digest.update(payload)


def _write_frame(handle, payload: bytes) -> None:
    handle.write(struct.pack(">I", len(payload)))
    handle.write(payload)


def _read_exact(handle, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = handle.read(remaining)
        if not chunk:
            raise BinaryAsmError(
                "ASM_PROTOCOL_TRUNCATED",
                f"helper output ended with {remaining} frame bytes missing",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(handle, *, max_frame_bytes: int) -> tuple[bytes, bool]:
    prefix = handle.read(4)
    if not prefix:
        return b"", False
    if len(prefix) != 4:
        raise BinaryAsmError("ASM_PROTOCOL_STRAY_BYTES", "stdout has a partial frame prefix")
    length = struct.unpack(">I", prefix)[0]
    if length < 2 or length > max_frame_bytes:
        raise BinaryAsmError(
            "ASM_PROTOCOL_FRAME_LENGTH_INVALID",
            f"helper emitted frame length {length}, maximum is {max_frame_bytes}",
        )
    return _read_exact(handle, length), True


def resolve_asm_jar(explicit_path: str | Path | None = None) -> Path:
    if explicit_path:
        candidates = [Path(explicit_path).expanduser()]
    elif os.environ.get("JUA_ASM_JAR"):
        candidates = [Path(os.environ["JUA_ASM_JAR"]).expanduser()]
    else:
        candidates = [
            Path(__file__).resolve().parent / "vendor" / f"asm-{ASM_VERSION}.jar",
            Path.home() / ".m2" / "repository" / "org" / "ow2" / "asm" / "asm"
            / ASM_VERSION / f"asm-{ASM_VERSION}.jar",
        ]
    found_wrong = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        actual = _sha256_file(candidate)
        if actual == ASM_SHA256:
            return candidate.resolve()
        found_wrong.append(f"{candidate}:{actual}")
    reason = "ASM_PINNED_JAR_SHA256_MISMATCH" if found_wrong else "ASM_PINNED_JAR_MISSING"
    detail = "; ".join(found_wrong) if found_wrong else (
        f"set JUA_ASM_JAR to asm-{ASM_VERSION}.jar with SHA-256 {ASM_SHA256}"
    )
    raise BinaryAsmError(reason, detail)


def _verified_parser_identity() -> tuple[str, str]:
    current_sources = _parser_implementation_source_digests()
    current_support_identity = _artifact_diff_support_identity()
    if (
        current_sources != _CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS
        or current_support_identity
        != _CAPTURED_ARTIFACT_DIFF_SUPPORT_IDENTITY
    ):
        raise BinaryAsmError(
            "ASM_IMPLEMENTATION_CHANGED_DURING_RUN",
            "parser source or artifact-diff support changed after process start",
        )
    identity = _parser_identity_from_inputs(
        _CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS,
        _CAPTURED_ARTIFACT_DIFF_SUPPORT_IDENTITY,
    )
    return identity, _CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS[
        "java/BinaryFactExtractor.java"
    ]


def parser_identity(*, asm_jar: Path | None = None) -> tuple[str, str]:
    resolve_asm_jar(asm_jar)
    return _verified_parser_identity()


def capture_parser_identity_binding(
    *, asm_jar: str | Path | None = None,
) -> ParserIdentityBinding:
    """Verify and bind one exact parser implementation for a pipeline run."""

    asm_path = resolve_asm_jar(asm_jar)
    identity, helper_sha = _verified_parser_identity()
    return ParserIdentityBinding(
        asm_path=asm_path,
        parser_identity=identity,
        helper_sha256=helper_sha,
    )


def parser_identity_from_binding(
    binding: ParserIdentityBinding,
    *,
    asm_jar: str | Path | None = None,
) -> tuple[Path, str, str]:
    """Use a previously verified binding without another content scan."""

    if type(binding) is not ParserIdentityBinding:
        raise BinaryAsmError(
            "ASM_PARSER_IDENTITY_BINDING_INVALID",
            "binding must be created by capture_parser_identity_binding",
        )
    bound_path = Path(binding.asm_path)
    if not bound_path.is_absolute():
        raise BinaryAsmError(
            "ASM_PARSER_IDENTITY_BINDING_INVALID", "ASM path is not absolute"
        )
    if asm_jar is not None and Path(asm_jar).expanduser().resolve() != bound_path:
        raise BinaryAsmError(
            "ASM_PARSER_IDENTITY_BINDING_MISMATCH",
            f"requested={Path(asm_jar).expanduser().resolve()}; bound={bound_path}",
        )
    for field_name, value in (
        ("parser_identity", binding.parser_identity),
        ("helper_sha256", binding.helper_sha256),
    ):
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise BinaryAsmError(
                "ASM_PARSER_IDENTITY_BINDING_INVALID", field_name
            )
    return bound_path, binding.parser_identity, binding.helper_sha256


def verify_parser_identity_binding(binding: ParserIdentityBinding) -> None:
    """Fail closed if any byte behind a run-scoped binding has changed."""

    asm_path, expected_identity, expected_helper_sha = (
        parser_identity_from_binding(binding)
    )
    # resolve_asm_jar performs the pinned ASM byte check. The identity helper
    # then rereads the complete parser source and policy closure.
    resolved = resolve_asm_jar(asm_path)
    actual_identity, actual_helper_sha = _verified_parser_identity()
    if (
        resolved != asm_path
        or actual_identity != expected_identity
        or actual_helper_sha != expected_helper_sha
    ):
        raise BinaryAsmError(
            "ASM_PARSER_IDENTITY_BINDING_CHANGED",
            "parser implementation changed after the run binding was captured",
        )


@lru_cache(maxsize=8)
def _compile_helper(
    asm_jar_text: str,
    helper_sha: str,
    javac_text: str = "",
    java_text: str = "",
) -> _CompiledAsmHelper:
    javac = javac_text or shutil.which("javac")
    java = java_text or shutil.which("java")
    if not javac or not java:
        raise BinaryAsmError(
            "ASM_JAVA_TOOLCHAIN_MISSING", "both java and javac are required for the ASM helper"
        )
    temporary = _OwnedHelperDirectory("binary-asm-helper")
    output = temporary.path
    try:
        completed = execute_binary_tool(
            [
                javac,
                "-encoding", "UTF-8",
                "-cp", asm_jar_text,
                "-d", str(output),
                str(JAVA_HELPER),
            ],
            stage="binary_asm.compile_helper",
            reason_prefix="ASM_HELPER_COMPILE",
            timeout_seconds=60,
        )
        if not completed.succeeded:
            raise BinaryAsmError(
                "ASM_HELPER_COMPILE_FAILED",
                json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
            )
        class_file = output / "BinaryFactExtractor.class"
        if not class_file.is_file():
            raise BinaryAsmError(
                "ASM_HELPER_COMPILE_INCOMPLETE", "main helper class is missing"
            )
        return _CompiledAsmHelper(output, java, temporary)
    except BaseException:
        temporary.cleanup()
        raise


def _compiled_helper_manifest(
    output: Path,
) -> tuple[tuple[str, int, str], ...]:
    root = Path(output)
    try:
        if (
            not root.is_absolute()
            or root.resolve() != root
            or not stat.S_ISDIR(root.lstat().st_mode)
        ):
            raise ValueError("compiled helper root is not a canonical directory")
        records = []
        for path in sorted(root.rglob("*")):
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode) or path.suffix != ".class":
                raise ValueError("compiled helper contains an unexpected entry")
            relative = path.relative_to(root).as_posix()
            size = path.stat().st_size
            records.append((relative, size, _sha256_file(path)))
    except (OSError, ValueError) as error:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", str(error)
        ) from error
    if not records or not any(
        name == "BinaryFactExtractor.class" for name, _size, _sha in records
    ):
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", "main helper class is missing"
        )
    return tuple(records)


def compiled_asm_helper_binding_from_mapping(
    value: Mapping[str, Any],
) -> CompiledAsmHelperBinding:
    fields = {
        "asm_path", "helper_sha256", "javac_path", "java_path",
        "output_path", "class_files",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", "binding fields changed"
        )
    raw_files = value.get("class_files")
    if not isinstance(raw_files, list):
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", "class_files"
        )
    class_files = []
    for item in raw_files:
        if (
            not isinstance(item, list)
            or len(item) != 3
            or type(item[0]) is not str
            or type(item[1]) is not int
            or type(item[2]) is not str
        ):
            raise BinaryAsmError(
                "ASM_COMPILED_HELPER_BINDING_INVALID", "class_files"
            )
        class_files.append((item[0], item[1], item[2]))
    return CompiledAsmHelperBinding(
        asm_path=Path(str(value["asm_path"])),
        helper_sha256=str(value["helper_sha256"]),
        javac_path=str(value["javac_path"]),
        java_path=str(value["java_path"]),
        output_path=Path(str(value["output_path"])),
        class_files=tuple(class_files),
    )


def _compiled_helper_from_binding(
    binding: CompiledAsmHelperBinding,
) -> _CompiledAsmHelper:
    if type(binding) is not CompiledAsmHelperBinding:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", "binding type"
        )
    for field_name, value in (
        ("helper_sha256", binding.helper_sha256),
        *(
            (f"class_files[{index}].sha256", item[2])
            for index, item in enumerate(binding.class_files)
        ),
    ):
        if (
            len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise BinaryAsmError(
                "ASM_COMPILED_HELPER_BINDING_INVALID", field_name
            )
    asm_path = binding.asm_path
    output_path = binding.output_path
    java_path = Path(binding.java_path)
    javac_path = Path(binding.javac_path)
    try:
        canonical_paths = all(
            path.is_absolute() and path.resolve() == path
            for path in (asm_path, output_path, java_path, javac_path)
        )
    except OSError as error:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", str(error)
        ) from error
    if not canonical_paths or not java_path.is_file() or not javac_path.is_file():
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_INVALID", "tool paths changed"
        )
    if resolve_asm_jar(asm_path) != asm_path:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_CHANGED", "ASM path changed"
        )
    if _sha256_file(JAVA_HELPER) != binding.helper_sha256:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_CHANGED", "helper source changed"
        )
    actual_manifest = _compiled_helper_manifest(output_path)
    if actual_manifest != binding.class_files:
        raise BinaryAsmError(
            "ASM_COMPILED_HELPER_BINDING_CHANGED", "compiled classes changed"
        )
    return _CompiledAsmHelper(output_path, str(java_path), None)


_INSTALLED_COMPILED_ASM_HELPER: tuple[
    CompiledAsmHelperBinding, _CompiledAsmHelper
] | None = None


def capture_compiled_asm_helper_binding(
    *,
    asm_jar: str | Path | None = None,
    jdk_home: str | Path | None = None,
    parser_identity_binding: ParserIdentityBinding | None = None,
) -> CompiledAsmHelperBinding:
    """Compile once in the parent and bind every resulting class byte."""

    if parser_identity_binding is None:
        asm_path = resolve_asm_jar(asm_jar)
        _identity, helper_sha = parser_identity(asm_jar=asm_path)
    else:
        asm_path, _identity, helper_sha = parser_identity_from_binding(
            parser_identity_binding, asm_jar=asm_jar
        )
    if jdk_home is None:
        javac_value = shutil.which("javac")
        java_value = shutil.which("java")
        if not javac_value or not java_value:
            raise BinaryAsmError(
                "ASM_JAVA_TOOLCHAIN_MISSING", "java and javac are required"
            )
        javac = Path(javac_value).resolve()
        java = Path(java_value).resolve()
    else:
        javac = jdk_tool_path(jdk_home, "javac").resolve()
        java = jdk_tool_path(jdk_home, "java").resolve()
    compiled = _compile_helper(
        str(asm_path), helper_sha, str(javac), str(java)
    )
    return CompiledAsmHelperBinding(
        asm_path=asm_path,
        helper_sha256=helper_sha,
        javac_path=str(javac),
        java_path=str(java),
        output_path=compiled.output,
        class_files=_compiled_helper_manifest(compiled.output),
    )


def install_compiled_asm_helper_binding(
    binding: CompiledAsmHelperBinding,
) -> None:
    """Verify and install a parent-owned compiled helper in one child."""

    compiled = _compiled_helper_from_binding(binding)
    global _INSTALLED_COMPILED_ASM_HELPER
    _INSTALLED_COMPILED_ASM_HELPER = (binding, compiled)


def verify_compiled_asm_helper_binding(
    binding: CompiledAsmHelperBinding,
) -> None:
    """Recheck every bound byte before worker evidence may escape."""

    _compiled_helper_from_binding(binding)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_compile_helper.cache_clear)


def _validate_class_record(
    record: dict[str, Any],
    expected: dict[tuple[str, str], str],
) -> tuple[str, str]:
    key = (
        str(record.get("artifact_instance_identity") or ""),
        str(record.get("class_entry") or ""),
    )
    expected_sha = expected.get(key)
    if expected_sha is None:
        raise BinaryAsmError(
            "ASM_PROTOCOL_UNKNOWN_CLASS_RECORD", f"helper returned unexpected class {key}"
        )
    if record.get("class_bytes_sha256") != expected_sha:
        raise BinaryAsmError(
            "ASM_PROTOCOL_CLASS_SHA_MISMATCH", f"helper returned wrong content identity for {key}"
        )
    if record.get("frame_type") == "class_failure":
        if not record.get("failure_kind"):
            raise BinaryAsmError(
                "ASM_PROTOCOL_FAILURE_INCOMPLETE", f"failure record lacks failure kind for {key}"
            )
        return key
    required = {
        "class_name", "class_major", "class_access", "fields", "methods",
        "attribute_inventory", "attribute_inventory_digest", "class_contract_digest",
    }
    missing = sorted(required - set(record))
    if missing:
        raise BinaryAsmError(
            "ASM_PROTOCOL_CLASS_FACT_INCOMPLETE", f"{key} is missing fields {missing}"
        )
    for method in record.get("methods") or ():
        if not isinstance(method, dict) or not {
            "contract", "instructions", "try_catch", "implementation_digest"
        }.issubset(method):
            raise BinaryAsmError(
                "ASM_PROTOCOL_METHOD_FACT_INCOMPLETE", f"incomplete method record for {key}"
            )
    return key


@dataclass(frozen=True)
class _ParsedHelperOutput:
    records: tuple[dict[str, Any], ...]
    fact_count: int
    failure_count: int
    output_count: int
    fact_output_digest: str
    returned_keys: frozenset[tuple[str, str]]
    footer: dict[str, Any]


def _read_helper_output(
    stdout,
    *,
    identity: str,
    helper_sha: str,
    expected: dict[tuple[str, str], str],
    max_frame_bytes: int,
    max_records: int,
    record_consumer: Callable[[dict[str, Any]], None] | None,
    retain_records: bool,
    require_eof: bool,
) -> _ParsedHelperOutput:
    """Consume and validate one complete helper response.

    Persistent and one-shot transports deliberately share this parser.  JVM
    reuse therefore changes only process transport; every header, record,
    digest, cardinality and input/output-set check remains identical.
    """

    retained = []
    fact_count = 0
    failure_count = 0
    output_count = 0
    returned_keys: set[tuple[str, str]] = set()
    record_digest = hashlib.sha256()
    header_bytes, present = _read_frame(
        stdout, max_frame_bytes=max_frame_bytes
    )
    if not present:
        raise BinaryAsmError(
            "ASM_PROTOCOL_HEADER_MISSING", "helper emitted no output"
        )
    header = json.loads(header_bytes)
    if header != {
        "frame_type": "output_header",
        "protocol_schema": PROTOCOL_SCHEMA,
        "output_schema": OUTPUT_SCHEMA,
        "parser_identity": identity,
        "helper_sha256": helper_sha,
        "asm_version": ASM_VERSION,
        "max_supported_class_major": MAX_SUPPORTED_CLASS_MAJOR,
    }:
        raise BinaryAsmError(
            "ASM_PROTOCOL_HEADER_INVALID", f"unexpected helper header: {header}"
        )
    while True:
        raw, present = _read_frame(stdout, max_frame_bytes=max_frame_bytes)
        if not present:
            raise BinaryAsmError(
                "ASM_PROTOCOL_FOOTER_MISSING",
                "helper ended without output footer",
            )
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BinaryAsmError(
                "ASM_PROTOCOL_JSON_INVALID", f"invalid helper JSON: {error}"
            ) from error
        frame_type = record.get("frame_type")
        if frame_type == "output_footer":
            footer = record
            break
        if frame_type not in {"class_fact", "class_failure"}:
            raise BinaryAsmError(
                "ASM_PROTOCOL_FRAME_TYPE_INVALID", f"unexpected {frame_type}"
            )
        output_count += 1
        if output_count > max_records:
            raise BinaryAsmError(
                "ASM_OUTPUT_RECORD_LIMIT_EXCEEDED",
                f"output exceeds {max_records}",
            )
        _framed_digest_update(record_digest, raw)
        record_key = _validate_class_record(record, expected)
        if record_key in returned_keys:
            raise BinaryAsmError(
                "ASM_PROTOCOL_CLASS_RECORD_DUPLICATE",
                f"helper returned duplicate class record {record_key}",
            )
        returned_keys.add(record_key)
        if frame_type == "class_fact":
            fact_count += 1
        else:
            failure_count += 1
        if record_consumer is not None:
            record_consumer(record)
        if retain_records:
            retained.append(record)
    if require_eof:
        stray = stdout.read(1)
        if stray:
            raise BinaryAsmError(
                "ASM_PROTOCOL_STRAY_BYTES",
                "stdout contains bytes after output footer",
            )
    return _ParsedHelperOutput(
        records=tuple(retained),
        fact_count=fact_count,
        failure_count=failure_count,
        output_count=output_count,
        fact_output_digest=record_digest.hexdigest(),
        returned_keys=frozenset(returned_keys),
        footer=footer,
    )


class _AsmSessionError(RuntimeError):
    pass


class _AsmSession:
    """One exclusively leased reusable BinaryFactExtractor JVM."""

    def __init__(
        self,
        compiled_helper: _CompiledAsmHelper,
        asm_path: Path,
        identity: str,
        helper_sha: str,
        max_heap_megabytes: int,
    ) -> None:
        self.process = managed_popen(
            [
                compiled_helper.java,
                f"-Xmx{int(max_heap_megabytes)}m",
                "-cp",
                os.pathsep.join(
                    (str(compiled_helper.output), str(asm_path))
                ),
                "BinaryFactExtractor",
                identity,
                helper_sha,
                str(MAX_SUPPORTED_CLASS_MAJOR),
                "--session",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._closed = False
        self._close_lock = threading.Lock()
        self._stderr_tail = bytearray()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="binary-asm-session-stderr",
            daemon=True,
        )
        self._stderr_thread.start()

    @property
    def alive(self) -> bool:
        return not self._closed and self.process.poll() is None

    def _drain_stderr(self) -> None:
        handle = self.process.stderr
        if handle is None:
            return
        try:
            while True:
                block = handle.read(4096)
                if not block:
                    return
                self._stderr_tail.extend(block)
                if len(self._stderr_tail) > 64 * 1024:
                    del self._stderr_tail[:-64 * 1024]
        except (OSError, ValueError):
            return

    def exchange(
        self,
        protocol_input: Path,
        response_reader: Callable[[Any], _ParsedHelperOutput],
        timeout_seconds: float,
    ) -> tuple[_ParsedHelperOutput, str]:
        if not self.alive:
            raise _AsmSessionError("ASM session process is not alive")
        stdin = self.process.stdin
        stdout = self.process.stdout
        if stdin is None or stdout is None:
            raise _AsmSessionError("ASM session pipes are unavailable")

        timed_out = threading.Event()
        writer_done = threading.Event()
        writer_failure: list[BaseException] = []

        def write_request() -> None:
            try:
                with protocol_input.open("rb") as source:
                    shutil.copyfileobj(source, stdin, length=1024 * 1024)
                stdin.flush()
            except BaseException as error:
                writer_failure.append(error)
                self.close(terminate=True)
            finally:
                writer_done.set()

        def terminate_on_deadline() -> None:
            if self.alive:
                timed_out.set()
                self.close(terminate=True)

        writer = threading.Thread(
            target=write_request,
            name="binary-asm-session-request",
            daemon=True,
        )
        deadline = threading.Timer(timeout_seconds, terminate_on_deadline)
        timer_started = False
        try:
            deadline.daemon = True
            deadline.start()
            timer_started = True
            writer.start()
            parsed = response_reader(stdout)
            writer.join(timeout=max(0.01, float(timeout_seconds)))
            if writer.is_alive():
                timed_out.set()
                self.close(terminate=True)
                raise _AsmSessionError("ASM session request write timed out")
            if writer_failure:
                raise _AsmSessionError(
                    f"ASM session request write failed: {writer_failure[0]}"
                ) from writer_failure[0]
            if timed_out.is_set():
                raise _AsmSessionError("ASM session request timed out")
            if not self.alive:
                detail = bytes(self._stderr_tail).decode(
                    "utf-8", errors="replace"
                )
                raise _AsmSessionError(
                    "ASM session exited after response: " + detail[-2000:]
                )
            return parsed, ""
        except BaseException:
            self.close(terminate=True)
            raise
        finally:
            try:
                deadline.cancel()
            except BaseException:
                pass
            if timer_started:
                try:
                    deadline.join()
                except BaseException:
                    pass

    def close(self, *, terminate: bool) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        process = self.process
        try:
            if process.stdin is not None:
                process.stdin.close()
            if terminate and process.poll() is None:
                terminate_process_tree(process)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                terminate_process_tree(process)
                process.wait(timeout=5)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        finally:
            for handle in (process.stdout, process.stderr):
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
            release_process_tree(process)


class _AsmSessionPool:
    def __init__(
        self,
        compiled_helper: _CompiledAsmHelper,
        asm_path: Path,
        identity: str,
        helper_sha: str,
        max_heap_megabytes: int,
        max_sessions: int,
    ) -> None:
        self.compiled_helper = compiled_helper
        self.asm_path = asm_path
        self.identity = identity
        self.helper_sha = helper_sha
        self.max_heap_megabytes = int(max_heap_megabytes)
        self.max_sessions = max(
            1, min(MAX_PERSISTENT_SESSIONS, int(max_sessions))
        )
        self._idle: queue.LifoQueue[_AsmSession] = queue.LifoQueue()
        self._condition = threading.Condition()
        self._session_count = 0
        self._closed = False

    def _new_session(self) -> _AsmSession:
        return _AsmSession(
            self.compiled_helper,
            self.asm_path,
            self.identity,
            self.helper_sha,
            self.max_heap_megabytes,
        )

    def _acquire(self, deadline: float) -> _AsmSession:
        while True:
            with self._condition:
                if self._closed:
                    raise _AsmSessionError("ASM session pool is closed")
                try:
                    return self._idle.get_nowait()
                except queue.Empty:
                    pass
                if self._session_count < self.max_sessions:
                    self._session_count += 1
                    reserve = True
                else:
                    reserve = False
                if reserve:
                    break
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise _AsmSessionError("ASM session lease timed out")
                self._condition.wait(timeout=min(0.05, remaining))
        try:
            return self._new_session()
        except BaseException:
            with self._condition:
                self._session_count -= 1
                self._condition.notify()
            raise

    def run(
        self,
        protocol_input: Path,
        response_reader: Callable[[Any], _ParsedHelperOutput],
        timeout_seconds: float,
    ) -> tuple[_ParsedHelperOutput, str]:
        deadline = time.perf_counter() + float(timeout_seconds)
        session = self._acquire(deadline)
        reusable = False
        try:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise _AsmSessionError("ASM session deadline elapsed")
            result = session.exchange(
                protocol_input, response_reader, remaining
            )
            reusable = session.alive
            return result
        finally:
            with self._condition:
                if reusable and not self._closed:
                    self._idle.put(session)
                else:
                    session.close(terminate=True)
                    self._session_count -= 1
                self._condition.notify()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            sessions = []
            while True:
                try:
                    sessions.append(self._idle.get_nowait())
                except queue.Empty:
                    break
            self._session_count -= len(sessions)
            self._condition.notify_all()
        # Every retained session is idle only after its response footer,
        # count, input digest and output digest have been validated. Closing
        # stdin is the helper protocol's explicit EOF boundary and lets the JVM
        # exit without the comparatively expensive process-tree discovery used
        # by the exceptional termination path. ``_AsmSession.close`` retains a
        # bounded timeout and force-terminates a helper that does not honour
        # EOF, so cleanup can neither leak nor weaken fail-closed behaviour.
        # Close the independent sessions concurrently and preserve the first
        # cleanup failure.
        failures: list[BaseException] = []
        failure_lock = threading.Lock()

        def close_session(session: _AsmSession) -> None:
            try:
                session.close(terminate=False)
            except BaseException as error:
                with failure_lock:
                    failures.append(error)

        threads = [
            threading.Thread(
                target=close_session,
                args=(session,),
                name="binary-asm-session-close",
                daemon=True,
            )
            for session in sessions
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        finalize_parallel_process_tree_cleanup()
        if failures:
            raise failures[0]


_ASM_SESSION_POOLS: dict[tuple[Any, ...], _AsmSessionPool] = {}
_ASM_SESSION_POOLS_LOCK = threading.Lock()


def _persistent_pool_key(
    compiled_helper: _CompiledAsmHelper,
    asm_path: Path,
    identity: str,
    helper_sha: str,
    max_heap_megabytes: int,
    max_sessions: int,
) -> tuple[Any, ...]:
    asm_status = asm_path.stat()
    return (
        str(compiled_helper.output),
        str(compiled_helper.java),
        str(asm_path),
        int(asm_status.st_size),
        int(asm_status.st_mtime_ns),
        identity,
        helper_sha,
        int(max_heap_megabytes),
        int(max_sessions),
    )


def _run_persistent_helper(
    protocol_input: Path,
    *,
    compiled_helper: _CompiledAsmHelper,
    asm_path: Path,
    identity: str,
    helper_sha: str,
    max_heap_megabytes: int,
    max_sessions: int,
    timeout_seconds: float,
    response_reader: Callable[[Any], _ParsedHelperOutput],
) -> tuple[_ParsedHelperOutput, str] | None:
    """Return ``None`` when reusable transport needs exact one-shot fallback."""

    try:
        key = _persistent_pool_key(
            compiled_helper,
            asm_path,
            identity,
            helper_sha,
            max_heap_megabytes,
            max_sessions,
        )
        with _ASM_SESSION_POOLS_LOCK:
            pool = _ASM_SESSION_POOLS.get(key)
            if pool is None:
                pool = _AsmSessionPool(
                    compiled_helper,
                    asm_path,
                    identity,
                    helper_sha,
                    max_heap_megabytes,
                    max_sessions,
                )
                _ASM_SESSION_POOLS[key] = pool
        return pool.run(protocol_input, response_reader, timeout_seconds)
    except (
        _AsmSessionError,
        BinaryAsmError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ):
        return None


def close_persistent_asm_sessions() -> None:
    with _ASM_SESSION_POOLS_LOCK:
        pools = list(_ASM_SESSION_POOLS.values())
        _ASM_SESSION_POOLS.clear()
    for pool in pools:
        pool.close()


def _forget_persistent_asm_sessions_after_fork() -> None:
    # Child processes must never use or close protocol pipes owned by the
    # parent. The inherited descriptors disappear with the child process.
    global _ASM_SESSION_POOLS, _ASM_SESSION_POOLS_LOCK
    _ASM_SESSION_POOLS = {}
    _ASM_SESSION_POOLS_LOCK = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_forget_persistent_asm_sessions_after_fork)
atexit.register(close_persistent_asm_sessions)


def _run_one_shot_helper(
    protocol_input: Path,
    stderr_path: Path,
    *,
    compiled_helper: _CompiledAsmHelper,
    asm_path: Path,
    identity: str,
    helper_sha: str,
    max_heap_megabytes: int,
    timeout_seconds: float,
    response_reader: Callable[[Any], _ParsedHelperOutput],
) -> tuple[_ParsedHelperOutput, str]:
    """Execute the original isolated JVM transport with exact cleanup."""

    with protocol_input.open("rb") as stdin, stderr_path.open("wb") as stderr:
        process = managed_popen(
            [
                compiled_helper.java,
                f"-Xmx{int(max_heap_megabytes)}m",
                "-cp",
                os.pathsep.join(
                    (str(compiled_helper.output), str(asm_path))
                ),
                "BinaryFactExtractor",
                identity,
                helper_sha,
                str(MAX_SUPPORTED_CLASS_MAJOR),
            ],
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=stderr,
        )
        timed_out = threading.Event()
        lifecycle_lock = threading.Lock()
        helper_completed = False

        def terminate_on_deadline():
            nonlocal helper_completed
            with lifecycle_lock:
                try:
                    process_running = process.poll() is None
                except (AttributeError, OSError):
                    process_running = False
                if helper_completed or not process_running:
                    return
                timed_out.set()
            try:
                terminate_process_tree(process)
            except BaseException:
                pass

        deadline = threading.Timer(timeout_seconds, terminate_on_deadline)
        timer_started = False
        try:
            deadline.daemon = True
            deadline.start()
            timer_started = True
            assert process.stdout is not None
            parsed = response_reader(process.stdout)
            returncode = process.wait()
            with lifecycle_lock:
                helper_completed = True
                exceeded_deadline = timed_out.is_set()
            if exceeded_deadline:
                raise TimeoutError("ASM helper deadline elapsed")
        except BaseException as error:
            if not timed_out.is_set():
                try:
                    terminate_process_tree(process)
                except BaseException:
                    pass
            if timed_out.is_set():
                raise BinaryAsmError(
                    "ASM_HELPER_TIMEOUT",
                    f"ASM helper exceeded {timeout_seconds}s",
                ) from error
            raise
        finally:
            with lifecycle_lock:
                helper_completed = True
            try:
                deadline.cancel()
            except BaseException:
                pass
            if timer_started:
                try:
                    deadline.join()
                except BaseException:
                    pass
            if process.stdout is not None:
                try:
                    process.stdout.close()
                except OSError:
                    pass
            release_process_tree(process)

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    if returncode != 0:
        raise BinaryAsmError(
            "ASM_HELPER_FAILED",
            f"helper exit={returncode}: {stderr_text[-4000:]}",
        )
    return parsed, stderr_text


def extract_class_facts(
    inputs: Iterable[BinaryClassInput],
    *,
    asm_jar: str | Path | None = None,
    jdk_home: str | Path | None = None,
    max_class_bytes: int = DEFAULT_MAX_CLASS_BYTES,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_heap_megabytes: int = DEFAULT_MAX_HEAP_MEGABYTES,
    record_consumer: Callable[[dict[str, Any]], None] | None = None,
    retain_records: bool = True,
    persistent_session: bool = False,
    persistent_max_sessions: int = DEFAULT_MAX_PERSISTENT_SESSIONS,
    parser_identity_binding: ParserIdentityBinding | None = None,
) -> BinaryFactRun:
    """Extract facts and validate every protocol/count/digest boundary.

    ``record_consumer`` allows a SQLite writer to consume records incrementally;
    ``retain_records=False`` prevents a second in-memory copy. Persistent mode
    reuses only the JVM transport; it invokes the same parser and conservation
    checks, and falls back to the one-shot helper after a transport failure.
    """
    if not 16 <= int(max_heap_megabytes) <= DEFAULT_MAX_HEAP_MEGABYTES:
        raise BinaryAsmError(
            "ASM_HELPER_HEAP_LIMIT_INVALID",
            f"heap must be within 16..{DEFAULT_MAX_HEAP_MEGABYTES} MiB",
        )
    if float(timeout_seconds) <= 0:
        raise BinaryAsmError(
            "ASM_HELPER_TIMEOUT_INVALID", "timeout must be positive"
        )
    if (
        isinstance(persistent_max_sessions, bool)
        or not isinstance(persistent_max_sessions, int)
        or not 1 <= persistent_max_sessions <= MAX_PERSISTENT_SESSIONS
    ):
        raise BinaryAsmError(
            "ASM_SESSION_COUNT_INVALID",
            f"session count must be within 1..{MAX_PERSISTENT_SESSIONS}",
        )
    if parser_identity_binding is None:
        asm_path = resolve_asm_jar(asm_jar)
        identity, helper_sha = parser_identity(asm_jar=asm_path)
    else:
        asm_path, identity, helper_sha = parser_identity_from_binding(
            parser_identity_binding, asm_jar=asm_jar
        )
    if jdk_home:
        javac = jdk_tool_path(jdk_home, "javac").resolve()
        java = jdk_tool_path(jdk_home, "java").resolve()
    else:
        javac_value = shutil.which("javac")
        java_value = shutil.which("java")
        javac = Path(javac_value).resolve() if javac_value else None
        java = Path(java_value).resolve() if java_value else None
    installed = _INSTALLED_COMPILED_ASM_HELPER
    if (
        installed is not None
        and installed[0].asm_path == asm_path
        and installed[0].helper_sha256 == helper_sha
        and installed[0].javac_path == str(javac or "")
        and installed[0].java_path == str(java or "")
    ):
        compiled_helper = installed[1]
    elif jdk_home:
        compiled_helper = _compile_helper(
            str(asm_path), helper_sha, str(javac), str(java)
        )
    else:
        compiled_helper = _compile_helper(str(asm_path), helper_sha)
    input_digest = hashlib.sha256()
    expected: dict[tuple[str, str], str] = {}
    input_count = 0

    with short_temporary_directory(prefix="binary-asm-protocol") as temp_text:
        temp = Path(temp_text)
        class_frames = temp / "class-input.frames"
        with class_frames.open("wb") as handle:
            for item in inputs:
                if not isinstance(item, BinaryClassInput):
                    raise BinaryAsmError(
                        "ASM_INPUT_TYPE_INVALID", "inputs must contain BinaryClassInput values"
                    )
                input_count += 1
                if input_count > max_records:
                    raise BinaryAsmError(
                        "ASM_INPUT_RECORD_LIMIT_EXCEEDED", f"class count exceeds {max_records}"
                    )
                if len(item.class_bytes) > max_class_bytes:
                    raise BinaryAsmError(
                        "ASM_CLASS_SIZE_LIMIT_EXCEEDED",
                        f"{item.class_entry} has {len(item.class_bytes)} bytes; maximum is {max_class_bytes}",
                    )
                key = (item.artifact_instance_identity, item.class_entry)
                if key in expected:
                    raise BinaryAsmError(
                        "ASM_INPUT_CLASS_DUPLICATE", f"duplicate artifact/class input {key}"
                    )
                expected[key] = _sha256_bytes(item.class_bytes)
                payload = _canonical_json({
                    "frame_type": "class_input",
                    "artifact_instance_identity_b64": base64.b64encode(
                        item.artifact_instance_identity.encode("utf-8")
                    ).decode("ascii"),
                    "class_entry_b64": base64.b64encode(
                        item.class_entry.encode("utf-8")
                    ).decode("ascii"),
                    "class_bytes_b64": base64.b64encode(item.class_bytes).decode("ascii"),
                })
                if len(payload) > max_frame_bytes:
                    raise BinaryAsmError(
                        "ASM_INPUT_FRAME_LIMIT_EXCEEDED", f"encoded frame exceeds {max_frame_bytes}"
                    )
                _write_frame(handle, payload)
                _framed_digest_update(input_digest, payload)

        protocol_input = temp / "protocol-input.frames"
        class_input_digest = input_digest.hexdigest()
        with protocol_input.open("wb") as output:
            _write_frame(output, _canonical_json({
                "frame_type": "input_header",
                "protocol_schema": PROTOCOL_SCHEMA,
                "parser_identity": identity,
                "class_input_count": str(input_count),
                "class_input_digest": class_input_digest,
            }))
            with class_frames.open("rb") as source:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            _write_frame(output, _canonical_json({"frame_type": "input_footer"}))

        stderr_path = temp / "helper.stderr"

        def read_response(stdout, *, require_eof: bool):
            return _read_helper_output(
                stdout,
                identity=identity,
                helper_sha=helper_sha,
                expected=expected,
                max_frame_bytes=max_frame_bytes,
                max_records=max_records,
                record_consumer=record_consumer,
                retain_records=retain_records,
                require_eof=require_eof,
            )

        helper_started = time.perf_counter()
        transport_result = None
        # A streaming consumer may have externally committed a prefix before a
        # broken session is detected, so it retains the original one-shot path.
        # Pipeline snapshot construction has no consumer and can retry safely.
        if persistent_session and record_consumer is None:
            transport_result = _run_persistent_helper(
                protocol_input,
                compiled_helper=compiled_helper,
                asm_path=asm_path,
                identity=identity,
                helper_sha=helper_sha,
                max_heap_megabytes=max_heap_megabytes,
                max_sessions=persistent_max_sessions,
                timeout_seconds=timeout_seconds,
                response_reader=lambda stdout: read_response(
                    stdout, require_eof=False
                ),
            )
        if transport_result is None:
            remaining_seconds = (
                float(timeout_seconds)
                - (time.perf_counter() - helper_started)
            )
            if remaining_seconds <= 0:
                raise BinaryAsmError(
                    "ASM_HELPER_TIMEOUT",
                    f"ASM helper exceeded {timeout_seconds}s",
                )
            transport_result = _run_one_shot_helper(
                protocol_input,
                stderr_path,
                compiled_helper=compiled_helper,
                asm_path=asm_path,
                identity=identity,
                helper_sha=helper_sha,
                max_heap_megabytes=max_heap_megabytes,
                timeout_seconds=remaining_seconds,
                response_reader=lambda stdout: read_response(
                    stdout, require_eof=True
                ),
            )
        parsed, stderr_text = transport_result
        expected_footer = {
            "input_record_count": input_count,
            "fact_record_count": parsed.fact_count,
            "failure_record_count": parsed.failure_count,
            "output_record_count": parsed.output_count,
            "class_input_digest": class_input_digest,
            "fact_output_digest": parsed.fact_output_digest,
            "coverage_status": (
                "complete" if parsed.failure_count == 0 else "partial"
            ),
        }
        mismatches = {
            key: (parsed.footer.get(key), value)
            for key, value in expected_footer.items()
            if parsed.footer.get(key) != value
        }
        if mismatches:
            raise BinaryAsmError(
                "ASM_PROTOCOL_FOOTER_CONSERVATION_FAILED", f"footer mismatches: {mismatches}"
            )
        if set(expected) != parsed.returned_keys:
            raise BinaryAsmError(
                "ASM_PROTOCOL_INPUT_OUTPUT_SET_MISMATCH", "not every input has exactly one output"
            )
        return BinaryFactRun(
            parser_identity=identity,
            helper_sha256=helper_sha,
            asm_jar_sha256=ASM_SHA256,
            records=parsed.records,
            input_record_count=input_count,
            fact_record_count=parsed.fact_count,
            failure_record_count=parsed.failure_count,
            class_input_digest=class_input_digest,
            fact_output_digest=parsed.fact_output_digest,
            coverage_status=expected_footer["coverage_status"],
            stderr=stderr_text,
        )


__all__ = [
    "ASM_SHA256",
    "ASM_VERSION",
    "BinaryAsmError",
    "BinaryClassInput",
    "BinaryFactRun",
    "CompiledAsmHelperBinding",
    "ParserIdentityBinding",
    "MAX_SUPPORTED_CLASS_MAJOR",
    "capture_parser_identity_binding",
    "capture_compiled_asm_helper_binding",
    "close_persistent_asm_sessions",
    "compiled_asm_helper_binding_from_mapping",
    "extract_class_facts",
    "parser_identity",
    "parser_identity_from_binding",
    "resolve_asm_jar",
    "install_compiled_asm_helper_binding",
    "verify_compiled_asm_helper_binding",
    "verify_parser_identity_binding",
]
