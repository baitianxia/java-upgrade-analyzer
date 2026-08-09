#!/usr/bin/env python3
"""Pinned ASM helper launcher and fail-closed framed protocol validator."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import threading
from typing import Any, Callable, Iterable

from binary_first_contract import BinaryFirstContractError, canonical_identity
from path_runtime import make_short_temp_dir, short_temporary_directory


ASM_VERSION = "9.9.1"
ASM_SHA256 = "6f3828a215c920059a5efa2fb55c233d6c54ec5cadca99ce1b1bdd10077c7ddd"
MAX_SUPPORTED_CLASS_MAJOR = 70  # Java 26, the maximum declared by ASM 9.9.1.
PROTOCOL_SCHEMA = "binary-fact-frame-v1"
OUTPUT_SCHEMA = "binary-class-fact-v1"
VISITOR_POLICY_VERSION = "asm-lossless-facts-v1"
JAVA_HELPER = Path(__file__).resolve().parent / "java" / "BinaryFactExtractor.java"
SUPPORT_MANIFEST = Path(__file__).resolve().parent / "binary_first_support_manifest.json"

DEFAULT_MAX_CLASS_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FRAME_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100_000
DEFAULT_TIMEOUT_SECONDS = 300


class BinaryAsmError(BinaryFirstContractError):
    pass


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


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def parser_identity(*, asm_jar: Path | None = None) -> tuple[str, str]:
    asm_jar = resolve_asm_jar(asm_jar)
    helper_sha = _sha256_file(JAVA_HELPER)
    support_sha = _sha256_file(SUPPORT_MANIFEST)
    identity = canonical_identity(
        "binary_asm_parser_identity",
        {
            "protocol_schema": PROTOCOL_SCHEMA,
            "output_schema": OUTPUT_SCHEMA,
            "asm_version": ASM_VERSION,
            "asm_jar_sha256": ASM_SHA256,
            "helper_sha256": helper_sha,
            "visitor_policy_version": VISITOR_POLICY_VERSION,
            "max_supported_class_major": MAX_SUPPORTED_CLASS_MAJOR,
            "support_manifest_sha256": support_sha,
        },
        schema_version="1",
    )
    return identity, helper_sha


@lru_cache(maxsize=4)
def _compile_helper(asm_jar_text: str, helper_sha: str) -> tuple[Path, str]:
    javac = shutil.which("javac")
    java = shutil.which("java")
    if not javac or not java:
        raise BinaryAsmError(
            "ASM_JAVA_TOOLCHAIN_MISSING", "both java and javac are required for the ASM helper"
        )
    output = make_short_temp_dir(prefix="binary-asm-helper")
    completed = subprocess.run(
        [
            javac,
            "-encoding", "UTF-8",
            "-cp", asm_jar_text,
            "-d", str(output),
            str(JAVA_HELPER),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise BinaryAsmError(
            "ASM_HELPER_COMPILE_FAILED",
            (completed.stderr or completed.stdout or "javac failed").strip(),
        )
    class_file = output / "BinaryFactExtractor.class"
    if not class_file.is_file():
        raise BinaryAsmError("ASM_HELPER_COMPILE_INCOMPLETE", "main helper class is missing")
    return output, java


def _validate_class_record(
    record: dict[str, Any],
    expected: dict[tuple[str, str], str],
) -> None:
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
        return
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


def extract_class_facts(
    inputs: Iterable[BinaryClassInput],
    *,
    asm_jar: str | Path | None = None,
    max_class_bytes: int = DEFAULT_MAX_CLASS_BYTES,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    record_consumer: Callable[[dict[str, Any]], None] | None = None,
    retain_records: bool = True,
) -> BinaryFactRun:
    """Extract facts and validate every protocol/count/digest boundary.

    ``record_consumer`` allows a SQLite writer to consume records incrementally;
    ``retain_records=False`` prevents a second in-memory copy.
    """
    asm_path = resolve_asm_jar(asm_jar)
    identity, helper_sha = parser_identity(asm_jar=asm_path)
    class_dir, java = _compile_helper(str(asm_path), helper_sha)
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
        retained = []
        fact_count = 0
        failure_count = 0
        output_count = 0
        returned_keys: set[tuple[str, str]] = set()
        record_digest = hashlib.sha256()
        footer = None
        with protocol_input.open("rb") as stdin, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [
                    java,
                    "-Xmx512m",
                    "-cp", os.pathsep.join((str(class_dir), str(asm_path))),
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

            def terminate_on_deadline():
                timed_out.set()
                process.kill()

            deadline = threading.Timer(timeout_seconds, terminate_on_deadline)
            deadline.daemon = True
            deadline.start()
            assert process.stdout is not None
            try:
                header_bytes, present = _read_frame(process.stdout, max_frame_bytes=max_frame_bytes)
                if not present:
                    raise BinaryAsmError("ASM_PROTOCOL_HEADER_MISSING", "helper emitted no output")
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
                    raw, present = _read_frame(process.stdout, max_frame_bytes=max_frame_bytes)
                    if not present:
                        raise BinaryAsmError(
                            "ASM_PROTOCOL_FOOTER_MISSING", "helper ended without output footer"
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
                            "ASM_OUTPUT_RECORD_LIMIT_EXCEEDED", f"output exceeds {max_records}"
                        )
                    _framed_digest_update(record_digest, raw)
                    _validate_class_record(record, expected)
                    record_key = (
                        str(record.get("artifact_instance_identity") or ""),
                        str(record.get("class_entry") or ""),
                    )
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
                stray = process.stdout.read(1)
                if stray:
                    raise BinaryAsmError(
                        "ASM_PROTOCOL_STRAY_BYTES", "stdout contains bytes after output footer"
                    )
                returncode = process.wait()
            except BaseException as error:
                process.kill()
                process.wait()
                if timed_out.is_set():
                    raise BinaryAsmError(
                        "ASM_HELPER_TIMEOUT", f"ASM helper exceeded {timeout_seconds}s"
                    ) from error
                raise
            finally:
                deadline.cancel()
                process.stdout.close()

        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        if returncode != 0:
            raise BinaryAsmError(
                "ASM_HELPER_FAILED",
                f"helper exit={returncode}: {stderr_text[-4000:]}",
            )
        assert footer is not None
        expected_footer = {
            "input_record_count": input_count,
            "fact_record_count": fact_count,
            "failure_record_count": failure_count,
            "output_record_count": output_count,
            "class_input_digest": class_input_digest,
            "fact_output_digest": record_digest.hexdigest(),
            "coverage_status": "complete" if failure_count == 0 else "partial",
        }
        mismatches = {
            key: (footer.get(key), value)
            for key, value in expected_footer.items()
            if footer.get(key) != value
        }
        if mismatches:
            raise BinaryAsmError(
                "ASM_PROTOCOL_FOOTER_CONSERVATION_FAILED", f"footer mismatches: {mismatches}"
            )
        if set(expected) != returned_keys:
            raise BinaryAsmError(
                "ASM_PROTOCOL_INPUT_OUTPUT_SET_MISMATCH", "not every input has exactly one output"
            )
        return BinaryFactRun(
            parser_identity=identity,
            helper_sha256=helper_sha,
            asm_jar_sha256=ASM_SHA256,
            records=tuple(retained),
            input_record_count=input_count,
            fact_record_count=fact_count,
            failure_record_count=failure_count,
            class_input_digest=class_input_digest,
            fact_output_digest=record_digest.hexdigest(),
            coverage_status=expected_footer["coverage_status"],
            stderr=stderr_text,
        )


__all__ = [
    "ASM_SHA256",
    "ASM_VERSION",
    "BinaryAsmError",
    "BinaryClassInput",
    "BinaryFactRun",
    "MAX_SUPPORTED_CLASS_MAJOR",
    "extract_class_facts",
    "parser_identity",
    "resolve_asm_jar",
]
