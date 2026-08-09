#!/usr/bin/env python3
"""Run isolated, non-initializing class definition checks on the target JVM."""

from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
from typing import Any, Mapping

from binary_asm_helper import _canonical_json, _read_frame, _write_frame
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_platform_image import JdkPlatformImage
from path_runtime import make_short_temp_dir, short_temporary_directory


JAVA_HELPER = Path(__file__).resolve().parent / "java" / "ClassDefinitionVerifier.java"
SCHEMA = "target-jvm-definition-v1"


class ClassDefinitionVerifierError(BinaryFirstContractError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@lru_cache(maxsize=8)
def _compile_helper(javac_text: str, source_sha256: str) -> Path:
    output = make_short_temp_dir(prefix="definition-verifier")
    completed = subprocess.run(
        [
            javac_text,
            "-encoding", "UTF-8",
            "-source", "8",
            "-target", "8",
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
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_HELPER_COMPILE_FAILED",
            (completed.stderr or completed.stdout or "javac failed").strip(),
        )
    if not (output / "ClassDefinitionVerifier.class").is_file():
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_HELPER_COMPILE_INCOMPLETE", "helper class missing"
        )
    return output


def verifier_identity(platform: JdkPlatformImage) -> str:
    return canonical_identity(
        "class_definition_verifier_identity",
        {
            "schema": SCHEMA,
            "helper_sha256": _sha256_file(JAVA_HELPER),
            "runtime_platform_image_identity": platform.identity,
            "target_java_launcher_sha256": _sha256_file(platform.java_executable),
            "verification_flags": ["-Xverify:all", "initialize=false", "reflection-member-linkage"],
        },
        schema_version="1",
    )


def verify_class_definitions(
    platform: JdkPlatformImage,
    selected_class_bytes: Mapping[str, bytes],
    *,
    timeout_seconds: int = 300,
) -> dict[str, dict[str, Any]]:
    source_sha = _sha256_file(JAVA_HELPER)
    javac = platform.jdk_home / "bin" / "javac"
    if not javac.is_file():
        raise ClassDefinitionVerifierError(
            "TARGET_JAVAC_MISSING", "a full target JDK is required to compile the verifier"
        )
    helper_dir = _compile_helper(str(javac), source_sha)
    names = sorted(selected_class_bytes)
    if len(names) != len(set(names)):
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_INPUT_DUPLICATE", "class names must be unique"
        )
    with short_temporary_directory(prefix="definition-input") as temp_text:
        root = Path(temp_text)
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not name or "." in name:
                raise ClassDefinitionVerifierError(
                    "CLASS_DEFINITION_NAME_INVALID", name
                )
            destination = root.joinpath(*path.parts).with_suffix(".class")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(bytes(selected_class_bytes[name]))
        protocol = io.BytesIO()
        _write_frame(protocol, _canonical_json({
            "frame_type": "definition_input_header",
            "class_count": str(len(names)),
        }))
        for name in names:
            _write_frame(protocol, _canonical_json({
                "frame_type": "class_name",
                "class_name_b64": base64.b64encode(name.encode("utf-8")).decode("ascii"),
            }))
        _write_frame(protocol, _canonical_json({"frame_type": "definition_input_footer"}))
        try:
            completed = subprocess.run(
                [
                    str(platform.java_executable),
                    "-Xverify:all",
                    "-cp", str(helper_dir),
                    "ClassDefinitionVerifier",
                    str(root),
                ],
                input=protocol.getvalue(),
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ClassDefinitionVerifierError(
                "CLASS_DEFINITION_VERIFIER_TIMEOUT",
                f"target JVM verifier exceeded {timeout_seconds}s",
            ) from error
    if completed.returncode != 0:
        raise ClassDefinitionVerifierError(
            "CLASS_DEFINITION_VERIFIER_FAILED",
            f"exit={completed.returncode}: {completed.stderr.decode('utf-8', errors='replace')[-4000:]}",
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
        actual_sha = hashlib.sha256(selected_class_bytes[name]).hexdigest()
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
