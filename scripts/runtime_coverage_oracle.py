#!/usr/bin/env python3
"""Produce artifact-bound per-API Oracle rows from an independent runtime test."""

from __future__ import annotations

import argparse
import csv
from datetime import date
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile

from csv_io import open_csv_read, open_csv_write
from path_runtime import short_temporary_directory
from signature_utils import canonical_api_identity_tuple, signatures_match_identity


SCHEMA = "java-upgrade-analyzer.runtime-coverage-oracle.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
JAVA_HELPER = Path(__file__).with_name("java") / "JacocoMethodCoverage.java"
PRIMITIVE_TYPES = {
    "B": "byte", "C": "char", "D": "double", "F": "float",
    "I": "int", "J": "long", "S": "short", "Z": "boolean",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _zip_entry_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bind_classfiles_to_artifact(artifact: Path, classfiles: Path) -> dict:
    """Require analyzed class bytes to be the artifact or one exact nested JAR."""
    artifact = Path(artifact).resolve()
    classfiles = Path(classfiles).resolve()
    artifact_sha = sha256_file(artifact)
    classfiles_sha = sha256_file(classfiles)
    if artifact_sha == classfiles_sha:
        return {
            "artifact_sha256": artifact_sha,
            "classfiles_sha256": classfiles_sha,
            "artifact_entry": "<artifact>",
        }
    try:
        with zipfile.ZipFile(artifact) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".jar"):
                    continue
                if _zip_entry_sha256(archive, info) == classfiles_sha:
                    return {
                        "artifact_sha256": artifact_sha,
                        "classfiles_sha256": classfiles_sha,
                        "artifact_entry": info.filename,
                    }
    except zipfile.BadZipFile as error:
        raise ValueError("final_artifact_not_archive") from error
    raise ValueError("classfiles_not_bound_to_final_artifact")


def _descriptor_type(descriptor: str, start: int) -> tuple[str, int]:
    dimensions = 0
    while start < len(descriptor) and descriptor[start] == "[":
        dimensions += 1
        start += 1
    if start >= len(descriptor):
        raise ValueError("invalid_jvm_descriptor")
    marker = descriptor[start]
    if marker in PRIMITIVE_TYPES:
        type_name = PRIMITIVE_TYPES[marker]
        end = start + 1
    elif marker == "L":
        terminator = descriptor.find(";", start)
        if terminator < 0:
            raise ValueError("invalid_jvm_descriptor")
        type_name = descriptor[start + 1:terminator].replace("/", ".").replace("$", ".")
        end = terminator + 1
    else:
        raise ValueError("invalid_jvm_descriptor")
    return type_name + "[]" * dimensions, end


def descriptor_signature(descriptor: str) -> str:
    value = str(descriptor or "").strip()
    if not value.startswith("(") or ")" not in value:
        raise ValueError("invalid_method_descriptor")
    end = value.index(")")
    offset = 1
    parameters = []
    while offset < end:
        type_name, offset = _descriptor_type(value, offset)
        parameters.append(type_name)
    if offset != end:
        raise ValueError("invalid_method_descriptor")
    return "(" + ",".join(parameters) + ")"


def parse_coverage_output(output: str) -> list[dict]:
    rows = []
    for line in str(output or "").splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) not in {5, 6}:
            raise ValueError("jacoco_helper_output_invalid")
        owner, member, descriptor, covered, total = fields[:5]
        ancestors = fields[5].split(";") if len(fields) == 6 and fields[5] else []
        rows.append({
            "owner": owner.replace("/", ".").replace("$", "."),
            "member": member,
            "descriptor": descriptor,
            "signature": descriptor_signature(descriptor),
            "covered_instructions": int(covered),
            "total_instructions": int(total),
            "ancestors": [
                item.replace("/", ".").replace("$", ".")
                for item in ancestors
            ],
        })
    return rows


def validate_junit_reports(paths: list[Path]) -> dict:
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    evidence = []
    for raw_path in paths:
        path = Path(raw_path)
        root = ET.parse(path).getroot()
        suites = [root] if root.tag.rsplit("}", 1)[-1] == "testsuite" else list(root)
        for suite in suites:
            for field in totals:
                totals[field] += int(suite.attrib.get(field, 0) or 0)
        evidence.append({"path": str(path.resolve()), "sha256": sha256_file(path)})
    if totals["tests"] <= 0:
        raise ValueError("runtime_test_count_zero")
    if totals["failures"] or totals["errors"]:
        raise ValueError(
            f"runtime_tests_failed:{totals['failures']}:{totals['errors']}"
        )
    return {"totals": totals, "reports": evidence}


def _api_runtime_key(row: dict) -> tuple[str, str, str] | None:
    _, api_name, signature, kind, _ = canonical_api_identity_tuple(row)
    if kind not in {"method", "constructor"} or "." not in api_name:
        return None
    owner, member = api_name.rsplit(".", 1)
    return owner, "<init>" if kind == "constructor" else member, signature


def build_runtime_oracle_rows(
    api_rows: list[dict], coverage_rows: list[dict], *, artifact_sha256: str,
    evidence_path: Path, evidence_sha256: str, authority_version: str,
) -> list[dict]:
    if not SHA256_RE.fullmatch(str(artifact_sha256 or "")):
        raise ValueError("artifact_sha256_invalid")
    records = []
    for row in api_rows:
        key = _api_runtime_key(row)
        matched = []
        if key is not None:
            owner, member, signature = key
            matched = [
                item for item in coverage_rows
                if (item.get("owner") == owner or owner in (item.get("ancestors") or []))
                and item.get("member") == member
                and signatures_match_identity(signature, item.get("signature"))
            ]
        conclusion = "reachable" if matched else "uncertain"
        records.append({
            **{
                field: str(row.get(field) or "")
                for field in (
                    "coord", "api_name", "api_signature", "symbol_kind",
                    "change_type",
                )
            },
            "oracle_conclusion": conclusion,
            "authority": "jacoco-runtime",
            "authority_version": authority_version,
            "procedure": (
                "Passed project test with JaCoCo execution probes; match exact class, "
                "method or constructor, and JVM parameter descriptor against class bytes "
                "cryptographically bound to the final artifact"
            ),
            "evidence_path": str(Path(evidence_path).resolve()),
            "evidence_sha256": evidence_sha256,
            "generated_at": date.today().isoformat(),
            "evidence_mode": "project_test",
            "artifact_sha256": artifact_sha256,
            "capabilities": "artifact_bound;executable_runtime",
            "runtime_covered_instructions": sum(
                int(item.get("covered_instructions") or 0) for item in matched
            ),
        })
    return records


def _run_command(args) -> tuple[list[str], Path, int]:
    payload = json.loads(Path(args.command_json).read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload or not all(
        isinstance(item, str) and item for item in payload
    ):
        raise ValueError("runtime_command_must_be_nonempty_string_array")
    exec_path = Path(args.jacoco_exec)
    if exec_path.exists():
        exec_path.unlink()
    started_ns = time.time_ns()
    environment = os.environ.copy()
    if args.jacoco_agent:
        agent = Path(args.jacoco_agent).resolve()
        options = f"-javaagent:{agent}=destfile={exec_path.resolve()},append=false"
        if args.agent_includes:
            options += f",includes={args.agent_includes}"
        existing = environment.get("JAVA_TOOL_OPTIONS", "").strip()
        environment["JAVA_TOOL_OPTIONS"] = " ".join(filter(None, (options, existing)))
    completed = subprocess.run(
        payload,
        cwd=Path(args.run_cwd),
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    command_log = Path(args.command_log_out)
    command_log.parent.mkdir(parents=True, exist_ok=True)
    command_log.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode:
        raise ValueError(f"runtime_test_command_failed:{completed.returncode}")
    if not exec_path.is_file() or exec_path.stat().st_mtime_ns < started_ns:
        raise ValueError("jacoco_execution_data_not_fresh")
    return payload, command_log, started_ns


def _resolve_test_reports(args, started_ns: int) -> list[Path]:
    paths = [Path(item) for item in (args.test_result or [])]
    for pattern in args.test_result_glob or []:
        paths.extend(Path(item) for item in glob.glob(pattern))
    unique = sorted({path.resolve() for path in paths if path.is_file()})
    if args.command_json:
        unique = [path for path in unique if path.stat().st_mtime_ns >= started_ns]
    if not unique:
        raise ValueError("fresh_runtime_test_report_missing")
    return unique


def read_jacoco_coverage(
    exec_path: Path, classfiles: list[Path], classpath: list[Path], *,
    javac: str = "javac", java: str = "java",
) -> list[dict]:
    if not classpath:
        raise ValueError("jacoco_reader_classpath_missing")
    for path in [Path(exec_path), *map(Path, classfiles), *map(Path, classpath)]:
        if not path.is_file():
            raise ValueError(f"runtime_oracle_input_missing:{path}")
    joined_classpath = os.pathsep.join(str(Path(item).resolve()) for item in classpath)
    with short_temporary_directory(prefix="s5-jacoco") as tmp:
        build_dir = Path(tmp)
        compile_result = subprocess.run(
            [javac, "-cp", joined_classpath, "-d", str(build_dir), str(JAVA_HELPER)],
            text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if compile_result.returncode:
            raise ValueError("jacoco_reader_compile_failed:" + compile_result.stdout[-500:])
        runtime_classpath = os.pathsep.join((str(build_dir), joined_classpath))
        read_result = subprocess.run(
            [java, "-cp", runtime_classpath, "JacocoMethodCoverage", str(exec_path),
             *(str(Path(item)) for item in classfiles)],
            text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if read_result.returncode:
            raise ValueError("jacoco_reader_failed:" + read_result.stdout[-500:])
    return parse_coverage_output(read_result.stdout)


def _write_csv(path: Path, rows: list[dict]) -> None:
    fields = (
        "coord", "api_name", "api_signature", "symbol_kind", "change_type",
        "oracle_conclusion", "authority", "authority_version", "procedure",
        "evidence_path", "evidence_sha256", "generated_at", "evidence_mode",
        "artifact_sha256", "capabilities", "runtime_covered_instructions",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_csv_write(path) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-universe", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--classfiles", required=True, action="append", type=Path)
    parser.add_argument("--jacoco-exec", required=True, type=Path)
    parser.add_argument("--jacoco-classpath", required=True, action="append", type=Path)
    parser.add_argument("--test-result", action="append", type=Path)
    parser.add_argument("--test-result-glob", action="append")
    parser.add_argument("--command-json", type=Path)
    parser.add_argument("--run-cwd", type=Path)
    parser.add_argument("--command-log-out", type=Path)
    parser.add_argument("--jacoco-agent", type=Path)
    parser.add_argument("--agent-includes", default="")
    parser.add_argument("--javac", default="javac")
    parser.add_argument("--java", default="java")
    parser.add_argument("--authority-version", default="JaCoCo")
    parser.add_argument("--evidence-out", required=True, type=Path)
    parser.add_argument("--oracle-out", required=True, type=Path)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        if bool(args.command_json) != bool(args.run_cwd and args.command_log_out):
            raise ValueError("runtime_command_requires_cwd_and_log")
        command = []
        command_log = None
        started_ns = 0
        if args.command_json:
            command, command_log, started_ns = _run_command(args)
        reports = _resolve_test_reports(args, started_ns)
        test_evidence = validate_junit_reports(reports)
        bindings = [
            bind_classfiles_to_artifact(args.artifact, item)
            for item in args.classfiles
        ]
        artifact_shas = {item["artifact_sha256"] for item in bindings}
        if len(artifact_shas) != 1:
            raise ValueError("classfiles_artifact_binding_conflict")
        coverage = read_jacoco_coverage(
            args.jacoco_exec, args.classfiles, args.jacoco_classpath,
            javac=args.javac, java=args.java,
        )
        with open_csv_read(args.api_universe) as handle:
            api_rows = list(csv.DictReader(handle))
        if not api_rows:
            raise ValueError("api_universe_empty")
        evidence = {
            "schema": SCHEMA,
            "artifact": str(args.artifact.resolve()),
            "artifact_sha256": next(iter(artifact_shas)),
            "classfile_bindings": bindings,
            "jacoco_exec": str(args.jacoco_exec.resolve()),
            "jacoco_exec_sha256": sha256_file(args.jacoco_exec),
            "test_evidence": test_evidence,
            "command": command,
            "command_log": ({
                "path": str(command_log.resolve()),
                "sha256": sha256_file(command_log),
            } if command_log else None),
            "covered_methods": coverage,
        }
        args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
        args.evidence_out.write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        evidence_sha = sha256_file(args.evidence_out)
        rows = build_runtime_oracle_rows(
            api_rows,
            coverage,
            artifact_sha256=evidence["artifact_sha256"],
            evidence_path=args.evidence_out,
            evidence_sha256=evidence_sha,
            authority_version=args.authority_version,
        )
        _write_csv(args.oracle_out, rows)
        result = {
            "schema": SCHEMA,
            "status": "passed",
            "api_count": len(rows),
            "reachable": sum(row["oracle_conclusion"] == "reachable" for row in rows),
            "uncertain": sum(row["oracle_conclusion"] == "uncertain" for row in rows),
            "artifact_sha256": evidence["artifact_sha256"],
            "oracle_out": str(args.oracle_out),
            "evidence_out": str(args.evidence_out),
        }
        returncode = 0
    except (OSError, ValueError, ET.ParseError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        result = {
            "schema": SCHEMA,
            "status": "failed",
            "error": f"{type(error).__name__}:{error}",
        }
        returncode = 2
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
