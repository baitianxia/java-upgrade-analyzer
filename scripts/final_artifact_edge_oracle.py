#!/usr/bin/env python3
"""Independently enumerate executable JVM edges from a packaged artifact."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from threading import Event, Lock
import time
import zipfile

from edge_truth import EdgeIdentity, canonical_edge_identity


INVOKE_OPCODES = {"invokevirtual", "invokeinterface", "invokestatic", "invokespecial", "invokedynamic"}
FIELD_OPCODES = {"getfield", "putfield", "getstatic", "putstatic"}
EDGE_OPCODES = INVOKE_OPCODES | FIELD_OPCODES
NESTED_JAR_PREFIXES = ("BOOT-INF/lib/", "WEB-INF/lib/")
VERSIONED_CLASS_RE = re.compile(r"^META-INF/versions/(?P<version>\d+)/(?P<logical>.+)$")
CLASS_DECLARATION_RE = re.compile(
    r"^\s*(?:[\w$]+\s+)*(?:class|interface|enum|record)\s+([\w.$]+)"
)
HEADER_LINE_RE = re.compile(r"^ {2}(?! )(?P<header>.+);\s*$")
INSTRUCTION_RE = re.compile(r"^\s*(\d+):\s+([a-z][a-z0-9_]*)\b(.*)$")
METHOD_COMMENT_RE = re.compile(
    r"^(?:InterfaceMethod|Method)\s+(?:(?P<owner>[\w/$]+)\.)?\"?(?P<member>[^\":]+)\"?:(?P<descriptor>\(.*)$"
)
FIELD_COMMENT_RE = re.compile(
    r"^Field\s+(?:(?P<owner>[\w/$]+)\.)?(?P<member>[^:]+):(?P<descriptor>.+)$"
)
CONSTANT_POOL_DYNAMIC_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+InvokeDynamic\s+#(?P<bootstrap>\d+):#\d+\s+"
    r"//\s+#\d+:(?P<member>[^:]+):(?P<descriptor>\(.*)$"
)
DYNAMIC_COMMENT_RE = re.compile(
    r"^InvokeDynamic\s+#(?P<bootstrap>\d+):(?P<member>[^:]+):(?P<descriptor>\(.*)$"
)
BOOTSTRAP_REFERENCE_RE = re.compile(
    r"^\s*(?P<index>\d+):\s+#\d+\s+REF_\w+\s+(?P<owner>[\w/$]+)\."
    r"\"?(?P<member>[^\":]+)\"?:(?P<descriptor>\(.*)$"
)
PROCEDURE = "javap -v -c -p -s <extracted-class-file>; enumerate executable final-artifact edges"
ORACLE_PROCEDURE_VERSION = "java-upgrade-analyzer.final-artifact-javap.v2"
MAX_JAVAP_WORKERS = 8
JAVAP_VERSION_TIMEOUT_SECONDS = 5.0
_IMMUTABLE_ORACLE_CACHE: dict[tuple[str, str, str, str], str] = {}
_IMMUTABLE_ORACLE_CACHE_LOCK = Lock()


@dataclass(frozen=True)
class PackagedClass:
    artifact_entry: str
    extracted_path: Path


def clear_immutable_oracle_cache() -> None:
    """Reset process-local immutable oracle results for isolated tests."""
    with _IMMUTABLE_ORACLE_CACHE_LOCK:
        _IMMUTABLE_ORACLE_CACHE.clear()


def _oracle_cache_key(artifact_sha256: str, jdk_version: str) -> tuple[str, str, str, str]:
    return artifact_sha256, ORACLE_PROCEDURE_VERSION, PROCEDURE, jdk_version


def _is_runtime_class(entry: str) -> bool:
    return entry.endswith(".class") and not entry.startswith("META-INF/") and not entry.endswith("module-info.class")


def _is_nested_jar(entry: str) -> bool:
    return entry.endswith(".jar") and entry.startswith(NESTED_JAR_PREFIXES)


def _logical_class_entry(info: zipfile.ZipInfo) -> tuple[str, int] | None:
    versioned_match = VERSIONED_CLASS_RE.match(info.filename)
    if versioned_match:
        logical = versioned_match.group("logical")
        if not _is_runtime_class(logical):
            return None
        return logical, int(versioned_match.group("version"))
    if _is_runtime_class(info.filename):
        return info.filename, 0
    return None


def _select_effective_classes(
    infos: list[zipfile.ZipInfo], target_major: int | None, scope: str, multi_release: bool
) -> tuple[list[zipfile.ZipInfo], list[str]]:
    grouped: dict[str, dict[int, list[zipfile.ZipInfo]]] = {}
    for info in infos:
        logical = _logical_class_entry(info)
        if logical is None:
            continue
        logical_name, version = logical
        grouped.setdefault(logical_name, {}).setdefault(version, []).append(info)

    selected: list[zipfile.ZipInfo] = []
    failures: list[str] = []
    for logical_name in sorted(grouped):
        candidates = grouped[logical_name]
        eligible_versions = [
            version for version in candidates
            if version == 0 or (multi_release and target_major is not None and version <= target_major)
        ]
        if multi_release and target_major is None and any(version > 0 for version in candidates):
            failures.append(f"{scope}!/{logical_name}: cannot resolve versioned class without javap major version")
            continue
        if not eligible_versions:
            continue
        selected_version = max(eligible_versions)
        duplicate_versions = [
            version for version, entries in candidates.items()
            if version == selected_version and len(entries) != 1
        ]
        if duplicate_versions:
            versions = ",".join(str(version) for version in sorted(duplicate_versions))
            failures.append(f"{scope}!/{logical_name}: duplicate logical class entry for version(s) {versions}")
            continue
        selected.append(candidates[selected_version][0])
    return selected, failures


def _is_multi_release_archive(archive: zipfile.ZipFile) -> bool:
    for info in archive.infolist():
        if info.is_dir() or info.filename.lower() != "meta-inf/manifest.mf":
            continue
        try:
            manifest = archive.read(info).decode("utf-8", errors="replace")
        except (OSError, zipfile.BadZipFile):
            return False
        attributes: dict[str, str] = {}
        current_key: str | None = None
        for line in manifest.splitlines():
            if not line:
                break
            if line.startswith(" "):
                if current_key is not None:
                    attributes[current_key] += line[1:]
                continue
            key, separator, value = line.partition(":")
            if not separator:
                current_key = None
                continue
            current_key = key.strip().lower()
            attributes[current_key] = value.strip()
        return attributes.get("multi-release", "").strip().lower() == "true"
    return False


def _write_extracted_class(destination: Path, index: int, content: bytes) -> Path:
    class_path = destination / f"class-{index:06d}.class"
    class_path.write_bytes(content)
    return class_path


def _extract_packaged_classes(
    snapshot: bytes, destination: Path, target_major: int | None
) -> tuple[list[PackagedClass], list[str]]:
    entries: list[PackagedClass] = []
    failures: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(snapshot)) as outer:
            direct_infos, direct_failures = _select_effective_classes(
                outer.infolist(), target_major, "final-artifact", _is_multi_release_archive(outer)
            )
            failures.extend(direct_failures)
            for info in direct_infos:
                try:
                    path = _write_extracted_class(destination, len(entries), outer.read(info))
                    entries.append(PackagedClass(info.filename, path))
                except (OSError, zipfile.BadZipFile) as error:
                    failures.append(f"{info.filename}: extract failed: {error}")

            nested_by_name: dict[str, list[zipfile.ZipInfo]] = {}
            for info in outer.infolist():
                if not info.is_dir() and _is_nested_jar(info.filename):
                    nested_by_name.setdefault(info.filename, []).append(info)
            for nested_name in sorted(nested_by_name):
                nested_infos = nested_by_name[nested_name]
                if len(nested_infos) != 1:
                    failures.append(f"{nested_name}: duplicate nested JAR entry")
                    continue
                nested_info = nested_infos[0]
                try:
                    with zipfile.ZipFile(io.BytesIO(outer.read(nested_info))) as nested:
                        class_infos, nested_failures = _select_effective_classes(
                            nested.infolist(), target_major, nested_name, _is_multi_release_archive(nested)
                        )
                        failures.extend(nested_failures)
                        for class_info in class_infos:
                            path = _write_extracted_class(destination, len(entries), nested.read(class_info))
                            entries.append(PackagedClass(f"{nested_name}!/{class_info.filename}", path))
                except (OSError, zipfile.BadZipFile) as error:
                    failures.append(f"{nested_name}: nested JAR read failed: {error}")
    except (OSError, zipfile.BadZipFile) as error:
        failures.append(f"final-artifact: artifact read failed: {error}")
    return entries, failures


def _parse_member_header(line: str, caller_owner: str) -> tuple[str | None, str | None]:
    match = HEADER_LINE_RE.match(line)
    if not match:
        return None, None
    header = match.group("header").strip()
    if header == "static {}":
        return "<clinit>", "method"
    if "(" not in header:
        return None, "field"
    if ")" not in header:
        return None, "invalid"
    before_parameters, remainder = header.split("(", 1)
    _, suffix = remainder.split(")", 1)
    if suffix and not re.fullmatch(r"\s+throws\s+.+", suffix):
        return None, "invalid"
    parts = before_parameters.split()
    if not parts:
        return None, "invalid"
    candidate = parts[-1].strip('"')
    if not re.fullmatch(r"[\w$<>.]+", candidate):
        return None, "invalid"
    if candidate in {caller_owner, caller_owner.rsplit(".", 1)[-1]}:
        return "<init>", "method"
    return candidate, "method"


def _parse_member_reference(comment: str, caller_owner: str) -> tuple[str, str, str] | None:
    match = METHOD_COMMENT_RE.match(comment)
    if not match:
        return None
    owner = (match.group("owner") or caller_owner.replace(".", "/")).replace("/", ".")
    return owner, match.group("member"), match.group("descriptor")


def _parse_field_reference(comment: str, caller_owner: str) -> tuple[str, str, str] | None:
    match = FIELD_COMMENT_RE.match(comment)
    if not match:
        return None
    owner = (match.group("owner") or caller_owner.replace(".", "/")).replace("/", ".")
    return owner, match.group("member"), match.group("descriptor")


def _bootstrap_references(output: str) -> dict[int, tuple[str, str, str]]:
    in_bootstrap_section = False
    references: dict[int, tuple[str, str, str]] = {}
    for line in output.splitlines():
        if line.strip() == "BootstrapMethods:":
            in_bootstrap_section = True
            continue
        if not in_bootstrap_section:
            continue
        match = BOOTSTRAP_REFERENCE_RE.match(line)
        if match:
            references[int(match.group("index"))] = (
                match.group("owner").replace("/", "."),
                match.group("member"),
                match.group("descriptor"),
            )
    return references


def _dynamic_references(output: str) -> dict[int, tuple[int, str, str]]:
    references: dict[int, tuple[int, str, str]] = {}
    for line in output.splitlines():
        match = CONSTANT_POOL_DYNAMIC_RE.match(line)
        if match:
            references[int(match.group("constant"))] = (
                int(match.group("bootstrap")), match.group("member"), match.group("descriptor")
            )
    return references


def _parse_dynamic_reference(
    rest: str,
    comment: str,
    dynamic_references: dict[int, tuple[int, str, str]],
    bootstrap_references: dict[int, tuple[str, str, str]],
) -> tuple[tuple[str, str, str] | None, str | None]:
    constant_match = re.search(r"#(\d+)", rest)
    comment_match = DYNAMIC_COMMENT_RE.match(comment)
    dynamic_reference = dynamic_references.get(int(constant_match.group(1))) if constant_match else None
    if dynamic_reference is None and comment_match:
        dynamic_reference = (
            int(comment_match.group("bootstrap")), comment_match.group("member"), comment_match.group("descriptor")
        )
    if dynamic_reference is None:
        return None, "unresolved invokedynamic bootstrap or constant-pool reference"
    bootstrap_index, _, _ = dynamic_reference
    callee = bootstrap_references.get(bootstrap_index)
    if callee is None:
        return None, f"unresolved invokedynamic bootstrap {bootstrap_index}"
    return callee, None


def _edge_row(
    artifact_sha256: str,
    artifact_entry: str,
    authority_version: str,
    caller_owner: str,
    caller_member: str,
    caller_descriptor: str,
    callee: tuple[str, str, str],
    opcode: str,
    instruction_offset: int,
) -> dict:
    identity = EdgeIdentity(
        artifact_sha256=artifact_sha256,
        caller_owner=caller_owner,
        caller_member=caller_member,
        caller_descriptor=caller_descriptor,
        callee_owner=callee[0],
        callee_member=callee[1],
        callee_descriptor=callee[2],
        opcode_family=opcode,
    )
    return {
        "artifact_sha256": identity.artifact_sha256,
        "artifact_entry": artifact_entry,
        "caller_owner": identity.caller_owner,
        "caller_member": identity.caller_member,
        "caller_descriptor": identity.caller_descriptor,
        "callee_owner": identity.callee_owner,
        "callee_member": identity.callee_member,
        "callee_descriptor": identity.callee_descriptor,
        "opcode_family": identity.opcode_family,
        "instruction_offset": instruction_offset,
        "authority": "jdk-javap",
        "authority_version": authority_version,
        "procedure": PROCEDURE,
    }


def _parse_javap_output(
    output: str,
    artifact_sha256: str,
    artifact_entry: str,
    authority_version: str,
) -> tuple[list[dict], list[str]]:
    caller_owner = ""
    caller_member: str | None = None
    caller_descriptor = ""
    declaration_state: str | None = None
    rows: list[dict] = []
    failures: list[str] = []
    dynamic_references = _dynamic_references(output)
    bootstrap_references = _bootstrap_references(output)

    for line in output.splitlines():
        class_match = CLASS_DECLARATION_RE.match(line)
        if class_match:
            caller_owner = class_match.group(1)
            caller_member = None
            caller_descriptor = ""
            declaration_state = None
            continue
        parsed_member, parsed_state = _parse_member_header(line, caller_owner) if caller_owner else (None, None)
        if parsed_state is not None:
            caller_member = parsed_member
            caller_descriptor = ""
            declaration_state = parsed_state
            continue
        stripped = line.strip()
        if stripped.startswith("descriptor:"):
            if declaration_state == "field":
                continue
            if declaration_state != "method" or caller_member is None:
                failures.append(f"{artifact_entry}: descriptor without a valid header")
                caller_descriptor = ""
            else:
                caller_descriptor = stripped.partition(":")[2].strip()
            continue
        if stripped == "Code:":
            if declaration_state != "method" or caller_member is None or not caller_descriptor:
                failures.append(f"{artifact_entry}: Code block without a valid header and descriptor")
            continue
        instruction_match = INSTRUCTION_RE.match(line)
        if not instruction_match:
            continue
        offset, opcode, rest = instruction_match.groups()
        if opcode not in EDGE_OPCODES:
            continue
        if not caller_owner or declaration_state != "method" or caller_member is None or not caller_descriptor:
            failures.append(f"{artifact_entry}: missing caller context for {opcode} at {offset}")
            continue
        _, separator, comment = rest.partition("//")
        if not separator:
            failures.append(f"{artifact_entry}: missing constant-pool comment for {opcode} at {offset}")
            continue
        if opcode == "invokedynamic":
            callee, dynamic_failure = _parse_dynamic_reference(
                rest, comment.strip(), dynamic_references, bootstrap_references
            )
            if dynamic_failure:
                failures.append(f"{artifact_entry}: {dynamic_failure} at {offset}")
                continue
        elif opcode in FIELD_OPCODES:
            callee = _parse_field_reference(comment.strip(), caller_owner)
        else:
            callee = _parse_member_reference(comment.strip(), caller_owner)
        if callee is None:
            failures.append(f"{artifact_entry}: unparseable {opcode} comment at {offset}: {comment.strip()}")
            continue
        rows.append(_edge_row(
            artifact_sha256,
            artifact_entry,
            authority_version,
            caller_owner,
            caller_member,
            caller_descriptor,
            callee,
            opcode,
            int(offset),
        ))
    if not caller_owner:
        failures.append(f"{artifact_entry}: javap output had no class declaration")
    return rows, failures


def _javap_version(javap: str, *, timeout: float) -> str:
    completed = subprocess.run(
        [javap, "-version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=timeout
    )
    return (completed.stdout or completed.stderr).strip()


def _javap_major(version: str) -> int | None:
    match = re.search(r"(?:1\.)?(\d+)", version)
    return int(match.group(1)) if match else None


def _cancel_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.kill()
    process.communicate()


def _parse_entry_with_javap(
    entry: PackagedClass,
    artifact_sha256: str,
    javap: str,
    version: str,
    cancellation_event: Event,
    deadline: float | None,
) -> dict:
    per_class_deadline = time.perf_counter() + 30.0
    deadline = min(deadline, per_class_deadline) if deadline is not None else per_class_deadline
    if cancellation_event.is_set() or (deadline is not None and time.perf_counter() >= deadline):
        return {"rows": [], "failures": [], "completed": False, "parsed": False}
    try:
        process = subprocess.Popen(
            [javap, "-v", "-c", "-p", "-s", str(entry.extracted_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: {javap} execution failed: {error}"],
            "completed": True,
            "parsed": False,
        }

    while True:
        remaining = deadline - time.perf_counter() if deadline is not None else None
        if cancellation_event.is_set() or (remaining is not None and remaining <= 0):
            _cancel_process(process)
            return {"rows": [], "failures": [], "completed": False, "parsed": False}
        wait_seconds = min(0.1, remaining) if remaining is not None else 0.1
        try:
            stdout, stderr = process.communicate(timeout=wait_seconds)
            break
        except subprocess.TimeoutExpired:
            continue

    if process.returncode != 0:
        detail = (stderr or stdout).strip().replace("\n", " ")
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: javap failed: {detail}"],
            "completed": True,
            "parsed": False,
        }
    if not version:
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: javap version was empty"],
            "completed": True,
            "parsed": False,
        }
    rows, failures = _parse_javap_output(stdout, artifact_sha256, entry.artifact_entry, version)
    return {"rows": rows, "failures": failures, "completed": True, "parsed": True}


def _parse_entries_with_javap(
    entries: list[PackagedClass], artifact_sha256: str, javap: str, version: str
) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    failures: list[str] = []
    cancellation_event = Event()
    for entry in entries:
        result = _parse_entry_with_javap(
            entry, artifact_sha256, javap, version, cancellation_event, None
        )
        rows.extend(result["rows"])
        failures.extend(result["failures"])
    return rows, failures


def _worker_exception_result(entry: PackagedClass, error: BaseException) -> dict:
    return {
        "rows": [],
        "failures": [
            f"{entry.artifact_entry}: oracle worker failed: {type(error).__name__}: {error}"
        ],
        "completed": True,
        "parsed": False,
    }


def _base_result(artifact_sha256: str, *, elapsed_seconds: float, **values) -> dict:
    return {
        "artifact_sha256": artifact_sha256,
        "class_count": int(values.get("class_count") or 0),
        "completed_class_count": int(values.get("completed_class_count") or 0),
        "parsed_class_count": int(values.get("parsed_class_count") or 0),
        "cached_class_count": int(values.get("cached_class_count") or 0),
        "parse_failure_count": int(values.get("parse_failure_count") or 0),
        "parse_seconds": float(values.get("parse_seconds") or 0.0),
        "elapsed_seconds": elapsed_seconds,
        "worker_count": int(values.get("worker_count") or 0),
        "cache_hits": int(values.get("cache_hits") or 0),
        "cache_misses": int(values.get("cache_misses") or 0),
        "timed_out": bool(values.get("timed_out")),
        "interrupted": bool(values.get("interrupted")),
        "edges": list(values.get("edges") or []),
        "failures": list(values.get("failures") or []),
        "complete": bool(values.get("complete")),
    }


def scan_final_artifact(
    artifact: Path,
    javap: str = "javap",
    *,
    max_workers: int | None = None,
    time_budget_seconds: float | None = None,
) -> dict:
    """Return every executable edge found in the final artifact and nested runtime JARs."""
    artifact = Path(artifact)
    started_at = time.perf_counter()
    budget = float(time_budget_seconds or 0.0)
    deadline = started_at + budget if budget > 0 else None
    try:
        snapshot = artifact.read_bytes()
    except OSError as error:
        return _base_result(
            "",
            elapsed_seconds=time.perf_counter() - started_at,
            failures=[f"{artifact}: artifact snapshot read failed: {error}"],
            complete=False,
        )
    digest = hashlib.sha256(snapshot).hexdigest()
    version_timeout = JAVAP_VERSION_TIMEOUT_SECONDS
    if deadline is not None:
        version_timeout = deadline - time.perf_counter()
        if version_timeout <= 0:
            return _base_result(
                digest,
                elapsed_seconds=time.perf_counter() - started_at,
                failures=[f"oracle_time_budget_exceeded:{budget:.3f}s"],
                timed_out=True,
                cache_misses=1,
                complete=False,
            )
        version_timeout = min(version_timeout, JAVAP_VERSION_TIMEOUT_SECONDS)
    try:
        version = _javap_version(javap, timeout=version_timeout)
    except subprocess.TimeoutExpired:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=["oracle_javap_version_timeout"],
            timed_out=True,
            cache_misses=1,
            complete=False,
        )
    except OSError as error:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=[f"oracle_javap_version_failed:OSError: {error}"],
            cache_misses=1,
            complete=False,
        )
    except KeyboardInterrupt:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=["oracle_interrupted"],
            interrupted=True,
            cache_misses=1,
            complete=False,
        )
    except Exception as error:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=[f"oracle_javap_version_failed:{type(error).__name__}: {error}"],
            cache_misses=1,
            complete=False,
        )
    cache_key = _oracle_cache_key(digest, version)
    with _IMMUTABLE_ORACLE_CACHE_LOCK:
        cached_serialized = _IMMUTABLE_ORACLE_CACHE.get(cache_key)
    if cached_serialized is not None:
        cached = json.loads(cached_serialized)
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            class_count=cached["class_count"],
            completed_class_count=cached["class_count"],
            cached_class_count=cached["class_count"],
            parse_failure_count=cached["parse_failure_count"],
            cache_hits=1,
            edges=cached["edges"],
            failures=cached["failures"],
            complete=cached["complete"],
        )
    target_major = _javap_major(version)
    cancellation_event = Event()
    timed_out = False
    interrupted = False
    parse_started_at = time.perf_counter()
    entries: list[PackagedClass] = []
    failures: list[str] = []
    results: list[dict | None] = []
    worker_count = 0
    try:
        with tempfile.TemporaryDirectory(prefix="final-artifact-edge-oracle-") as temporary_directory:
            entries, failures = _extract_packaged_classes(snapshot, Path(temporary_directory), target_major)
            if deadline is not None and time.perf_counter() >= deadline:
                timed_out = True
            if entries and not timed_out:
                requested_workers = max_workers if max_workers is not None else min(
                    MAX_JAVAP_WORKERS, max(1, os.cpu_count() or 1)
                )
                worker_count = min(
                    len(entries), MAX_JAVAP_WORKERS, max(1, int(requested_workers))
                )
                executor = ThreadPoolExecutor(
                    max_workers=worker_count, thread_name_prefix="final-artifact-javap"
                )
                futures = [
                    executor.submit(
                        _parse_entry_with_javap,
                        entry,
                        digest,
                        javap,
                        version,
                        cancellation_event,
                        deadline,
                    )
                    for entry in entries
                ]
                try:
                    for future in futures:
                        remaining = deadline - time.perf_counter() if deadline is not None else None
                        if remaining is not None and remaining <= 0:
                            timed_out = True
                            cancellation_event.set()
                            break
                        try:
                            future.result(timeout=remaining)
                        except FutureTimeoutError:
                            timed_out = True
                            cancellation_event.set()
                            break
                        except BaseException:
                            # Record this failure after all submitted classes have finished.
                            continue
                except KeyboardInterrupt:
                    interrupted = True
                    cancellation_event.set()
                finally:
                    executor.shutdown(wait=True, cancel_futures=True)
                for entry, future in zip(entries, futures):
                    if future.cancelled():
                        results.append(None)
                        continue
                    try:
                        results.append(future.result())
                    except KeyboardInterrupt:
                        interrupted = True
                        cancellation_event.set()
                        results.append(None)
                    except BaseException as error:
                        results.append(_worker_exception_result(entry, error))
                if any(result is None or not result.get("completed") for result in results):
                    if deadline is not None and time.perf_counter() >= deadline:
                        timed_out = True
                    elif not interrupted:
                        failures.append("oracle_parse_incomplete")
    except KeyboardInterrupt:
        interrupted = True
        cancellation_event.set()

    rows: list[dict] = []
    parse_failures: list[str] = []
    completed_class_count = 0
    parsed_class_count = 0
    for result in results:
        if result is None:
            continue
        rows.extend(result["rows"])
        parse_failures.extend(result["failures"])
        completed_class_count += int(bool(result.get("completed")))
        parsed_class_count += int(bool(result.get("parsed")))
    failures.extend(parse_failures)
    if timed_out:
        failures.append(f"oracle_time_budget_exceeded:{budget:.3f}s")
    if interrupted:
        failures.append("oracle_interrupted")
    rows.sort(key=lambda row: (
        canonical_edge_identity(row), row["artifact_entry"], row["instruction_offset"]
    ))
    parse_seconds = time.perf_counter() - parse_started_at
    complete = not failures and completed_class_count == len(entries)
    result = _base_result(
        digest,
        elapsed_seconds=time.perf_counter() - started_at,
        class_count=len(entries),
        completed_class_count=completed_class_count,
        parsed_class_count=parsed_class_count,
        parse_failure_count=len(parse_failures),
        parse_seconds=parse_seconds,
        worker_count=worker_count,
        cache_misses=1,
        timed_out=timed_out,
        interrupted=interrupted,
        edges=rows,
        failures=failures,
        complete=complete,
    )
    if complete and not timed_out and not interrupted and completed_class_count == len(entries):
        serialized = json.dumps(
            {
                "class_count": len(entries),
                "parse_failure_count": len(parse_failures),
                "edges": rows,
                "failures": failures,
                "complete": complete,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with _IMMUTABLE_ORACLE_CACHE_LOCK:
            _IMMUTABLE_ORACLE_CACHE.setdefault(cache_key, serialized)
    return result
