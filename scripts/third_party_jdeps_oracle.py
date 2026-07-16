#!/usr/bin/env python3
"""Independent class-reference Oracle backed by the JDK jdeps tool."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tempfile
import time
import zipfile

from signature_utils import canonical_api_identity


JDEPS_EDGE_RE = re.compile(r"^\s+(\S+)\s+->\s+(\S+)\s+(?:\S+|not found)\s*$")


def serialized_api_identity(row: dict) -> str:
    return canonical_api_identity(row)


def parse_jdeps_class_dependencies(output: str) -> list[tuple[str, str]]:
    dependencies = []
    for line in str(output or "").splitlines():
        match = JDEPS_EDGE_RE.match(line)
        if match:
            dependencies.append((match.group(1), match.group(2)))
    return dependencies


def _effective_class_entries(archive: zipfile.ZipFile, java_major: int) -> dict[str, str]:
    selected: dict[str, tuple[int, str]] = {}
    for name in archive.namelist():
        if not name.endswith(".class") or name.endswith(("module-info.class", "package-info.class")):
            continue
        logical = name
        version = 0
        match = re.match(r"META-INF/versions/(\d+)/(.*\.class)$", name)
        if match:
            version = int(match.group(1))
            logical = match.group(2)
            if version > java_major:
                continue
        prior = selected.get(logical)
        if prior is None or version > prior[0]:
            selected[logical] = (version, name)
    return {logical: physical for logical, (_version, physical) in selected.items()}


def _materialize_classes(
    archive: zipfile.ZipFile,
    destination: Path,
    java_major: int,
    *,
    prefix: str = "",
) -> int:
    count = 0
    for logical, physical in _effective_class_entries(archive, java_major).items():
        if prefix:
            if not logical.startswith(prefix):
                continue
            logical = logical[len(prefix):]
        output = destination / logical
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(archive.read(physical))
        count += 1
    return count


def scan_artifact_class_references(
    artifact: Path,
    selected_rows: list[dict],
    *,
    excluded_nested_jars: set[str] | None = None,
    application_owned_nested_jars: set[str] | None = None,
    jdeps: str = "jdeps",
    max_workers: int = 4,
    timeout_seconds: float = 60.0,
) -> dict:
    targets: dict[str, list[str]] = defaultdict(list)
    for row in selected_rows:
        api_name = str(row.get("api_name") or "").strip()
        if (
            str(row.get("symbol_kind") or "").strip().lower() == "class"
            and api_name
        ):
            targets[api_name].append(serialized_api_identity(row))
    reachability = {
        identity: "not_found_in_static_analysis"
        for identities in targets.values() for identity in identities
    }
    if not targets:
        return {
            "complete": True, "api_reachability": reachability,
            "references": [], "errors": [], "metrics": {"jdeps_invocations": 0},
        }
    started = time.perf_counter()
    artifact = Path(artifact)
    snapshot = artifact.read_bytes()
    artifact_sha256 = hashlib.sha256(snapshot).hexdigest()
    version = subprocess.run(
        [jdeps, "--version"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=10,
    )
    if version.returncode != 0:
        return {
            "complete": False, "api_reachability": reachability, "references": [],
            "errors": [f"jdeps_version_failed:{version.stderr.strip()}"],
            "metrics": {"jdeps_invocations": 0, "elapsed_seconds": time.perf_counter() - started},
        }
    major_match = re.search(r"(\d+)", version.stdout)
    java_major = int(major_match.group(1)) if major_match else 8
    excluded = set(excluded_nested_jars or set())
    application_owned = set(application_owned_nested_jars or set())
    references: list[dict] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="jua-jdeps-") as temp_dir:
        root = Path(temp_dir)
        jobs: list[tuple[str, Path, bool, int]] = []
        with zipfile.ZipFile(io.BytesIO(snapshot)) as outer:
            business_dir = root / "business"
            business_count = _materialize_classes(
                outer, business_dir, java_major, prefix="BOOT-INF/classes/"
            )
            if not business_count:
                business_count = _materialize_classes(
                    outer, business_dir, java_major, prefix="WEB-INF/classes/"
                )
            if business_count:
                jobs.append(("BOOT-INF/classes/", business_dir, True, business_count))
            nested_index = 0
            for name in sorted(outer.namelist()):
                if (
                    not name.endswith(".jar")
                    or not name.startswith(("BOOT-INF/lib/", "WEB-INF/lib/"))
                    or name in excluded
                ):
                    continue
                nested_index += 1
                destination = root / f"nested-{nested_index}"
                try:
                    with zipfile.ZipFile(io.BytesIO(outer.read(name))) as nested:
                        count = _materialize_classes(nested, destination, java_major)
                except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
                    errors.append(f"{name}:{type(error).__name__}:{error}")
                    continue
                if count:
                    jobs.append((name, destination, name in application_owned, count))

        def run_job(job):
            entry, directory, business_owned, class_count = job
            try:
                completed = subprocess.run(
                    [jdeps, "--ignore-missing-deps", "-verbose:class", "-filter:none", str(directory)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    check=False, timeout=timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                return entry, business_owned, class_count, [], f"{type(error).__name__}:{error}"
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip().replace("\n", " ")[:500]
                return entry, business_owned, class_count, [], f"returncode={completed.returncode}:{detail}"
            return entry, business_owned, class_count, parse_jdeps_class_dependencies(completed.stdout), ""

        with ThreadPoolExecutor(max_workers=max(1, int(max_workers))) as executor:
            futures = [executor.submit(run_job, job) for job in jobs]
            for future in as_completed(futures):
                entry, business_owned, _class_count, dependencies, error = future.result()
                if error:
                    errors.append(f"{entry}:{error}")
                    continue
                for caller, target in dependencies:
                    identities = targets.get(target) or []
                    if not identities:
                        continue
                    for identity in identities:
                        if business_owned:
                            reachability[identity] = "reachable"
                        elif reachability[identity] != "reachable":
                            reachability[identity] = "uncertain"
                        references.append({
                            "api_identity": identity,
                            "caller_class": caller,
                            "target_class": target,
                            "artifact_entry": entry,
                            "artifact_sha256": artifact_sha256,
                            "business_owned": business_owned,
                        })

    return {
        "complete": not errors,
        "api_reachability": reachability,
        "references": sorted(references, key=lambda item: (
            item["api_identity"], item["artifact_entry"], item["caller_class"],
        )),
        "errors": sorted(errors),
        "metrics": {
            "jdeps_invocations": len(jobs),
            "class_count": sum(job[3] for job in jobs),
            "elapsed_seconds": time.perf_counter() - started,
            "worker_count": max(1, int(max_workers)),
        },
    }
