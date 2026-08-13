#!/usr/bin/env python3
"""Pinned real-project final-artifact guard for the binary-first engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Mapping
import urllib.request
import zipfile

from binary_asm_helper import resolve_asm_jar
from binary_fact_store import BinaryFactStore
from binary_pipeline import BinaryPipelineError, run_pipeline
from binary_result_truth import evaluate_formal_result_truth, validate_result_truth
from binary_tool_execution import execute_binary_tool
from path_runtime import short_temporary_directory


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT / "tests" / "fixtures" / "binary_first" / "real_projects"
    / "mybatis_sample_xml.json"
)


class BinaryRealProjectGuardError(RuntimeError):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = str(reason_code)
        self.detail = str(detail)
        super().__init__(f"{self.reason_code}: {self.detail}")


_JAVAP_METHOD_HEADING = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|abstract|native|"
    r"synchronized|strictfp|default)\s+)+.*?([A-Za-z_$][\w$]*)\([^)]*\)"
    r"(?:\s+throws\s+.*?)?;\s*$"
)
_JAVAP_FIELD_HEADING = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|volatile|transient)\s+)+"
    r".+\s+([A-Za-z_$][\w$]*);\s*$"
)
_JAVAP_DESCRIPTOR = re.compile(r"^\s*descriptor:\s*(\S+)\s*$")
_JAVAP_FLAGS = re.compile(r"^\s*flags:\s*\(0x[0-9a-fA-F]+\)\s*(.*)$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _jdk_tool(jdk_home: str | Path, name: str) -> str:
    root = Path(jdk_home).expanduser().resolve()
    candidates = (root / "bin" / name, root / "bin" / f"{name}.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise BinaryRealProjectGuardError(
        "REAL_PROJECT_ORACLE_JDK_TOOL_MISSING", f"{name}; jdk_home={root}"
    )


def _javap_contracts(
    *, javap: str, classpath: list[Path], class_name: str,
) -> dict[tuple[str, str, str, str], tuple[str, ...]]:
    completed = execute_binary_tool(
        [
            javap, "-classpath", os.pathsep.join(map(str, classpath)),
            "-p", "-s", "-v", class_name,
        ],
        stage="binary_real_project.oracle_javap",
        reason_prefix="REAL_PROJECT_ORACLE_JAVAP",
        timeout_seconds=60,
        require_stdout=True,
    )
    if not completed.succeeded:
        raise BinaryRealProjectGuardError(
            completed.failure.reason_code,
            json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
        )
    owner = class_name.replace(".", "/")
    simple_name = class_name.rsplit(".", 1)[-1]
    pending_name = ""
    pending_kind = ""
    pending_identity: tuple[str, str, str, str] | None = None
    contracts: dict[tuple[str, str, str, str], tuple[str, ...]] = {}
    for line in str(completed.stdout).splitlines():
        method = _JAVAP_METHOD_HEADING.match(line)
        if method:
            pending_name = method.group(1)
            if pending_name == simple_name:
                pending_name = "<init>"
            pending_kind = "method"
            pending_identity = None
            continue
        field = _JAVAP_FIELD_HEADING.match(line)
        if field:
            pending_name = field.group(1)
            pending_kind = "field"
            pending_identity = None
            continue
        descriptor = _JAVAP_DESCRIPTOR.match(line)
        if descriptor and pending_name:
            pending_identity = (
                owner, pending_name, descriptor.group(1), pending_kind,
            )
            pending_name = ""
            pending_kind = ""
            continue
        flags = _JAVAP_FLAGS.match(line)
        if flags and pending_identity:
            contracts[pending_identity] = tuple(sorted(
                value.strip()
                for value in flags.group(1).split(",") if value.strip()
            ))
            pending_identity = None
    return contracts


def _independent_linkage_oracle(
    config: Mapping[str, Any], manifest: Mapping[str, Any], *, jdk_home: str | Path,
) -> dict[str, Any] | None:
    """Verify authored subset linkage truth using only pinned inputs/OpenJDK."""
    expected = dict(manifest.get("expected") or {})
    provenance = dict(expected.get("oracle_provenance") or {})
    if provenance.get("oracle_kind") != "pinned-openjdk-javap-and-jvm-linkage-v1":
        return None
    implementation = dict(provenance.get("oracle_implementation") or {})
    source_relative = str(implementation.get("path") or "")
    source = (ROOT / source_relative).resolve()
    expected_sha = str(implementation.get("sha256") or "")
    if (
        not source_relative
        or not source.is_relative_to(ROOT.resolve())
        or not source.is_file()
        or _sha256(source) != expected_sha
    ):
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ORACLE_IMPLEMENTATION_INVALID", source_relative
        )
    main_class = str(implementation.get("main_class") or "")
    expected_stdout = [
        str(value) for value in implementation.get("expected_stdout") or ()
    ]
    if not main_class or not expected_stdout:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ORACLE_IMPLEMENTATION_INVALID",
            f"missing main_class/expected_stdout: {source_relative}",
        )

    base_paths = [
        Path(str(row["path"])).resolve()
        for row in (config.get("base") or {}).get("artifacts") or ()
    ]
    current_paths = [
        Path(str(row["path"])).resolve()
        for row in (config.get("current") or {}).get("artifacts") or ()
    ]
    javap = _jdk_tool(jdk_home, "javap")
    javac = _jdk_tool(jdk_home, "javac")
    java = _jdk_tool(jdk_home, "java")
    rows = list(
        ((expected.get("formal_result_truth") or {}).get("expected_results") or ())
    )
    identities = {
        (
            str(row.get("owner") or ""), str(row.get("member") or ""),
            str(row.get("descriptor") or ""), str(row.get("member_kind") or ""),
        )
        for row in rows
    }
    issues: list[dict[str, Any]] = []
    contract_observations = []
    for owner in sorted({identity[0] for identity in identities}):
        dotted = owner.replace("/", ".")
        base_contracts = _javap_contracts(
            javap=javap, classpath=base_paths, class_name=dotted
        )
        current_contracts = _javap_contracts(
            javap=javap, classpath=current_paths, class_name=dotted
        )
        for identity in sorted(value for value in identities if value[0] == owner):
            base_flags = base_contracts.get(identity)
            current_flags = current_contracts.get(identity)
            linkage_flags = {
                "ACC_PUBLIC", "ACC_PROTECTED", "ACC_PRIVATE", "ACC_STATIC",
                "ACC_ABSTRACT", "ACC_FINAL",
            }
            compatible = (
                base_flags is not None
                and current_flags is not None
                and set(base_flags).intersection(linkage_flags)
                == set(current_flags).intersection(linkage_flags)
            )
            contract_observations.append({
                "identity": {
                    key: value for key, value in zip(
                        ("owner", "member", "descriptor", "member_kind"), identity
                    )
                },
                "base_flags": list(base_flags or ()),
                "current_flags": list(current_flags or ()),
                "linkage_contract_compatible": compatible,
            })
            if not compatible:
                issues.append({
                    "reason_code": "REAL_PROJECT_ORACLE_JAVAP_CONTRACT_MISMATCH",
                    "identity": list(identity),
                })

    executions: dict[str, Any] = {}
    with short_temporary_directory(prefix="real-project-linkage-oracle") as temporary:
        classes = Path(temporary) / "classes"
        classes.mkdir()
        compile_result = execute_binary_tool(
            [
                javac, "-encoding", "UTF-8", "-classpath",
                os.pathsep.join(map(str, base_paths)), "-d", str(classes),
                str(source),
            ],
            stage="binary_real_project.oracle_compile",
            reason_prefix="REAL_PROJECT_ORACLE_COMPILE",
            timeout_seconds=60,
        )
        if not compile_result.succeeded:
            raise BinaryRealProjectGuardError(
                compile_result.failure.reason_code,
                json.dumps(
                    compile_result.failure.to_mapping(), ensure_ascii=False
                ),
            )
        for side, paths in (("base", base_paths), ("current", current_paths)):
            execution = execute_binary_tool(
                [
                    java, "-classpath",
                    os.pathsep.join([str(classes), *map(str, paths)]),
                    main_class,
                ],
                stage=f"binary_real_project.oracle_execute_{side}",
                reason_prefix="REAL_PROJECT_ORACLE_EXECUTE",
                timeout_seconds=60,
            )
            actual_stdout = str(execution.stdout).strip().splitlines()
            matched = execution.succeeded and actual_stdout == expected_stdout
            executions[side] = {
                "returncode": execution.returncode,
                "stdout_lines": actual_stdout,
                "expected_stdout_lines": expected_stdout,
                "matched": matched,
            }
            if not matched:
                issues.append({
                    "reason_code": "REAL_PROJECT_ORACLE_JVM_LINKAGE_MISMATCH",
                    "side": side,
                    "returncode": execution.returncode,
                    "stdout_lines": actual_stdout,
                    "stderr": str(execution.stderr)[-1000:],
                })
    return {
        "schema": "java-upgrade-analyzer.real-project-linkage-oracle.v1",
        "status": "passed" if not issues else "failed",
        "issues": issues,
        "producer": "OpenJDK javap + javac + JVM linker",
        "source_path": source_relative,
        "source_sha256": expected_sha,
        "contract_observations": contract_observations,
        "executions": executions,
    }


def _canonicalize_zip(source: Path, destination: Path) -> None:
    """Copy an unsigned build artifact with stable entry metadata and bytes."""
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or any(
            not _safe_entry(name) for name in names
        ):
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_SOURCE_ARCHIVE_INVALID", str(source)
            )
        with zipfile.ZipFile(destination, "w") as output:
            for original in sorted(infos, key=lambda item: item.filename):
                info = zipfile.ZipInfo(
                    original.filename, date_time=(1980, 1, 1, 0, 0, 0)
                )
                info.compress_type = original.compress_type
                info.external_attr = original.external_attr
                info.internal_attr = original.internal_attr
                info.create_system = original.create_system
                info.comment = original.comment
                output.writestr(info, archive.read(original))


def _canonical_zip_info(original: zipfile.ZipInfo, name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = original.compress_type
    info.external_attr = original.external_attr
    info.internal_attr = original.internal_attr
    info.create_system = original.create_system
    info.comment = original.comment
    return info


def load_guard_manifest(path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_MANIFEST_INVALID", f"{target}: {error}"
        ) from error
    if payload.get("schema") != "java-upgrade-analyzer.binary-real-project-guard.v1":
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_MANIFEST_SCHEMA_INVALID", str(payload.get("schema"))
        )
    expected = payload.get("expected")
    if not isinstance(expected, Mapping):
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_EXPECTATION_CONTRACT_INVALID", "expected must be an object"
        )
    formal_truth = expected.get("formal_result_truth")
    if expected.get("reachable_changed_methods") and formal_truth is None:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_FORMAL_TRUTH_MISSING", str(payload.get("case") or target)
        )
    if formal_truth is not None:
        truth_issues = validate_result_truth(formal_truth)
        if truth_issues:
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_FORMAL_TRUTH_INVALID",
                json.dumps(truth_issues, ensure_ascii=False, sort_keys=True),
            )
        if formal_truth.get("result_set_policy") == "exact":
            provenance = expected.get("oracle_provenance")
            producers = (
                provenance.get("oracle_producers")
                if isinstance(provenance, Mapping) else None
            )
            if (
                not isinstance(provenance, Mapping)
                or provenance.get("system_generated") is not False
                or not str(provenance.get("oracle_kind") or "")
                or not str(provenance.get("completeness_argument") or "")
                or not isinstance(producers, list)
                or len(producers) < 2
                or any(
                    not isinstance(item, Mapping)
                    or not all(
                        str(item.get(field) or "")
                        for field in ("id", "organization", "mechanism")
                    )
                    for item in (producers or ())
                )
            ):
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_EXACT_TRUTH_PROVENANCE_INVALID",
                    str(payload.get("case") or target),
                )
        if formal_truth.get("expected_results"):
            provenance = expected.get("oracle_provenance")
            producers = (
                provenance.get("oracle_producers")
                if isinstance(provenance, Mapping) else None
            )
            implementation = (
                provenance.get("oracle_implementation")
                if isinstance(provenance, Mapping) else None
            )
            if (
                not isinstance(provenance, Mapping)
                or provenance.get("system_generated") is not False
                or not str(provenance.get("oracle_kind") or "")
                or not str(provenance.get("completeness_argument") or "")
                or not isinstance(producers, list)
                or len(producers) < 2
                or len({
                    str(item.get("mechanism") or "")
                    for item in producers if isinstance(item, Mapping)
                }) < 2
                or any(
                    not isinstance(item, Mapping)
                    or not all(
                        str(item.get(field) or "")
                        for field in ("id", "organization", "mechanism")
                    )
                    for item in (producers or ())
                )
                or not isinstance(implementation, Mapping)
                or not str(implementation.get("path") or "")
                or len(str(implementation.get("sha256") or "")) != 64
                or not str(implementation.get("main_class") or "")
                or not isinstance(implementation.get("expected_stdout"), list)
                or not implementation.get("expected_stdout")
            ):
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SUBSET_TRUTH_PROVENANCE_INVALID",
                    str(payload.get("case") or target),
                )
            if provenance.get(
                "oracle_kind"
            ) == "pinned-openjdk-javap-and-jvm-linkage-v1":
                inconsistent = [
                    {
                        "owner": row.get("owner"),
                        "member": row.get("member"),
                        "descriptor": row.get("descriptor"),
                        "static_linkage_status": row.get(
                            "static_linkage_status"
                        ),
                    }
                    for row in formal_truth.get("expected_results") or ()
                    if row.get("static_linkage_status")
                    != "compatible_or_not_applicable"
                ]
                if inconsistent:
                    raise BinaryRealProjectGuardError(
                        "REAL_PROJECT_ORACLE_EXPECTED_LINKAGE_STATE_INVALID",
                        json.dumps(
                            inconsistent, ensure_ascii=False, sort_keys=True
                        ),
                    )
    return payload


def verify_manifest_contract(
    manifest: Mapping[str, Any], *, manifest_path: str | Path
) -> dict[str, Any]:
    """Verify pinned identities and independent exact-truth preconditions."""
    issues = []
    revision = str(manifest.get("git_revision") or "")
    if len(revision) != 40 or any(ch not in "0123456789abcdef" for ch in revision):
        issues.append({"reason_code": "REAL_PROJECT_GIT_REVISION_INVALID"})
    assets = dict(manifest.get("assets") or {})
    for name in ("application", "base_dependency"):
        asset = dict(assets.get(name) or {})
        digest = str(asset.get("sha256") or "")
        if len(digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in digest
        ):
            issues.append({
                "reason_code": "REAL_PROJECT_ASSET_DIGEST_INVALID",
                "asset": name,
            })
    expected = dict(manifest.get("expected") or {})
    truth = dict(expected.get("formal_result_truth") or {})
    provenance = dict(expected.get("oracle_provenance") or {})
    oracle_kind = str(provenance.get("oracle_kind") or "")
    implementation_check: dict[str, Any] = {}
    if oracle_kind == "identical-runtime-bytes-exact-empty-v1":
        base = dict(assets.get("base_dependency") or {})
        current = dict(manifest.get("current_nested_asset") or {})
        checks = {
            "dependency_sha256": base.get("sha256") == current.get("sha256"),
            "dependency_coordinate": (
                base.get("coordinate") == current.get("coordinate")
            ),
            "exact_result_set": truth.get("result_set_policy") == "exact",
            "empty_expected_results": truth.get("expected_results") == [],
            "all_reachability_states_closed": set(
                truth.get("exact_reachability_statuses") or ()
            ) == {
                "reachable", "uncertain", "not_found_in_static_analysis",
                "not_analyzed",
            },
        }
        for field, passed in checks.items():
            if not passed:
                issues.append({
                    "reason_code": "REAL_PROJECT_NOOP_ORACLE_PRECONDITION_FAILED",
                    "field": field,
                })
    else:
        checks = {}
        if truth.get("expected_results"):
            implementation = dict(
                provenance.get("oracle_implementation") or {}
            )
            implementation_path = str(implementation.get("path") or "")
            expected_sha = str(implementation.get("sha256") or "")
            repository_root = ROOT.resolve()
            candidate = (repository_root / implementation_path).resolve()
            path_safe = bool(
                implementation_path
                and candidate.is_relative_to(repository_root)
                and candidate.is_file()
            )
            actual_sha = _sha256(candidate) if path_safe else ""
            implementation_check = {
                "path": implementation_path,
                "path_safe_and_present": path_safe,
                "expected_sha256": expected_sha,
                "actual_sha256": actual_sha,
                "sha256_matches": bool(expected_sha and actual_sha == expected_sha),
            }
            if not all((
                implementation_check["path_safe_and_present"],
                implementation_check["sha256_matches"],
            )):
                issues.append({
                    "reason_code": (
                        "REAL_PROJECT_ORACLE_IMPLEMENTATION_INVALID"
                    ),
                    "fields": sorted(
                        field for field in (
                            "path_safe_and_present", "sha256_matches"
                        ) if not implementation_check[field]
                    ),
                })
            if oracle_kind == "pinned-openjdk-javap-and-jvm-linkage-v1":
                incompatible_rows = [
                    {
                        "owner": row.get("owner"),
                        "member": row.get("member"),
                        "descriptor": row.get("descriptor"),
                    }
                    for row in truth.get("expected_results") or ()
                    if row.get("static_linkage_status")
                    != "compatible_or_not_applicable"
                ]
                if incompatible_rows:
                    issues.append({
                        "reason_code": (
                            "REAL_PROJECT_ORACLE_EXPECTED_LINKAGE_STATE_INVALID"
                        ),
                        "results": incompatible_rows,
                    })
    path = Path(manifest_path).expanduser().resolve()
    return {
        "schema": (
            "java-upgrade-analyzer.binary-real-project-manifest-verification.v1"
        ),
        "status": "passed" if not issues else "failed",
        "issues": issues,
        "case": manifest.get("case"),
        "repository": manifest.get("repository"),
        "git_revision": revision,
        "manifest_sha256": _sha256(path),
        "formal_result_set_policy": truth.get("result_set_policy"),
        "expected_result_count": len(truth.get("expected_results") or ()),
        "oracle_kind": oracle_kind,
        "oracle_producer_count": len(
            provenance.get("oracle_producers") or ()
        ),
        "oracle_implementation": implementation_check,
        "noop_preconditions": checks,
    }


def evaluate_real_project_formal_truth(
    formal_payload: Mapping[str, Any], expected: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Evaluate the optional exact-identity contract for a real-project case."""
    if "formal_result_truth" not in expected:
        return None
    return evaluate_formal_result_truth(
        formal_payload, expected.get("formal_result_truth")
    )


def resolve_asset(
    asset: Mapping[str, Any], cache_root: str | Path, *, allow_download: bool,
) -> Path:
    cache = Path(cache_root).expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    filename = Path(str(asset.get("filename") or "")).name
    expected = str(asset.get("sha256") or "").lower()
    if not filename or len(expected) != 64:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_CONTRACT_INVALID", str(asset)
        )
    target = cache / filename
    if target.is_file() and _sha256(target) == expected:
        return target
    if target.exists():
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_DIGEST_MISMATCH", str(target)
        )
    if not allow_download:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_MISSING", f"{filename}; cache={cache}"
        )
    if str(asset.get("kind") or "published") == "source_build":
        repository = str(asset.get("repository_url") or "")
        revision = str(asset.get("git_revision") or "")
        working_directory = str(asset.get("working_directory") or "")
        build_command = [str(value) for value in asset.get("build_command") or ()]
        artifact_path = str(asset.get("artifact_path") or "")
        if (
            not repository.startswith("https://")
            or len(revision) != 40
            or not build_command
            or not artifact_path
        ):
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_SOURCE_BUILD_CONTRACT_INVALID", filename
            )
        with short_temporary_directory(
            prefix="real-project-source-build"
        ) as temporary:
            checkout = Path(temporary) / "checkout"
            commands = [
                (
                    ["git", "clone", "--quiet", "--no-checkout", repository, str(checkout)],
                    cache,
                    "clone",
                ),
                (
                    ["git", "-C", str(checkout), "checkout", "--quiet", "--detach", revision],
                    cache,
                    "checkout",
                ),
            ]
            for command, cwd, stage in commands:
                completed = execute_binary_tool(
                    command, stage=f"binary_real_project.{stage}",
                    reason_prefix="REAL_PROJECT_SOURCE_GIT",
                    timeout_seconds=300, cwd=cwd,
                )
                if not completed.succeeded:
                    raise BinaryRealProjectGuardError(
                        completed.failure.reason_code,
                        json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
                    )
            head = execute_binary_tool(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                stage="binary_real_project.revision",
                reason_prefix="REAL_PROJECT_SOURCE_GIT",
                timeout_seconds=30, require_stdout=True,
            )
            if not head.succeeded or str(head.stdout).strip() != revision:
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SOURCE_REVISION_MISMATCH",
                    str(head.stdout).strip() if head.succeeded else str(head.failure),
                )
            build_root = (checkout / working_directory).resolve()
            try:
                build_root.relative_to(checkout.resolve())
            except ValueError as error:
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SOURCE_BUILD_PATH_UNSAFE", working_directory
                ) from error
            built = execute_binary_tool(
                build_command, stage="binary_real_project.build",
                reason_prefix="REAL_PROJECT_SOURCE_BUILD",
                timeout_seconds=900, cwd=build_root,
            )
            if not built.succeeded:
                raise BinaryRealProjectGuardError(
                    built.failure.reason_code,
                    json.dumps(built.failure.to_mapping(), ensure_ascii=False),
                )
            produced = (build_root / artifact_path).resolve()
            try:
                produced.relative_to(build_root)
            except ValueError as error:
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SOURCE_ARTIFACT_PATH_UNSAFE", artifact_path
                ) from error
            if not produced.is_file():
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SOURCE_ARTIFACT_DIGEST_MISMATCH",
                    str(produced),
                )
            partial = cache / f".{filename}.partial"
            if asset.get("canonicalize_zip") is True:
                _canonicalize_zip(produced, partial)
            else:
                shutil.copyfile(produced, partial)
            if _sha256(partial) != expected:
                partial.unlink(missing_ok=True)
                raise BinaryRealProjectGuardError(
                    "REAL_PROJECT_SOURCE_ARTIFACT_DIGEST_MISMATCH",
                    str(produced),
                )
            partial.replace(target)
            return target
    url = str(asset.get("url") or "")
    if not url.startswith("https://"):
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_CONTRACT_INVALID",
            f"published asset must use HTTPS: {url}",
        )
    partial = cache / f".{filename}.partial"
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
    except (OSError, TimeoutError) as primary_error:
        partial.unlink(missing_ok=True)
        curl = shutil.which("curl")
        if not curl:
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_ASSET_DOWNLOAD_FAILED",
                f"{url}: urllib={primary_error}; secure curl fallback unavailable",
            ) from primary_error
        fallback = execute_binary_tool(
            [
                curl,
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "30",
                "--max-time",
                "120",
                "--output",
                str(partial),
                url,
            ],
            stage="binary_real_project.download_curl_fallback",
            reason_prefix="REAL_PROJECT_ASSET_DOWNLOAD",
            timeout_seconds=130,
        )
        if not fallback.succeeded or not partial.is_file():
            partial.unlink(missing_ok=True)
            fallback_detail = (
                fallback.failure.to_mapping()
                if fallback.failure is not None else
                {"reason_code": "REAL_PROJECT_ASSET_DOWNLOAD_NO_OUTPUT"}
            )
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_ASSET_DOWNLOAD_FAILED",
                json.dumps({
                    "url": url,
                    "urllib_error": str(primary_error),
                    "curl_fallback": fallback_detail,
                }, ensure_ascii=False, sort_keys=True),
            ) from primary_error
    actual = _sha256(partial)
    if actual != expected:
        partial.unlink(missing_ok=True)
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_DIGEST_MISMATCH",
            f"{filename}: expected={expected}; actual={actual}",
        )
    partial.replace(target)
    return target


def _safe_entry(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _nested_order(archive: zipfile.ZipFile) -> list[str]:
    names = {item.filename for item in archive.infolist() if not item.is_dir()}
    if "BOOT-INF/classpath.idx" in names:
        result = []
        for raw in archive.read("BOOT-INF/classpath.idx").decode(
            "utf-8", errors="strict"
        ).splitlines():
            value = raw.strip()
            if value.startswith("- "):
                value = value[2:].strip().strip('"').strip("'")
            if value in names and value.startswith("BOOT-INF/lib/"):
                result.append(value)
        if result:
            return result
    return sorted(
        name for name in names
        if name.startswith("BOOT-INF/lib/") and name.endswith(".jar")
    )


def materialize_case(
    manifest: Mapping[str, Any], application: Path, base_dependency: Path,
    destination: str | Path, *, jdk_home: str | Path,
) -> dict[str, Any]:
    root = Path(destination).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    application_sha = _sha256(application)
    if application_sha != manifest["assets"]["application"]["sha256"]:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_APPLICATION_DIGEST_MISMATCH", application_sha
        )
    if _sha256(base_dependency) != manifest["assets"]["base_dependency"]["sha256"]:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_BASE_DEPENDENCY_DIGEST_MISMATCH", str(base_dependency)
        )
    business = root / "business-classes.jar"
    nested_paths: list[tuple[str, Path]] = []
    required_resources = set(manifest["expected"]["required_resources"])
    observed_resources = set()
    with zipfile.ZipFile(application) as outer:
        infos = outer.infolist()
        if len(infos) > 100_000:
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_ARCHIVE_ENTRY_LIMIT", str(len(infos))
            )
        if any(not _safe_entry(info.filename) for info in infos):
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_ARCHIVE_PATH_UNSAFE", str(application)
            )
        prefix = "BOOT-INF/classes/"
        business_entries = sorted(
            (
                info.filename[len(prefix):], info
            )
            for info in infos
            if not info.is_dir() and info.filename.startswith(prefix)
            and info.filename[len(prefix):]
            and _safe_entry(info.filename[len(prefix):])
        )
        with zipfile.ZipFile(business, "w") as output:
            for logical, info in business_entries:
                content = outer.read(info)
                output.writestr(_canonical_zip_info(info, logical), content)
                if logical in required_resources:
                    observed_resources.add(logical)
        missing_resources = required_resources - observed_resources
        if missing_resources:
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_REQUIRED_RESOURCE_MISSING",
                ",".join(sorted(missing_resources)),
            )
        deps = root / "nested"
        deps.mkdir(exist_ok=True)
        for slot, entry in enumerate(_nested_order(outer)):
            content = outer.read(entry)
            path = deps / f"{slot:03d}-{Path(entry).name}"
            path.write_bytes(content)
            nested_paths.append((entry, path))

    current_expected = manifest["current_nested_asset"]
    current_entry = str(current_expected["entry"])
    current_matches = [path for entry, path in nested_paths if entry == current_entry]
    if len(current_matches) != 1 or _sha256(current_matches[0]) != current_expected["sha256"]:
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_CURRENT_DEPENDENCY_IDENTITY_MISMATCH", current_entry
        )

    entrypoint = manifest["entrypoint"]
    application_coord = str(manifest["application_coordinate"])
    base_coord = str(manifest["assets"]["base_dependency"]["coordinate"])
    current_coord = str(current_expected["coordinate"])
    lineage = ":".join(current_coord.split(":")[:2])
    base_matches_current_runtime_asset = (
        _sha256(base_dependency) == str(current_expected["sha256"])
        and base_coord == current_coord
    )

    def side(name: str) -> dict[str, Any]:
        artifacts = [{
            "path": str(business),
            "outer_artifact_path": str(application),
            "container_entry": "BOOT-INF/classes/",
            "logical_location": "application/business-classes.jar",
            "loader_realm": "application-loader",
            "path_kind": "business_classes",
            "slot": 0,
            "coord": application_coord,
            "lineage": "application:business",
            "runtime_code_source_origin_identity": f"sha256:{application_sha}#BOOT-INF/classes",
        }]
        for index, (entry, current_path) in enumerate(nested_paths, start=1):
            filename = Path(entry).name
            if entry == current_entry:
                path = base_dependency if name == "base" else current_path
                coord = base_coord if name == "base" else current_coord
                dependency_lineage = lineage
            else:
                path = current_path
                coord = f"real-project:{filename}"
                dependency_lineage = f"real-project:{filename}"
            artifacts.append({
                "path": str(path), "outer_artifact_path": str(application),
                "container_entry": entry,
                "logical_location": f"dependencies/{index:03d}-{filename}",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": index, "coord": coord, "lineage": dependency_lineage,
                "runtime_code_source_origin_identity": (
                    f"sha256:{application_sha}#{entry}"
                    if (
                        name == "current"
                        or entry != current_entry
                        or base_matches_current_runtime_asset
                    )
                    else f"sha256:{_sha256(base_dependency)}#external-base"
                ),
            })
        return {
            "jdk_home": str(Path(jdk_home).expanduser().resolve()),
            "artifacts": artifacts,
            "runtime_profile": {
                "container_and_launcher_kind": "spring-boot-executable-jar",
                "loader_topology": {
                    "coverage_status": "complete",
                    "entrypoint_realms": ["application-loader"],
                    "realms": [{
                        "identity": "platform-loader", "kind": "platform",
                        "delegation": "parent_first", "module_mode": "named-platform",
                    }, {
                        "identity": "application-loader", "kind": "application",
                        "parent": "platform-loader", "delegation": "parent_first",
                        "module_mode": "unnamed",
                    }],
                },
                "runtime_security_and_package_sealing_policy_identity": (
                    "standard-unsealed-unsigned-v1"
                ),
                "active_profile_identities": ["default"],
                "resolved_configuration_properties": {},
                "runtime_configuration_coverage_status": "complete",
                "external_config_snapshot_identities": [],
                "agent_transformer_plugin_profile_identities": [],
                "business_entrypoint_profile": {
                    "coverage_status": "complete",
                    "activated_frameworks": list(
                        manifest.get("activated_frameworks") or ("spring_boot",)
                    ),
                    "main_class": entrypoint["class_name"],
                    "methods": [{
                        "initiating_loader_realm_identity": "application-loader",
                        "class_name": entrypoint["class_name"],
                        "member_name": entrypoint["member_name"],
                        "descriptor": entrypoint["descriptor"],
                    }],
                },
                "runtime_class_closure_coverage_status": "complete",
                "resource_selection_coverage_status": "complete",
            },
        }

    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "source_inputs": {
            "purpose_version": "source-input-purpose-v2",
            "business": {"status": "not_provided", "origin": "not_provided"},
            "dependencies": {"status": "not_provided", "origin": "not_provided"},
        },
        "asm_jar": str(resolve_asm_jar()),
        "base": side("base"), "current": side("current"),
        "runtime_comparison": {
            "comparison_intent": "release_snapshot",
            "controlled_profile_fields": ["loader_topology"],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
        },
        "real_project_attestation": {
            "case": manifest["case"], "git_revision": manifest["git_revision"],
            "application_sha256": application_sha,
            "base_dependency_sha256": _sha256(base_dependency),
            "current_dependency_sha256": current_expected["sha256"],
        },
    }


def _independent_identical_runtime_oracle(
    config: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any] | None:
    provenance = dict(
        (manifest.get("expected") or {}).get("oracle_provenance") or {}
    )
    if provenance.get("oracle_kind") != "identical-runtime-bytes-exact-empty-v1":
        return None
    base = list((config.get("base") or {}).get("artifacts") or ())
    current = list((config.get("current") or {}).get("artifacts") or ())
    issues = []
    if len(base) != len(current):
        issues.append({
            "reason_code": "REAL_PROJECT_NOOP_ARTIFACT_COUNT_MISMATCH",
            "base": len(base), "current": len(current),
        })
    paired = []
    for index, (left, right) in enumerate(zip(base, current)):
        fields = (
            "logical_location", "loader_realm", "path_kind", "slot",
            "coord", "lineage", "runtime_code_source_origin_identity",
            "outer_artifact_path", "container_entry",
        )
        mismatches = [field for field in fields if left.get(field) != right.get(field)]
        left_path = Path(str(left.get("path") or ""))
        right_path = Path(str(right.get("path") or ""))
        left_sha = _sha256(left_path) if left_path.is_file() else ""
        right_sha = _sha256(right_path) if right_path.is_file() else ""
        if left_sha != right_sha:
            mismatches.append("content_sha256")
        try:
            with zipfile.ZipFile(left_path) as left_zip, zipfile.ZipFile(
                right_path
            ) as right_zip:
                left_inventory = [
                    (item.filename, item.file_size, item.CRC)
                    for item in left_zip.infolist()
                ]
                right_inventory = [
                    (item.filename, item.file_size, item.CRC)
                    for item in right_zip.infolist()
                ]
        except (OSError, zipfile.BadZipFile) as error:
            left_inventory = []
            right_inventory = [("archive_error", 0, 0)]
            mismatches.append(f"zip_inventory:{type(error).__name__}")
        if left_inventory != right_inventory:
            mismatches.append("ordered_zip_inventory")
        if mismatches:
            issues.append({
                "reason_code": "REAL_PROJECT_NOOP_RUNTIME_PAIR_MISMATCH",
                "artifact_index": index,
                "fields": sorted(set(mismatches)),
            })
        paired.append({
            "artifact_index": index,
            "logical_location": left.get("logical_location"),
            "sha256": left_sha,
            "entry_count": len(left_inventory),
        })
    return {
        "schema": "java-upgrade-analyzer.real-project-noop-oracle.v1",
        "status": "passed" if not issues else "failed",
        "issues": issues,
        "artifact_count": len(paired),
        "paired_artifacts": paired,
        "expected_formal_result_count": 0,
        "expectation_source": "independent_complete_runtime_byte_identity",
    }


def run_guard(
    manifest: Mapping[str, Any], application: Path, base_dependency: Path,
    output_root: str | Path, *, jdk_home: str | Path,
) -> dict[str, Any]:
    output = Path(output_root).expanduser().resolve()
    materialized = output / "materialized"
    config = materialize_case(
        manifest, application, base_dependency, materialized, jdk_home=jdk_home
    )
    independent_noop_oracle = _independent_identical_runtime_oracle(
        config, manifest
    )
    if independent_noop_oracle is not None and independent_noop_oracle[
        "status"
    ] != "passed":
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_NOOP_ORACLE_FAILED",
            json.dumps(
                independent_noop_oracle["issues"],
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
    independent_linkage_oracle = _independent_linkage_oracle(
        config, manifest, jdk_home=jdk_home
    )
    if (
        independent_linkage_oracle is not None
        and independent_linkage_oracle["status"] != "passed"
    ):
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_LINKAGE_ORACLE_FAILED",
            json.dumps(
                independent_linkage_oracle["issues"],
                ensure_ascii=False,
                sort_keys=True,
            ),
        )
    result = run_pipeline(config, output_root=output / "binary_authority")
    generation = Path(result["generation_directory"])
    formal = json.loads(
        (generation / "binary_formal_results.json").read_text(encoding="utf-8")
    )
    overlay = json.loads(
        (generation / "binary_runtime_semantic_overlay.json").read_text(
            encoding="utf-8"
        )
    )
    entrypoints = json.loads(
        (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
    )
    with BinaryFactStore(generation / "current_binary_facts.sqlite") as store:
        packaged_resources = {
            str(row.get("resource_name") or "")
            for row in store.rows("resources")
        }
    expected = manifest["expected"]
    truth_evaluation = evaluate_real_project_formal_truth(formal, expected)
    expected_methods = set(expected.get("reachable_changed_methods") or ())
    expected_resources = set(expected.get("required_resources") or ())
    observed = {
        f"{row.get('display_owner')}.{row.get('display_member')}": row.get(
            "reachability_status"
        )
        for row in formal.get("by_api") or ()
    }
    missing = sorted(expected_methods - set(observed))
    not_reachable = sorted(
        value for value in expected_methods if observed.get(value) != "reachable"
    )
    semantic_kinds = {
        str(row.get("semantic_edge_kind") or "") for row in overlay.get("rows") or ()
    }
    issues = []
    if truth_evaluation is not None and truth_evaluation["status"] != "passed":
        issues.append({
            "reason_code": "REAL_PROJECT_FORMAL_RESULT_TRUTH_MISMATCH",
            "evaluation": truth_evaluation,
        })
    if missing:
        issues.append({"reason_code": "REAL_PROJECT_EXPECTED_CHANGE_MISSING", "items": missing})
    if not_reachable:
        issues.append({"reason_code": "REAL_PROJECT_EXPECTED_CHANGE_NOT_REACHABLE", "items": not_reachable})
    missing_resources = sorted(expected_resources - packaged_resources)
    if missing_resources:
        issues.append({
            "reason_code": "REAL_PROJECT_REQUIRED_RESOURCE_MISSING",
            "items": missing_resources,
        })
    expected_kind = str(expected.get("semantic_edge_kind") or "")
    if expected_kind and expected_kind not in semantic_kinds:
        issues.append({"reason_code": "REAL_PROJECT_SEMANTIC_EDGE_MISSING", "kind": expected_kind})
    expected_entrypoint = expected.get("entrypoint") or {}
    entrypoint_matches = [
        row for row in entrypoints.get("records") or ()
        if row.get("class_name") == expected_entrypoint.get("class_name")
        and row.get("member_name") == expected_entrypoint.get("member_name")
        and row.get("descriptor") == expected_entrypoint.get("descriptor")
        and row.get("entry_kind") == expected_entrypoint.get("entry_kind")
        and row.get("path_certainty") == expected_entrypoint.get("path_certainty")
    ] if expected_entrypoint else []
    if expected_entrypoint and len(entrypoint_matches) != 1:
        issues.append({
            "reason_code": "REAL_PROJECT_ENTRYPOINT_MISSING",
            "entrypoint": expected_entrypoint,
            "observed": [
                {
                    key: row.get(key) for key in (
                        "class_name", "member_name", "descriptor", "entry_kind",
                        "path_certainty", "dependency_coord", "runtime_path_kind",
                    )
                }
                for row in entrypoints.get("records") or ()
                if row.get("class_name") == expected_entrypoint.get("class_name")
            ],
        })
    fact_store_bytes = {
        side: (generation / f"{side}_binary_facts.sqlite").stat().st_size
        for side in ("base", "current")
    }
    generation_bytes = sum(
        path.stat().st_size for path in generation.iterdir() if path.is_file()
    )
    return {
        "schema": "java-upgrade-analyzer.binary-real-project-result.v1",
        "case": manifest["case"],
        "status": "passed" if not issues else "failed",
        "issues": issues,
        "result_generation_identity": result["result_generation_identity"],
        "observed_expected_methods": {
            key: observed.get(key) for key in sorted(expected_methods)
        },
        "observed_required_resources": sorted(
            expected_resources.intersection(packaged_resources)
        ),
        "semantic_edge_kinds": sorted(semantic_kinds),
        "observed_entrypoints": entrypoint_matches,
        "formal_result_truth_evaluation": truth_evaluation,
        "independent_noop_oracle": independent_noop_oracle,
        "independent_linkage_oracle": independent_linkage_oracle,
        "artifact_count": len(config["current"]["artifacts"]),
        "fact_store_bytes": fact_store_bytes,
        "generation_bytes": generation_bytes,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--cache-root", default="")
    parser.add_argument("--output-root", default="")
    parser.add_argument("--jdk-home", default="")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--verify-manifest", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = load_guard_manifest(args.manifest)
        if args.verify_manifest:
            result = verify_manifest_contract(
                manifest, manifest_path=args.manifest
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0 if result["status"] == "passed" else 1
        missing = [
            option for option, value in (
                ("--cache-root", args.cache_root),
                ("--output-root", args.output_root),
                ("--jdk-home", args.jdk_home),
            ) if not str(value or "").strip()
        ]
        if missing:
            raise BinaryRealProjectGuardError(
                "REAL_PROJECT_REQUIRED_ARGUMENT_MISSING", ",".join(missing)
            )
        application = resolve_asset(
            manifest["assets"]["application"], args.cache_root,
            allow_download=args.download,
        )
        base_dependency = resolve_asset(
            manifest["assets"]["base_dependency"], args.cache_root,
            allow_download=args.download,
        )
        result = run_guard(
            manifest, application, base_dependency, args.output_root,
            jdk_home=args.jdk_home,
        )
    except BinaryRealProjectGuardError as error:
        result = {
            "schema": "java-upgrade-analyzer.binary-real-project-result.v1",
            "status": "failed",
            "issues": [{
                "reason_code": error.reason_code,
                "detail": error.detail,
            }],
        }
    except BinaryPipelineError as error:
        result = {
            "schema": "java-upgrade-analyzer.binary-real-project-result.v1",
            "status": "failed",
            "issues": [{
                "reason_code": error.reason_code,
                "detail": str(error),
            }],
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
