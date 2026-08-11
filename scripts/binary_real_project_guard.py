#!/usr/bin/env python3
"""Pinned real-project final-artifact guard for the binary-first engine."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
from typing import Any, Mapping
import urllib.request
import zipfile

from binary_asm_helper import resolve_asm_jar
from binary_fact_store import BinaryFactStore
from binary_pipeline import BinaryPipelineError, run_pipeline
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    return payload


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
    partial = cache / f".{filename}.partial"
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
    except (OSError, TimeoutError) as error:
        partial.unlink(missing_ok=True)
        raise BinaryRealProjectGuardError(
            "REAL_PROJECT_ASSET_DOWNLOAD_FAILED", f"{url}: {error}"
        ) from error
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
                    if name == "current" or entry != current_entry
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


def run_guard(
    manifest: Mapping[str, Any], application: Path, base_dependency: Path,
    output_root: str | Path, *, jdk_home: str | Path,
) -> dict[str, Any]:
    output = Path(output_root).expanduser().resolve()
    materialized = output / "materialized"
    config = materialize_case(
        manifest, application, base_dependency, materialized, jdk_home=jdk_home
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
        "artifact_count": len(config["current"]["artifacts"]),
        "fact_store_bytes": fact_store_bytes,
        "generation_bytes": generation_bytes,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--jdk-home", required=True)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = load_guard_manifest(args.manifest)
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
