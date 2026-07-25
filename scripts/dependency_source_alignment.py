#!/usr/bin/env python3
"""Pin dependency source mappings to Step4-confirmed current-version commits."""

import hashlib
import io
import json
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path, PureWindowsPath

from artifact_coordinates import artifact_classifier, artifact_ga
from path_runtime import (
    bounded_path_component,
    git_with_long_paths,
    make_short_temp_dir,
    runtime_storage_root,
)


def _run_git(repo_path, *args):
    completed = subprocess.run(
        git_with_long_paths() + ["-C", str(repo_path), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return completed.stdout.strip(), completed.stderr.strip(), completed.returncode


def extract_zip_safely(archive, destination_root):
    """Extract only regular, root-contained ZIP members.

    `ZipFile.extractall` accepts archive-controlled path names.  Source
    snapshots must never let a Git/archive member create files outside the
    temporary snapshot directory or materialize an unexpected symlink.
    """
    destination_root = Path(destination_root).resolve()
    for member in archive.infolist():
        raw_name = str(member.filename or "")
        normalized_name = raw_name.replace("\\", "/")
        relative = Path(normalized_name)
        windows_relative = PureWindowsPath(raw_name)
        if (
            not raw_name
            or "\x00" in raw_name
            or relative.is_absolute()
            or windows_relative.is_absolute()
            or bool(windows_relative.drive)
            or any(part in {"", ".", ".."} for part in relative.parts)
            or stat.S_ISLNK(member.external_attr >> 16)
        ):
            raise RuntimeError("dependency_source_snapshot_archive_escapes_root")
        target = (destination_root / relative).resolve()
        try:
            target.relative_to(destination_root)
        except ValueError as exc:
            raise RuntimeError("dependency_source_snapshot_archive_escapes_root") from exc
        if member.is_dir() or raw_name.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member, "r") as source, target.open("wb") as output:
            shutil.copyfileobj(source, output)


def _coord_ga(coord):
    return artifact_ga(coord)


def _safe_coord(coord):
    return bounded_path_component(
        coord,
        max_length=40,
        default="dependency",
        always_hash=True,
    )


def normalize_mapping(mapping):
    if isinstance(mapping, dict):
        coord = str(mapping.get("coord") or "").strip()
        path = str(mapping.get("path") or "").strip()
    else:
        text = str(mapping or "").strip()
        if "=" not in text:
            return "", ""
        coord, path = (part.strip() for part in text.split("=", 1))
    return coord, path


def load_step4_current_ref_records(report_dir):
    path = Path(report_dir) / "evidence" / "api_changes" / "git_ref_matches.json"
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    records = []
    for item in payload.get("matched_items") or []:
        meta = dict(item.get("meta") or {})
        merged = {**item, **meta}
        coord = str(merged.get("coord") or "").strip()
        repo_path = str(merged.get("repo_path") or "").strip()
        ref = str(
            merged.get("resolved_new_ref")
            or merged.get("cur_ref")
            or merged.get("new_ref")
            or ""
        ).strip()
        new_source = dict(merged.get("new_source") or {})
        source_status = str(
            merged.get("current_source_status")
            or new_source.get("status")
            or ""
        ).strip()
        if not coord:
            continue
        records.append({
            "coord": coord,
            "repo_path": repo_path,
            "module_rel_path": str(merged.get("module_rel_path") or ".").strip() or ".",
            "current_ref": ref,
            "new_version": str(merged.get("new_version") or "").strip(),
            "source_status": source_status,
            "remote": str(new_source.get("remote") or "").strip(),
            "remote_ref": str(new_source.get("remote_ref") or "").strip(),
        })
    return records


def resolve_unique_ref_record(coord, records):
    exact_candidates = [
        item for item in records or []
        if str(item.get("coord") or "").strip() == str(coord or "").strip()
    ]
    if exact_candidates:
        candidates = exact_candidates
    elif artifact_classifier(coord):
        candidates = []
    else:
        coord_ga = _coord_ga(coord)
        candidates = [
            item for item in records or []
            if _coord_ga(item.get("coord"))
            and _coord_ga(item.get("coord")) == coord_ga
        ]
    if not candidates:
        return None, "step4_current_ref_missing"
    invalid_statuses = sorted({
        str(item.get("source_status") or "").strip() or "missing"
        for item in candidates
        if str(item.get("source_status") or "").strip() not in {
            "remote_source_resolved",
            "user_confirmed_local_source",
        }
    })
    if invalid_statuses:
        return None, "step4_source_provenance_unconfirmed"
    unique = {
        (
            str(item.get("repo_path") or "").strip(),
            str(item.get("module_rel_path") or ".").strip() or ".",
            str(item.get("current_ref") or "").strip(),
            str(item.get("source_status") or "").strip(),
        )
        for item in candidates
    }
    if len(unique) != 1:
        return None, "step4_current_ref_conflict"
    record = dict(candidates[0])
    if not record.get("repo_path") or not record.get("current_ref"):
        return None, "step4_current_ref_missing"
    return record, ""


def repository_fingerprint(repo_path):
    branch, _stderr, branch_rc = _run_git(repo_path, "branch", "--show-current")
    head, _stderr, head_rc = _run_git(repo_path, "rev-parse", "HEAD")
    status, _stderr, status_rc = _run_git(repo_path, "status", "--porcelain")
    if branch_rc or head_rc or status_rc:
        return None
    return {
        "branch": branch,
        "head": head,
        "status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        "dirty_entry_count": len([line for line in status.splitlines() if line.strip()]),
        "_raw_status": status,
    }


def _fingerprints_equal(before, after):
    if not before or not after:
        return False
    return all(before.get(key) == after.get(key) for key in ("branch", "head", "_raw_status"))


def _public_fingerprint(fingerprint):
    if not fingerprint:
        return {}
    return {key: value for key, value in fingerprint.items() if not key.startswith("_")}


def materialize_detached_snapshot(report_dir, coord, repo_path, ref, module_rel_path):
    commit, stderr, rc = _run_git(repo_path, "rev-parse", f"{ref}^{{commit}}")
    if rc or not commit:
        raise RuntimeError(f"dependency_source_ref_not_found:{stderr or ref}")
    snapshot = (
        runtime_storage_root(report_dir, "source_snapshots")
        / _safe_coord(coord)
        / commit[:12]
    )
    marker_name = ".jua-source-snapshot.json"
    reused = False
    if snapshot.exists():
        marker = snapshot / marker_name
        try:
            marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            marker_payload = {}
        if marker_payload.get("commit") != commit:
            raise RuntimeError("dependency_source_snapshot_conflict")
        reused = True
    else:
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        # `git worktree add` leaves a reverse registration in the user's
        # repository.  Report cleanup by `rm -rf` then creates a stale worktree
        # record.  Archive the exact commit instead: the source bytes are the
        # same tracked revision and the user's repository is never mutated.
        completed = subprocess.run(
            git_with_long_paths() + [
                "-C", str(repo_path), "archive", "--format=zip", commit,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "dependency_source_snapshot_create_failed:"
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
        temporary = make_short_temp_dir(
            prefix=f"source-{commit[:8]}",
            preferred_root=snapshot.parent,
            strict_preferred=True,
        )
        try:
            with zipfile.ZipFile(io.BytesIO(completed.stdout)) as archive:
                extract_zip_safely(archive, temporary)
            (temporary / marker_name).write_text(
                json.dumps({"schema": 1, "commit": commit}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.rename(snapshot)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    snapshot_root = snapshot.resolve()
    module_root = (snapshot / (module_rel_path or ".")).resolve()
    try:
        module_root.relative_to(snapshot_root)
    except ValueError as exc:
        raise RuntimeError("dependency_source_module_path_escapes_snapshot") from exc
    if not module_root.is_dir():
        raise RuntimeError("dependency_source_module_path_missing")
    return {
        "commit": commit,
        "snapshot_path": str(snapshot),
        "module_root": str(module_root),
        "snapshot_reused": reused,
    }


def discover_standard_source_dirs(module_root):
    module_root = Path(module_root)
    candidates = []
    for relative in (Path("src/main/java"), Path("src/main/kotlin")):
        path = module_root / relative
        if path.is_dir():
            candidates.append(str(path.resolve()))
    return candidates


def index_jar_classes(jar_path):
    classes = set()
    with zipfile.ZipFile(jar_path) as jar:
        for name in jar.namelist():
            if not name.endswith(".class") or name.startswith("META-INF/"):
                continue
            if name.endswith(("module-info.class", "package-info.class")):
                continue
            class_name = name[:-6].replace("/", ".")
            for prefix in ("BOOT-INF.classes.", "WEB-INF.classes."):
                if class_name.startswith(prefix):
                    class_name = class_name[len(prefix):]
                    break
            if class_name.startswith(("BOOT-INF.", "WEB-INF.", "lib.")):
                continue
            classes.add(class_name)
    return classes


def inventory_source_classes(source_dirs):
    """Return production source class candidates for alignment diagnostics.

    The graph parser remains authoritative.  This inventory deliberately uses
    package declarations plus declared type names only to explain how much of
    the selected source revision is represented by the runtime JAR.
    """
    classes = set()
    package_pattern = re.compile(
        r"^\s*package\s+([A-Za-z_][\w.]*)\s*;?",
        re.MULTILINE,
    )
    type_pattern = re.compile(
        r"\b(?:class|interface|enum|record|object)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    for source_dir in source_dirs or []:
        root = Path(source_dir)
        for path in sorted(list(root.rglob("*.java")) + list(root.rglob("*.kt"))):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            package_match = package_pattern.search(content)
            package_name = package_match.group(1) if package_match else ""
            for type_name in type_pattern.findall(content):
                classes.add(f"{package_name}.{type_name}" if package_name else type_name)
    return classes


def source_class_present_in_jar(class_fqcn, jar_classes):
    if class_fqcn in jar_classes:
        return True
    return any(value.startswith(f"{class_fqcn}$") for value in jar_classes)


def _runtime_item_for_coord(coord, runtime_catalog):
    by_coord = (runtime_catalog or {}).get("by_coord") or {}
    exact = by_coord.get(coord)
    if exact:
        return dict(exact)
    if artifact_classifier(coord):
        return None
    coord_ga = _coord_ga(coord)
    matches = [
        dict(item or {})
        for key, item in by_coord.items()
        if key != "__business__" and _coord_ga(key) == coord_ga
    ]
    return matches[0] if len(matches) == 1 else None


def _record_failure(coord, original_path, reason_code, reason):
    return {
        "coord": coord,
        "original_mapping_path": original_path,
        "status": "rejected",
        "reason_code": reason_code,
        "reason": reason,
        "snapshot_reused": False,
    }


def _write_evidence(report_dir, records):
    path = Path(report_dir) / "evidence" / "call_chain" / "dependency_source_alignment.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "java-upgrade-analyzer.dependency-source-alignment.v1",
        "summary": {
            "aligned": sum(1 for item in records if item.get("status") == "aligned"),
            "rejected": sum(1 for item in records if item.get("status") == "rejected"),
        },
        "items": records,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(path)


def align_dependency_source_mappings(report_dir, dependency_source_mappings, runtime_dependency_catalog):
    ref_records = load_step4_current_ref_records(report_dir)
    aligned_mappings = []
    allowed_classes_by_coord = {}
    records = []
    seen_alignments = set()

    for raw_mapping in dependency_source_mappings or []:
        coord, original_path = normalize_mapping(raw_mapping)
        if not coord or not original_path:
            records.append(_record_failure(coord, original_path, "dependency_source_mapping_invalid", "依赖源码映射格式无效"))
            continue
        ref_record, ref_error = resolve_unique_ref_record(coord, ref_records)
        if ref_error:
            records.append(_record_failure(coord, original_path, ref_error, "Step4 没有唯一确认该依赖当前版本对应的源码 ref"))
            continue
        runtime_item = _runtime_item_for_coord(coord, runtime_dependency_catalog)
        jar_path = str((runtime_item or {}).get("jar_path") or "").strip()
        if not jar_path or not Path(jar_path).is_file():
            records.append(_record_failure(coord, original_path, "runtime_jar_missing", "当前最终制品中缺少该依赖 JAR，无法校验源码范围"))
            continue

        source_git_root, stderr, rc = _run_git(original_path, "rev-parse", "--show-toplevel")
        if rc or not source_git_root:
            records.append(_record_failure(coord, original_path, "dependency_source_not_git_repo", stderr or "依赖源码目录不是 Git 工作区"))
            continue
        expected_repo = Path(ref_record["repo_path"]).resolve()
        actual_repo = Path(source_git_root).resolve()
        if expected_repo != actual_repo:
            records.append(_record_failure(coord, original_path, "dependency_source_repo_mismatch", "源码映射仓库与 Step4 ref 证据仓库不一致"))
            continue
        alignment_key = (
            coord,
            str(actual_repo),
            str(ref_record.get("module_rel_path") or "."),
            str(ref_record.get("current_ref") or ""),
        )
        if alignment_key in seen_alignments:
            continue
        seen_alignments.add(alignment_key)

        before = repository_fingerprint(actual_repo)
        if not before:
            records.append(_record_failure(coord, original_path, "dependency_source_workspace_unreadable", "无法读取依赖源码工作区状态"))
            continue
        try:
            snapshot = materialize_detached_snapshot(
                report_dir,
                coord,
                actual_repo,
                ref_record["current_ref"],
                ref_record.get("module_rel_path") or ".",
            )
            source_dirs = discover_standard_source_dirs(snapshot["module_root"])
            if not source_dirs:
                raise RuntimeError("dependency_source_main_sources_missing")
            jar_classes = index_jar_classes(jar_path)
            if not jar_classes:
                raise RuntimeError("runtime_jar_class_index_empty")
            source_classes = inventory_source_classes(source_dirs)
            retained_source_classes = {
                class_fqcn for class_fqcn in source_classes
                if source_class_present_in_jar(class_fqcn, jar_classes)
            }
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            reason_code = str(exc).split(":", 1)[0] or "dependency_source_alignment_failed"
            records.append(_record_failure(coord, original_path, reason_code, f"依赖源码版本无法与当前运行时 JAR 对齐：{exc}"))
            continue
        after = repository_fingerprint(actual_repo)
        if not _fingerprints_equal(before, after):
            records.append(_record_failure(coord, original_path, "dependency_source_workspace_changed", "创建隔离快照期间用户依赖源码工作区发生变化"))
            continue

        for source_dir in source_dirs:
            aligned_mappings.append(f"{coord}={source_dir}")
        allowed_classes_by_coord[coord] = jar_classes
        records.append({
            "coord": coord,
            "runtime_version": str((runtime_item or {}).get("version") or ""),
            "runtime_jar": jar_path,
            "original_mapping_path": original_path,
            "selected_ref": ref_record["current_ref"],
            "source_status": ref_record.get("source_status") or "",
            "remote": ref_record.get("remote") or "",
            "remote_ref": ref_record.get("remote_ref") or "",
            "commit": snapshot["commit"],
            "snapshot_path": snapshot["snapshot_path"],
            "module_rel_path": ref_record.get("module_rel_path") or ".",
            "source_dirs": source_dirs,
            "jar_class_count": len(jar_classes),
            "source_class_count": len(source_classes),
            "retained_source_class_count": len(retained_source_classes),
            "skipped_source_class_count": len(source_classes - retained_source_classes),
            "status": "aligned",
            "reason_code": "dependency_source_aligned",
            "reason": "依赖源码已固定到 Step4 确认的当前版本 commit，并受当前运行时 JAR 类范围约束",
            "snapshot_reused": bool(snapshot["snapshot_reused"]),
            "workspace_before": _public_fingerprint(before),
            "workspace_after": _public_fingerprint(after),
            "workspace_unchanged": True,
        })

    evidence_path = _write_evidence(report_dir, records)
    return {
        "mappings": aligned_mappings,
        "allowed_classes_by_coord": allowed_classes_by_coord,
        "records": records,
        "evidence_path": evidence_path,
    }
