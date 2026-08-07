#!/usr/bin/env python3
"""Pin dependency source mappings to Step4-confirmed current-version commits."""

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import time
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

from artifact_coordinates import artifact_classifier, artifact_ga
from compat import run_cmd
from path_runtime import (
    bounded_path_component,
    git_with_long_paths,
    make_short_temp_dir,
    runtime_storage_root,
)


def _run_git(repo_path, *args):
    stdout, stderr, rc = run_cmd(
        git_with_long_paths() + ["-C", str(repo_path), *args],
        timeout=60,
    )
    return stdout.strip(), stderr.strip(), rc


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
    status, _stderr, status_rc = _run_git(
        repo_path, "status", "--porcelain=v2", "--branch",
    )
    if status_rc:
        return None
    branch = ""
    head = ""
    dirty_entries = []
    for line in status.splitlines():
        if line.startswith("# branch.oid "):
            head = line[len("# branch.oid "):].strip()
        elif line.startswith("# branch.head "):
            branch = line[len("# branch.head "):].strip()
            if branch == "(detached)":
                branch = ""
        elif not line.startswith("# ") and line.strip():
            dirty_entries.append(line)
    if not _FULL_OBJECT_ID_RE.fullmatch(head):
        return None
    raw_status = "\n".join(dirty_entries)
    return {
        "branch": branch,
        "head": head.lower(),
        "status_sha256": hashlib.sha256(raw_status.encode("utf-8")).hexdigest(),
        "dirty_entry_count": len(dirty_entries),
        "_raw_status": raw_status,
    }


def _fingerprints_equal(before, after):
    if not before or not after:
        return False
    return all(before.get(key) == after.get(key) for key in ("branch", "head", "_raw_status"))


def _public_fingerprint(fingerprint):
    if not fingerprint:
        return {}
    return {key: value for key, value in fingerprint.items() if not key.startswith("_")}


_FULL_OBJECT_ID_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_SNAPSHOT_MARKER_NAME = ".jua-source-snapshot.json"
_SNAPSHOT_MARKER_SCHEMA = 2
_SNAPSHOT_PUBLISH_ATTEMPTS = 6
_SNAPSHOT_LOCK_TIMEOUT_SECONDS = 300


def _git_failure_detail(stderr, fallback):
    return str(stderr or "").strip() or str(fallback or "").strip()


def _resolve_commit(repo_path, ref):
    """Resolve a ref without turning an execution failure into "ref missing"."""
    failures = []
    revision = f"{ref}^{{commit}}"
    for _attempt in range(2):
        commit, stderr, rc = _run_git(
            repo_path,
            "rev-parse",
            "--verify",
            "--end-of-options",
            revision,
        )
        candidate = str(commit or "").strip()
        if rc == 0:
            if _FULL_OBJECT_ID_RE.fullmatch(candidate):
                return candidate.lower()
            raise RuntimeError(
                "dependency_source_ref_resolution_invalid:"
                + _git_failure_detail(stderr, "git rev-parse returned a non-object id")
            )
        failures.append((stderr, rc))

    last_stderr, last_rc = failures[-1]
    lowered = str(last_stderr or "").lower()
    if last_rc == -1:
        if "超时" in lowered or "timed out" in lowered or "timeout" in lowered:
            code = "dependency_source_ref_resolution_timeout"
        elif "命令未找到" in lowered or "not found" in lowered:
            code = "dependency_source_git_unavailable"
        else:
            code = "dependency_source_ref_resolution_failed"
        raise RuntimeError(
            f"{code}:{_git_failure_detail(last_stderr, ref)}"
        )

    _git_dir, health_stderr, health_rc = _run_git(
        repo_path, "rev-parse", "--git-dir",
    )
    if health_rc != 0:
        raise RuntimeError(
            "dependency_source_repository_unavailable:"
            + _git_failure_detail(health_stderr, last_stderr or repo_path)
        )
    raise RuntimeError(
        "dependency_source_ref_not_found:"
        + _git_failure_detail(last_stderr, ref)
    )


def _snapshot_content_manifest(snapshot, marker_name=_SNAPSHOT_MARKER_NAME):
    """Hash every cached entry so a matching commit marker is not trusted alone."""
    snapshot = Path(snapshot)
    digest = hashlib.sha256()
    entry_count = 0
    file_count = 0
    try:
        entries = sorted(
            snapshot.rglob("*"),
            key=lambda path: path.relative_to(snapshot).as_posix(),
        )
        for path in entries:
            relative = path.relative_to(snapshot).as_posix()
            if relative == marker_name:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise RuntimeError("dependency_source_snapshot_content_invalid")
            kind = b"D" if stat.S_ISDIR(mode) else b"F"
            digest.update(kind + b"\0" + relative.encode("utf-8") + b"\0")
            entry_count += 1
            if stat.S_ISREG(mode):
                file_count += 1
                size_before = path.stat().st_size
                digest.update(str(size_before).encode("ascii") + b"\0")
                with path.open("rb") as source:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                if path.stat().st_size != size_before:
                    raise RuntimeError("dependency_source_snapshot_content_changed")
                digest.update(b"\0")
    except OSError as exc:
        raise RuntimeError(
            f"dependency_source_snapshot_content_unreadable:{exc}"
        ) from exc
    return {
        "content_sha256": digest.hexdigest(),
        "entry_count": entry_count,
        "file_count": file_count,
    }


def _validate_snapshot(snapshot, commit, marker_name=_SNAPSHOT_MARKER_NAME):
    snapshot = Path(snapshot)
    if not os.path.lexists(snapshot):
        return False, "missing"
    if snapshot.is_symlink() or not snapshot.is_dir():
        return False, "snapshot_not_directory"
    marker = snapshot / marker_name
    try:
        if marker.is_symlink() or not marker.is_file():
            return False, "marker_missing"
        marker_payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "marker_unreadable"
    if (
        marker_payload.get("schema") != _SNAPSHOT_MARKER_SCHEMA
        or marker_payload.get("commit") != commit
    ):
        return False, "marker_identity_mismatch"
    try:
        actual = _snapshot_content_manifest(snapshot, marker_name)
    except RuntimeError as exc:
        return False, str(exc).split(":", 1)[0]
    for field in ("content_sha256", "entry_count", "file_count"):
        if marker_payload.get(field) != actual[field]:
            return False, f"marker_{field}_mismatch"
    return True, ""


def _remove_cache_entry(path):
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


@contextmanager
def _snapshot_cache_lock(snapshot):
    """Serialize validation/repair/publication, including across processes."""
    snapshot = Path(snapshot)
    lock_path = snapshot.with_name(f".{snapshot.name}.lock")
    try:
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise RuntimeError(
            f"dependency_source_snapshot_lock_failed:{exc}"
        ) from exc
    locked = False
    windows_lock = None
    posix_lock = None
    try:
        if os.name == "nt":
            import msvcrt

            windows_lock = msvcrt
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + _SNAPSHOT_LOCK_TIMEOUT_SECONDS
            while True:
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "dependency_source_snapshot_lock_timeout"
                        ) from exc
                    time.sleep(0.1)
        else:
            try:
                import fcntl
            except ImportError as exc:
                raise RuntimeError(
                    "dependency_source_snapshot_lock_unsupported"
                ) from exc

            posix_lock = fcntl
            deadline = time.monotonic() + _SNAPSHOT_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(
                        handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    locked = True
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise RuntimeError(
                            f"dependency_source_snapshot_lock_failed:{exc}"
                        ) from exc
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "dependency_source_snapshot_lock_timeout"
                        ) from exc
                    time.sleep(0.1)
        yield
    finally:
        if locked:
            try:
                if windows_lock is not None:
                    handle.seek(0)
                    windows_lock.locking(handle.fileno(), windows_lock.LK_UNLCK, 1)
                elif posix_lock is not None:
                    posix_lock.flock(handle.fileno(), posix_lock.LOCK_UN)
            except OSError:
                pass
        handle.close()


def _quarantine_invalid_snapshot(snapshot):
    """Atomically move one invalid entry away; concurrent repairers may race."""
    snapshot = Path(snapshot)
    quarantine = snapshot.with_name(
        f".{snapshot.name}.invalid-{uuid.uuid4().hex}"
    )
    try:
        snapshot.rename(quarantine)
    except FileNotFoundError:
        return False
    except OSError as exc:
        if not os.path.lexists(snapshot):
            return False
        raise RuntimeError(
            f"dependency_source_snapshot_repair_failed:{exc}"
        ) from exc
    _remove_cache_entry(quarantine)
    return True


def _create_snapshot_payload(temporary, repo_path, commit, marker_name):
    temporary = Path(temporary)
    payload = temporary / "payload"
    payload.mkdir()
    archive_path = temporary / "snapshot.zip"
    last_stderr = ""
    last_rc = 0
    for _attempt in range(2):
        try:
            archive_path.unlink()
        except FileNotFoundError:
            pass
        _stdout, last_stderr, last_rc = run_cmd(
            git_with_long_paths() + [
                "-C", str(repo_path), "archive", "--format=zip",
                f"--output={archive_path}", commit,
            ],
            timeout=120,
        )
        if last_rc == 0 and archive_path.is_file():
            break
    else:
        lowered = str(last_stderr or "").lower()
        if last_rc == -1 and (
            "超时" in lowered or "timed out" in lowered or "timeout" in lowered
        ):
            code = "dependency_source_snapshot_git_archive_timeout"
        elif last_rc == -1:
            code = "dependency_source_snapshot_git_archive_unavailable"
        elif last_rc == 0:
            code = "dependency_source_snapshot_git_archive_output_missing"
        else:
            code = "dependency_source_snapshot_git_archive_failed"
        raise RuntimeError(
            f"{code}:"
            + _git_failure_detail(
                last_stderr,
                f"git archive exited with code {last_rc}",
            )
        )

    try:
        with zipfile.ZipFile(archive_path) as archive:
            extract_zip_safely(archive, payload)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(
            f"dependency_source_snapshot_archive_invalid:{exc}"
        ) from exc
    if os.path.lexists(payload / marker_name):
        raise RuntimeError("dependency_source_snapshot_reserved_path_conflict")
    manifest = _snapshot_content_manifest(payload, marker_name)
    marker_payload = {
        "schema": _SNAPSHOT_MARKER_SCHEMA,
        "commit": commit,
        **manifest,
    }
    (payload / marker_name).write_text(
        json.dumps(marker_payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def materialize_detached_snapshot(report_dir, coord, repo_path, ref, module_rel_path):
    commit = _resolve_commit(repo_path, ref)
    snapshot = (
        runtime_storage_root(report_dir, "source_snapshots")
        / _safe_coord(coord)
        / commit
    )
    marker_name = _SNAPSHOT_MARKER_NAME
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    reused = False
    published = False
    last_validation_error = "missing"
    with _snapshot_cache_lock(snapshot):
        for _attempt in range(_SNAPSHOT_PUBLISH_ATTEMPTS):
            valid, last_validation_error = _validate_snapshot(
                snapshot, commit, marker_name,
            )
            if valid:
                reused = not published
                break
            if os.path.lexists(snapshot):
                _quarantine_invalid_snapshot(snapshot)
                continue

            # `git worktree add` leaves a reverse registration in the user's
            # repository.  Archive the exact commit instead: the source bytes are
            # the same tracked revision and the user's repository is never mutated.
            temporary = make_short_temp_dir(
                prefix=f"source-{commit[:8]}",
                preferred_root=snapshot.parent,
                strict_preferred=True,
            )
            try:
                payload = _create_snapshot_payload(
                    temporary, repo_path, commit, marker_name,
                )
                try:
                    payload.rename(snapshot)
                    published = True
                except OSError as exc:
                    # A process from an older build may not honor this lock but
                    # can still win the atomic rename. Validate its publication
                    # on the next iteration instead of reporting a false error.
                    if not os.path.lexists(snapshot):
                        raise RuntimeError(
                            f"dependency_source_snapshot_publish_failed:{exc}"
                        ) from exc
            finally:
                shutil.rmtree(temporary, ignore_errors=True)
        else:
            raise RuntimeError(
                "dependency_source_snapshot_cache_unstable:"
                + last_validation_error
            )

        valid, validation_error = _validate_snapshot(snapshot, commit, marker_name)
        if not valid:
            raise RuntimeError(
                "dependency_source_snapshot_validation_failed:"
                + validation_error
            )

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
        if rc:
            reason_code = (
                "dependency_source_git_unavailable"
                if rc == -1
                else "dependency_source_repository_discovery_failed"
            )
            records.append(_record_failure(
                coord,
                original_path,
                reason_code,
                stderr or "Git 无法确定依赖源码仓库根目录",
            ))
            continue
        if not source_git_root:
            records.append(_record_failure(
                coord,
                original_path,
                "dependency_source_repository_discovery_invalid",
                "Git 成功退出但没有返回依赖源码仓库根目录",
            ))
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
        if not after:
            records.append(_record_failure(
                coord,
                original_path,
                "dependency_source_workspace_recheck_failed",
                "创建隔离快照后无法重新读取依赖源码工作区状态",
            ))
            continue
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
