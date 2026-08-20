#!/usr/bin/env python3
"""Immutable whole-generation output writer for the binary authority pipeline."""

from __future__ import annotations

import csv
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
from typing import Any, Callable, Iterable, Mapping, MutableMapping

from binary_decision_engine import BinaryDecisionBundle
from binary_first_contract import (
    BinaryFirstContractError,
    canonical_identity,
    canonical_identity_streaming,
)
from binary_first_model import ResultGeneration, RuntimeProfile
from binary_source_overlay import SourceOverlayResult
from binary_trace_engine import BinaryTraceBundle
from binary_validation_contract import (
    VALIDATION_POLICY_VERSION,
)
from csv_io import open_csv_write
from path_runtime import make_short_temp_dir
from process_lock import exclusive_file_lock
from signature_utils import jvm_method_parameter_signature
from streaming_json import (
    fsync_directory as _fsync_directory_durable,
    write_json_streaming,
)


EDGE_KIND_LABELS = {
    "method": "字节码方法调用",
    "field": "字节码字段访问",
    "type": "字节码类型引用",
    "class_initialization": "类初始化",
    "invokedynamic_handle": "InvokeDynamic 方法句柄候选调用",
    "invokedynamic_bootstrap": "InvokeDynamic 引导方法候选调用",
    "reflection_method_invocation": "反射方法调用",
    "reflection_constructor_invocation": "反射构造调用",
    "reflection_field_access": "反射字段访问",
    "method_handle_invocation": "MethodHandle 调用",
    "method_handle_field_access": "MethodHandle 字段访问",
    "dynamic_proxy_callback": "JDK 动态代理回调",
    "mybatis_mapper_proxy_dispatch": "MyBatis Mapper 代理分派",
    "spring_transaction_proxy_dispatch": "Spring 事务代理分派",
    "spring_bean_wiring_dispatch": "Spring Bean 注入分派",
    "spring_data_repository_proxy_dispatch": "Spring Data 仓库代理分派",
    "spring_aop_dispatch": "Spring AOP 切面分派",
    "spring_security_filter_dispatch": "Spring Security 过滤器链",
    "declarative_http_client_dispatch": "声明式 HTTP 客户端分派",
    "dubbo_spi_dispatch": "Dubbo SPI 扩展分派",
    "implicit_data_contract_dispatch": "序列化/绑定数据契约",
}


_INDEPENDENT_VALIDATION_POLICY_VERSION = VALIDATION_POLICY_VERSION
_RESULT_GENERATION_SCHEMA = "java-upgrade-analyzer.binary-result-generation.v1"
_ACTIVE_DESCRIPTOR_LOCK_TIMEOUT_SECONDS = 5.0
_ACTIVE_DESCRIPTOR_SCHEMA = "java-upgrade-analyzer.active-binary-generation.v1"
_PUBLICATION_AUTHORITY_SIDECAR = "binary_publication_authority.json"
_PUBLICATION_AUTHORITY_SCHEMA = (
    "java-upgrade-analyzer.binary-publication-authority.v1"
)
_PERFORMANCE_AUTHORITY_BINDING_FIELDS = frozenset({
    "schema",
    "authority_mode",
    "support_contract_identity",
    "evidence_sha256",
    "source_implementation_identity",
    "binding_identity",
})
_PUBLICATION_REAUTHORIZATION_SCHEMA = (
    "java-upgrade-analyzer.binary-publication-reauthorization.v1"
)
_PUBLICATION_REAUTHORIZATION_FIELDS = frozenset({
    "schema",
    "result_generation_identity",
    "validation_run_identity",
    "validation_result_sha256",
    "activation_identity",
    "generation_performance_authority_binding",
    "current_performance_authority_binding",
    "reauthorization_identity",
})
_RELEASE_RECAPTURE_AUTHORITY_MODE = "release_recapture_measurement"
_RELEASE_RECAPTURE_PUBLICATION_CAPABILITY = object()
_RELEASE_RECAPTURE_PUBLICATION_CONTEXT: ContextVar[
    tuple[object, Path] | None
] = ContextVar("binary_release_recapture_publication", default=None)
_DIRECT_SEAL_FAST_PATH_CONTEXT: ContextVar[object | None] = ContextVar(
    "binary_direct_seal_fast_path", default=None
)
_INTEGRITY_PROOF_CAPTURE_CONTEXT: ContextVar[object | None] = ContextVar(
    "binary_integrity_proof_capture", default=None
)
_INTEGRITY_PROOF_RESULT_CONTEXT: ContextVar[object | None] = ContextVar(
    "binary_integrity_proof_result", default=None
)
_INTEGRITY_PROOF_CAPTURE_CAPABILITY = object()
_CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY = object()
_DIRECT_SEAL_FAST_PATH_LOCK = threading.Lock()
_DIRECT_SEAL_FAST_PATH_MAX_ENTRIES = 64
_DIRECT_SEAL_FAST_PATH_REGISTRY: dict[object, "_DirectSealCapability"] = {}
_DIRECT_SEAL_FAST_PATH_BY_OPERATION: dict[tuple[Any, ...], object] = {}
_DIRECT_SEAL_FAST_PATH_SEQUENCE = 0
_DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE: dict[int, bool] = {}
_DIRECT_SEAL_CTIME_SUPPORT_MAX_DEVICES = 32
_GENERATION_ATTACHMENT_POLICY = (
    "trace-results-content-bound-in-generation-sidecars-v2"
)
_RESULT_GENERATION_SNAPSHOT_LAYERS = frozenset({
    "decision",
    "assessment",
    "formal_projection",
    "candidate_projection",
})
_REQUIRED_CORE_GENERATION_SIDECARS = frozenset({
    "binary_decisions.json",
    "binary_projections.json",
    "binary_formal_results.json",
    "binary_candidate_results.json",
    "binary_entrypoints.json",
    "binary_coverage.json",
    "binary_summary.json",
    "binary_formal_results.csv",
})
_TRANSIENT_FACT_STORE_SIDECARS = frozenset({
    f"{name}{suffix}"
    for name in ("base_binary_facts.sqlite", "current_binary_facts.sqlite")
    for suffix in ("-wal", "-shm", "-journal")
})
_VALIDATION_V3_FIELDS = {
    "schema",
    "validation_run_identity",
    "result_generation_identity",
    "oracle_support_manifest_identity",
    "truth_set_identity",
    "issue_set_identity",
    "validation_policy_version",
    "validator_implementation_identity",
    "status",
    "issue_count",
    "issues",
    "domain_summary",
    "helper_identities",
    "skipped_domains",
    "production_identity_influence",
}
_GENERATION_METADATA_MAX_BYTES = 16 * 1024 * 1024


_StatSnapshot = tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _GenerationIntegrityProof:
    publication_authority_bytes: bytes | None
    directory_snapshots: tuple[tuple[Path, _StatSnapshot], ...]
    file_snapshots: tuple[tuple[Path, _StatSnapshot], ...]


@dataclass(frozen=True, slots=True)
class _TransactionDescriptorProof:
    file_snapshot: _StatSnapshot | None
    parent_snapshot: _StatSnapshot


@dataclass(frozen=True, slots=True)
class _DirectSealCapability:
    sequence: int
    owner_process_identity: int
    owner_thread_identity: int
    canonical_root: Path
    root_identity: tuple[int, int]
    probed_device: int
    operation_key: tuple[Any, ...]
    result_generation_identity: str
    validation_run_identity: str
    validation_result_sha256: str
    activation_identity: str
    unsealed_descriptor_bytes: bytes
    predecessor_bytes: bytes | None
    descriptor_before_identity: tuple[int, int] | None
    descriptor_after_identity: tuple[int, int]
    descriptor_snapshot: _StatSnapshot
    publication_authority_bytes: bytes | None
    directory_snapshots: tuple[tuple[Path, _StatSnapshot], ...]
    file_snapshots: tuple[tuple[Path, _StatSnapshot], ...]


def _public_edge_kind(kind: str) -> str:
    if kind.startswith("invokedynamic_handle_"):
        return "invokedynamic_handle"
    if kind.startswith("ldc_bootstrap_handle_"):
        return "constant_dynamic_handle"
    return kind


ENTRY_KIND_LABELS = {
    "declared_runtime_entry": "用户声明的运行入口",
    "java_main": "Java 主程序入口",
    "spring_scheduled": "Spring 定时任务",
    "spring_xml_scheduled": "Spring XML 定时任务",
    "spring_xml_quartz": "Spring XML Quartz 定时任务",
    "spring_event_listener": "Spring 事件监听",
    "spring_message_listener": "消息监听",
    "lifecycle_callback": "组件初始化回调",
    "jpa_lifecycle_callback": "JPA 生命周期回调",
    "spring_web_endpoint": "HTTP 接口入口",
    "spring_bean_initialization": "Spring Bean 初始化",
    "spring_application_runner": "Spring ApplicationRunner 启动回调",
    "spring_command_line_runner": "Spring CommandLineRunner 启动回调",
    "spring_application_listener": "Spring ApplicationListener 事件回调",
    "spring_environment_post_processor": "Spring 环境后处理回调",
    "spring_application_context_initializer": "Spring 上下文初始化回调",
    "spring_lifecycle_callback": "Spring 生命周期回调",
    "spring_web_interceptor": "Spring Web 拦截器回调",
    "spring_conversion_callback": "Spring 类型转换回调",
    "servlet_endpoint": "Servlet 请求入口",
    "servlet_filter": "Servlet 过滤器入口",
    "servlet_lifecycle_callback": "Servlet 生命周期回调",
    "quartz_job": "Quartz 定时任务",
}


class BinaryOutputError(BinaryFirstContractError):
    pass


class _ActiveGenerationLockAcquireTimeout(TimeoutError):
    """Distinguish lock acquisition from a TimeoutError raised by its body."""


@contextmanager
def _active_generation_lock(root: Path):
    manager = exclusive_file_lock(
        root / ".active-generation.lock",
        timeout_seconds=_ACTIVE_DESCRIPTOR_LOCK_TIMEOUT_SECONDS,
    )
    try:
        manager.__enter__()
    except TimeoutError as error:
        raise _ActiveGenerationLockAcquireTimeout(str(error)) from error
    except OSError as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_UNAVAILABLE",
            f"{root / '.active-generation.lock'}: {error}",
        ) from error
    try:
        yield
    finally:
        manager.__exit__(*sys.exc_info())


def _add_cleanup_note(primary: BaseException, note: str) -> None:
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        try:
            add_note(note)
            return
        except Exception:
            pass
    try:
        notes = list(getattr(primary, "__notes__", ()) or ())
        notes.append(note)
        setattr(primary, "__notes__", notes)
    except Exception:
        pass


def _finish_cleanups(
    primary: BaseException | None,
    errors: Iterable[tuple[str, BaseException]],
) -> None:
    failures = list(errors)
    if not failures:
        return
    if primary is not None:
        for label, error in failures:
            _add_cleanup_note(
                primary,
                f"cleanup failed ({label}): {type(error).__name__}: {error}",
            )
        return
    first_label, first = failures[0]
    for label, error in failures[1:]:
        _add_cleanup_note(
            first,
            f"additional cleanup failed ({label}): {type(error).__name__}: {error}",
        )
    _add_cleanup_note(first, f"cleanup operation: {first_label}")
    raise first


def _attempt_cleanups(
    actions: Iterable[tuple[str, Callable[[], None]]],
    *,
    primary: BaseException | None,
) -> None:
    errors = []
    for label, action in actions:
        try:
            action()
        except BaseException as error:
            errors.append((label, error))
    _finish_cleanups(primary, errors)


def _unlink_missing_ok(path: str | Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _rmtree_missing_ok(path: str | Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256_identity(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_safe_sidecar_basename(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and Path(value).name == value
    )


def _fsync_directory(path: Path) -> bool:
    """Synchronize a directory or explicitly report host non-support."""

    return _fsync_directory_durable(path)


def _fsync_regular_file(path: Path) -> None:
    """Synchronize one already-validated generation file without following links."""

    # CPython implements os.fsync with the Windows CRT ``_commit`` call.
    # Unlike POSIX fsync, _commit rejects a descriptor opened read-only with
    # EBADF.  Generation files are owned writable files at this point, so use
    # a read/write descriptor only on Windows and retain the narrower POSIX
    # access mode everywhere else.
    flags = (
        (os.O_RDWR if os.name == "nt" else os.O_RDONLY)
        | int(getattr(os, "O_NOFOLLOW", 0) or 0)
        | int(getattr(os, "O_BINARY", 0) or 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise BinaryOutputError(
                "BINARY_GENERATION_DURABILITY_TARGET_INVALID", str(path)
            )
        os.fsync(descriptor)
    finally:
        primary = sys.exc_info()[1]
        _attempt_cleanups(
            ((f"close durability descriptor for {path}", lambda: os.close(descriptor)),),
            primary=primary,
        )


def _make_generation_durable(
    generation: Path,
    relative_files: Iterable[str | Path],
    *,
    nested_directories: Iterable[Path] = (),
) -> None:
    """Order immutable bytes and directory entries before active publication."""

    for relative in sorted({Path(value) for value in relative_files}, key=str):
        if relative.is_absolute() or ".." in relative.parts:
            raise BinaryOutputError(
                "BINARY_GENERATION_DURABILITY_TARGET_INVALID", str(relative)
            )
        _fsync_regular_file(generation / relative)
    # Child directory contents must be durable before the generation entry and
    # its binary_generations parent.  Sort deepest first for future nesting.
    for directory in sorted(
        {Path(value) for value in nested_directories},
        key=lambda value: (-len(value.parts), str(value)),
    ):
        _fsync_directory(directory)
    _fsync_directory(generation)
    _fsync_directory(generation.parent)


def _descriptor_file_identity(value: os.stat_result) -> tuple[int, int]:
    return (int(value.st_dev), int(value.st_ino))


def _regular_file_snapshot(value: os.stat_result) -> _StatSnapshot:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        # Windows may expose different creation/change-time values for lstat
        # and fstat on the same file.  It is not a stable cross-API identity;
        # content hashes, inode/device, size and mtime remain enforced.
        0 if os.name == "nt" else int(value.st_ctime_ns),
    )


def _directory_snapshot(path: Path) -> _StatSnapshot:
    try:
        observed = os.lstat(path)
    except OSError as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"{path}: {error}",
        ) from error
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"generation path is not a private directory: {path}",
        )
    return _regular_file_snapshot(observed)


def _canonical_physical_output_root(
    output_root: str | Path,
    *,
    reason_code: str,
    create: bool = False,
) -> Path:
    """Canonicalize ancestors while refusing to follow the owned root leaf."""

    requested = Path(output_root).expanduser()
    if requested.name in {"", ".", ".."}:
        raise BinaryOutputError(
            reason_code, f"{requested}: output root must name a dedicated leaf"
        )
    try:
        if create:
            # Preserve first-run support for a multi-level missing output path
            # without using mkdir(parents=True), whose leaf checks follow
            # attacker- or crash-installed links.  Resolve the nearest existing
            # ancestor once, then create and lstat every owned directory leaf.
            missing_parent_names: list[str] = []
            ancestor = requested.parent
            while True:
                try:
                    physical_parent = ancestor.resolve(strict=True)
                    break
                except FileNotFoundError:
                    if ancestor == ancestor.parent or ancestor.name in {
                        "", ".", ".."
                    }:
                        raise
                    missing_parent_names.append(ancestor.name)
                    ancestor = ancestor.parent
            physical_parent_stat = os.lstat(physical_parent)
            if not stat.S_ISDIR(physical_parent_stat.st_mode):
                raise OSError(
                    f"existing output ancestor is not a directory: "
                    f"{physical_parent}"
                )
            for name in reversed(missing_parent_names):
                child = physical_parent / name
                try:
                    os.mkdir(child, 0o700)
                except FileExistsError:
                    pass
                child_stat = os.lstat(child)
                if stat.S_ISLNK(child_stat.st_mode) or not stat.S_ISDIR(
                    child_stat.st_mode
                ):
                    raise OSError(
                        f"output ancestor is not a physical directory: "
                        f"{child}"
                    )
                physical_parent = child
        else:
            physical_parent = requested.parent.resolve(strict=True)
        root = physical_parent / requested.name
        try:
            observed = os.lstat(root)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(root, 0o700)
            except FileExistsError:
                pass
            observed = os.lstat(root)
    except (OSError, RuntimeError) as error:
        raise BinaryOutputError(
            reason_code, f"{requested}: cannot inspect output root: {error}"
        ) from error
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise BinaryOutputError(
            reason_code, f"{root}: output root is not a physical directory"
        )
    return root


def _physical_generation_namespace(
    root: Path,
    *,
    create: bool,
    reason_code: str,
) -> Path:
    """Return the owned generation namespace without following its leaf."""

    generations = root / "binary_generations"
    try:
        if create:
            try:
                os.mkdir(generations, 0o700)
            except FileExistsError:
                pass
        observed = os.lstat(generations)
        resolved = generations.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BinaryOutputError(
            reason_code,
            f"{generations}: cannot inspect generation namespace: {error}",
        ) from error
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or resolved != generations
        or generations.parent != root
    ):
        raise BinaryOutputError(
            reason_code,
            f"{generations}: generation namespace is not a physical directory",
        )
    return generations


def _physical_generation_directory(
    generations: Path,
    generation_identity: str,
    *,
    reason_code: str,
) -> Path:
    """Resolve one exact content-addressed leaf without following a link."""

    generation = generations / generation_identity
    if not _is_sha256_identity(generation_identity):
        raise BinaryOutputError(reason_code, str(generation_identity))
    try:
        observed = os.lstat(generation)
        resolved = generation.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BinaryOutputError(
            reason_code,
            f"{generation}: cannot inspect generation directory: {error}",
        ) from error
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or resolved != generation
        or generation.parent != generations
    ):
        raise BinaryOutputError(
            reason_code,
            f"{generation}: generation is not a physical content-addressed directory",
        )
    return generation


def _read_stable_generation_file(
    path: Path,
    *,
    expected_sha256: str = "",
    capture_content: bool = False,
) -> tuple[str, bytes | None, _StatSnapshot]:
    """Hash one regular file from a stable descriptor without following links."""

    descriptor = None
    try:
        initial = os.lstat(path)
        if (
            stat.S_ISLNK(initial.st_mode)
            or not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
        ):
            raise OSError("not a private regular file")
        expected_snapshot = _regular_file_snapshot(initial)
        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or current.st_nlink != 1
            or _regular_file_snapshot(opened) != expected_snapshot
            or _regular_file_snapshot(current) != expected_snapshot
        ):
            raise OSError("file changed while opening")
        digest = hashlib.sha256()
        captured = bytearray() if capture_content else None
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            if captured is not None:
                if len(captured) + len(block) > _GENERATION_METADATA_MAX_BYTES:
                    raise OSError("metadata file exceeds the bounded read limit")
                captured.extend(block)
        final_opened = os.fstat(descriptor)
        final_path = os.lstat(path)
        if (
            final_opened.st_nlink != 1
            or final_path.st_nlink != 1
            or _regular_file_snapshot(final_opened) != expected_snapshot
            or _regular_file_snapshot(final_path) != expected_snapshot
        ):
            raise OSError("file changed while reading")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 and actual_sha256 != expected_sha256:
            raise OSError(
                "content digest mismatch: "
                f"expected={expected_sha256}; actual={actual_sha256}"
            )
        return (
            actual_sha256,
            bytes(captured) if captured is not None else None,
            expected_snapshot,
        )
    except BinaryOutputError:
        raise
    except OSError as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"{path}: {error}",
        ) from error
    finally:
        if descriptor is not None:
            _attempt_cleanups(
                ((f"close generation descriptor for {path}", lambda: os.close(descriptor)),),
                primary=sys.exc_info()[1],
            )


def _assert_generation_snapshot_unchanged(
    file_snapshots: Mapping[Path, _StatSnapshot],
    directory_snapshots: Mapping[Path, _StatSnapshot],
) -> None:
    try:
        for path, expected in directory_snapshots.items():
            if _directory_snapshot(path) != expected:
                raise OSError(f"generation directory changed: {path}")
        for path, expected in file_snapshots.items():
            current = os.lstat(path)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or _regular_file_snapshot(current) != expected
            ):
                raise OSError(f"generation file changed: {path}")
    except BinaryOutputError:
        raise
    except OSError as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", str(error)
        ) from error


def _direct_seal_operation_key(
    root: Path,
    root_identity: tuple[int, int],
    *,
    result_generation_identity: str,
    validation_run_identity: str,
    validation_result_sha256: str,
    activation_identity: str,
) -> tuple[Any, ...]:
    return (
        str(root),
        *root_identity,
        result_generation_identity,
        validation_run_identity,
        validation_result_sha256,
        activation_identity,
    )


def _remove_direct_seal_capability_locked(token: object) -> None:
    capability = _DIRECT_SEAL_FAST_PATH_REGISTRY.pop(token, None)
    if (
        capability is not None
        and _DIRECT_SEAL_FAST_PATH_BY_OPERATION.get(
            capability.operation_key
        ) is token
    ):
        _DIRECT_SEAL_FAST_PATH_BY_OPERATION.pop(
            capability.operation_key, None
        )


def _reset_direct_seal_fast_path_after_fork() -> None:
    """A child must not inherit tokens or a lock held by a vanished thread."""

    global _DIRECT_SEAL_FAST_PATH_LOCK
    global _DIRECT_SEAL_FAST_PATH_SEQUENCE

    _DIRECT_SEAL_FAST_PATH_LOCK = threading.Lock()
    _DIRECT_SEAL_FAST_PATH_REGISTRY.clear()
    _DIRECT_SEAL_FAST_PATH_BY_OPERATION.clear()
    _DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.clear()
    _DIRECT_SEAL_FAST_PATH_SEQUENCE = 0
    _DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
    _INTEGRITY_PROOF_CAPTURE_CONTEXT.set(None)
    _INTEGRITY_PROOF_RESULT_CONTEXT.set(None)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_direct_seal_fast_path_after_fork)


def _discard_current_direct_seal_capability() -> None:
    """Drop the current opaque token and its registry entry, if any."""

    token = _DIRECT_SEAL_FAST_PATH_CONTEXT.get()
    _DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
    if token is None:
        return
    with _DIRECT_SEAL_FAST_PATH_LOCK:
        _remove_direct_seal_capability_locked(token)


def _invalidate_direct_seal_capabilities_for_root(root: Path) -> None:
    """Invalidate all receipts that a new descriptor operation can supersede."""

    context_token = _DIRECT_SEAL_FAST_PATH_CONTEXT.get()
    _DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
    with _DIRECT_SEAL_FAST_PATH_LOCK:
        if context_token is not None:
            _remove_direct_seal_capability_locked(context_token)
        for token, capability in tuple(
            _DIRECT_SEAL_FAST_PATH_REGISTRY.items()
        ):
            if capability.canonical_root == root:
                _remove_direct_seal_capability_locked(token)


def _install_direct_seal_capability(
    capability: _DirectSealCapability,
) -> None:
    """Install one bounded, module-owned, current-context capability."""

    global _DIRECT_SEAL_FAST_PATH_SEQUENCE

    _discard_current_direct_seal_capability()
    token = object()
    with _DIRECT_SEAL_FAST_PATH_LOCK:
        previous = _DIRECT_SEAL_FAST_PATH_BY_OPERATION.get(
            capability.operation_key
        )
        if previous is not None:
            _remove_direct_seal_capability_locked(previous)
        while (
            len(_DIRECT_SEAL_FAST_PATH_REGISTRY)
            >= _DIRECT_SEAL_FAST_PATH_MAX_ENTRIES
        ):
            oldest = min(
                _DIRECT_SEAL_FAST_PATH_REGISTRY,
                key=lambda value: (
                    _DIRECT_SEAL_FAST_PATH_REGISTRY[value].sequence
                ),
            )
            _remove_direct_seal_capability_locked(oldest)
        _DIRECT_SEAL_FAST_PATH_SEQUENCE += 1
        installed = replace(
            capability, sequence=_DIRECT_SEAL_FAST_PATH_SEQUENCE
        )
        _DIRECT_SEAL_FAST_PATH_REGISTRY[token] = installed
        _DIRECT_SEAL_FAST_PATH_BY_OPERATION[
            installed.operation_key
        ] = token
    _DIRECT_SEAL_FAST_PATH_CONTEXT.set(token)


def _consume_direct_seal_capability(
    root: Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
    current: Mapping[str, Any] | None,
) -> _DirectSealCapability | None:
    """Atomically consume an exact operation capability across all contexts."""

    context_token = _DIRECT_SEAL_FAST_PATH_CONTEXT.get()
    _DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
    try:
        observed_root = _directory_snapshot(root)
    except BinaryOutputError:
        observed_root = None
    root_identity = (
        (observed_root[0], observed_root[1])
        if observed_root is not None else None
    )
    operation_key = None
    if (
        root_identity is not None
        and isinstance(current, Mapping)
        and _is_sha256_identity(current.get("validation_run_identity"))
        and _is_sha256_identity(current.get("validation_result_sha256"))
    ):
        operation_key = _direct_seal_operation_key(
            root,
            root_identity,
            result_generation_identity=expected_current_identity,
            validation_run_identity=current["validation_run_identity"],
            validation_result_sha256=current["validation_result_sha256"],
            activation_identity=expected_activation_identity,
        )

    selected = None
    with _DIRECT_SEAL_FAST_PATH_LOCK:
        operation_token = (
            _DIRECT_SEAL_FAST_PATH_BY_OPERATION.get(operation_key)
            if operation_key is not None else None
        )
        if (
            operation_token is not None
            and operation_token is context_token
        ):
            selected = _DIRECT_SEAL_FAST_PATH_REGISTRY.get(operation_token)

        tokens = {
            token
            for token, capability in _DIRECT_SEAL_FAST_PATH_REGISTRY.items()
            if (
                capability.canonical_root == root
                and capability.result_generation_identity
                == expected_current_identity
                and capability.activation_identity
                == expected_activation_identity
            )
        }
        if context_token is not None:
            tokens.add(context_token)
        if operation_token is not None:
            tokens.add(operation_token)
        for token in tokens:
            _remove_direct_seal_capability_locked(token)
    return selected


def _probe_ctime_change_detection(root: Path, expected_device: int) -> bool:
    """Prove same-size writes remain visible after restoring mtime."""

    descriptor = None
    probe_path: Path | None = None
    supported = False
    cleanup_ok = True
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=".binary-seal-ctime-probe-", dir=root
        )
        probe_path = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        original = b"0" * 64
        changed = b"1" * 64
        if os.write(descriptor, original) != len(original):
            raise OSError("short probe write")
        os.fsync(descriptor)
        baseline = os.fstat(descriptor)
        if (
            not stat.S_ISREG(baseline.st_mode)
            or baseline.st_dev != expected_device
            or baseline.st_nlink != 1
            or baseline.st_size != len(original)
        ):
            raise OSError("probe is not a private file on the expected device")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.write(descriptor, changed) != len(changed):
            raise OSError("short in-place probe write")
        os.fsync(descriptor)
        os.utime(
            probe_path,
            ns=(baseline.st_atime_ns, baseline.st_mtime_ns),
            follow_symlinks=False,
        )
        final_descriptor = os.fstat(descriptor)
        final_path = os.lstat(probe_path)
        supported = bool(
            _regular_file_snapshot(final_descriptor)
            == _regular_file_snapshot(final_path)
            and final_descriptor.st_dev == expected_device
            and final_descriptor.st_nlink == 1
            and final_descriptor.st_size == baseline.st_size
            and final_descriptor.st_mtime_ns == baseline.st_mtime_ns
            and final_descriptor.st_ctime_ns != baseline.st_ctime_ns
        )
    except (OSError, OverflowError, ValueError):
        supported = False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                cleanup_ok = False
        if probe_path is not None:
            try:
                probe_path.unlink(missing_ok=True)
            except (BinaryOutputError, OSError):
                cleanup_ok = False
    return bool(supported and cleanup_ok)


def _filesystem_supports_direct_seal_fast_path(
    root: Path, expected_device: int
) -> bool:
    if os.name != "posix":
        return False
    try:
        if _directory_snapshot(root)[0] != expected_device:
            return False
    except BinaryOutputError:
        return False
    with _DIRECT_SEAL_FAST_PATH_LOCK:
        cached = _DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.get(expected_device)
        if cached is not None:
            return cached
        supported = _probe_ctime_change_detection(root, expected_device)
        if (
            len(_DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE)
            >= _DIRECT_SEAL_CTIME_SUPPORT_MAX_DEVICES
        ):
            oldest_device = next(iter(
                _DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE
            ))
            _DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.pop(oldest_device, None)
        _DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE[expected_device] = supported
        return supported


def _publication_authority_binding_is_valid(value: Any) -> bool:
    return bool(
        type(value) is dict
        and set(value) == _PERFORMANCE_AUTHORITY_BINDING_FIELDS
        and type(value.get("schema")) is str
        and value.get("schema")
        == "java-upgrade-analyzer.performance-authority-binding.v2"
        and type(value.get("authority_mode")) is str
        and value.get("authority_mode") in {
            "release_evidence",
            "candidate_source_measurement",
            _RELEASE_RECAPTURE_AUTHORITY_MODE,
        }
        and all(
            type(value.get(field)) is str
            and _is_sha256_identity(value.get(field))
            for field in _PERFORMANCE_AUTHORITY_BINDING_FIELDS
            - {"schema", "authority_mode"}
        )
        and value.get("binding_identity")
        == _identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": value[
                    "support_contract_identity"
                ],
                "evidence_sha256": value["evidence_sha256"],
                "source_implementation_identity": value[
                    "source_implementation_identity"
                ],
                "authority_mode": value["authority_mode"],
            },
        )
    )


def _exact_mapping_equal(left: Any, right: Any) -> bool:
    return bool(
        isinstance(left, Mapping)
        and isinstance(right, Mapping)
        and set(left) == set(right)
        and all(
            type(left[field]) is type(right[field])
            and left[field] == right[field]
            for field in right
        )
    )


def binary_publication_reauthorization_receipt(
    *,
    generation_performance_authority_binding: Mapping[str, Any],
    current_performance_authority_binding: Mapping[str, Any],
    result_generation_identity: str,
    validation_run_identity: str,
    validation_result_sha256: str,
    activation_identity: str,
) -> dict[str, Any]:
    """Bind one live release reauthorization to an exact activation tuple."""

    generation_binding = dict(generation_performance_authority_binding)
    current_binding = dict(current_performance_authority_binding)
    identities = (
        result_generation_identity,
        validation_run_identity,
        validation_result_sha256,
        activation_identity,
    )
    if (
        not _publication_authority_binding_is_valid(generation_binding)
        or not _publication_authority_binding_is_valid(current_binding)
        or _exact_mapping_equal(generation_binding, current_binding)
        or generation_binding.get("authority_mode") != "release_evidence"
        or current_binding.get("authority_mode") != "release_evidence"
        or not all(type(value) is str and _is_sha256_identity(value) for value in identities)
    ):
        raise BinaryOutputError(
            "BINARY_PUBLICATION_REAUTHORIZATION_INVALID",
            "reauthorization requires distinct release bindings and exact operation identities",
        )
    core = {
        "schema": _PUBLICATION_REAUTHORIZATION_SCHEMA,
        "result_generation_identity": result_generation_identity,
        "validation_run_identity": validation_run_identity,
        "validation_result_sha256": validation_result_sha256,
        "activation_identity": activation_identity,
        "generation_performance_authority_binding": generation_binding,
        "current_performance_authority_binding": current_binding,
    }
    return {
        **core,
        "reauthorization_identity": _identity(
            "binary_publication_reauthorization_identity", core
        ),
    }


def _live_reauthorization_binding_is_current(binding: Mapping[str, Any]) -> bool:
    """Independently re-run the live gate for a callback-supplied binding."""

    try:
        from binary_pipeline import _verify_performance_authority_gate_binding

        observed = _verify_performance_authority_gate_binding(dict(binding))
    except Exception:
        return False
    return _exact_mapping_equal(observed, binding)


def _publication_reauthorization_is_valid(
    value: Any,
    *,
    expected_generation_binding: Mapping[str, Any],
    result_generation_identity: str,
    validation_run_identity: str,
    validation_result_sha256: str,
    activation_identity: str,
) -> bool:
    if type(value) is not dict or set(value) != _PUBLICATION_REAUTHORIZATION_FIELDS:
        return False
    generation_binding = value.get(
        "generation_performance_authority_binding"
    )
    current_binding = value.get("current_performance_authority_binding")
    if (
        type(generation_binding) is not dict
        or type(current_binding) is not dict
        or not _publication_authority_binding_is_valid(generation_binding)
        or not _publication_authority_binding_is_valid(current_binding)
        or not _exact_mapping_equal(
            generation_binding, expected_generation_binding
        )
        or _exact_mapping_equal(generation_binding, current_binding)
        or generation_binding.get("authority_mode") != "release_evidence"
        or current_binding.get("authority_mode") != "release_evidence"
        or not _live_reauthorization_binding_is_current(current_binding)
    ):
        return False
    expected_identities = {
        "result_generation_identity": result_generation_identity,
        "validation_run_identity": validation_run_identity,
        "validation_result_sha256": validation_result_sha256,
        "activation_identity": activation_identity,
    }
    if any(
        type(value.get(field)) is not str
        or value.get(field) != expected
        or not _is_sha256_identity(value.get(field))
        for field, expected in expected_identities.items()
    ):
        return False
    core = {
        "schema": value["schema"],
        "result_generation_identity": value[
            "result_generation_identity"
        ],
        "validation_run_identity": value["validation_run_identity"],
        "validation_result_sha256": value[
            "validation_result_sha256"
        ],
        "activation_identity": value["activation_identity"],
        "generation_performance_authority_binding": generation_binding,
        "current_performance_authority_binding": current_binding,
    }
    return bool(
        type(value.get("schema")) is str
        and value["schema"] == _PUBLICATION_REAUTHORIZATION_SCHEMA
        and type(value.get("reauthorization_identity")) is str
        and value["reauthorization_identity"]
        == _identity("binary_publication_reauthorization_identity", core)
    )


def _run_publication_guard(
    authority: Mapping[str, Any] | None,
    publication_guard: Callable[[], Any] | None,
    *,
    result_generation_identity: str,
    validation_run_identity: str,
    validation_result_sha256: str,
    activation_identity: str,
) -> Any:
    """Run the last-mile guard and bind its result to immutable authority.

    A canonical hash in a generation sidecar is an integrity checksum, not a
    trust root: an arbitrary caller can manufacture both the bytes and their
    hash.  Pipeline generations therefore require the caller to re-derive the
    complete binding from the release support/evidence snapshot at the exact
    publication boundary.  Low-level generations without pipeline
    fingerprints retain the historical optional callback contract.
    """

    if authority is None:
        return publication_guard() if publication_guard is not None else None
    if publication_guard is None:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_REQUIRED",
            "pipeline publication authority requires a live guard",
        )
    observed = publication_guard()
    expected = authority["performance_authority_gate_binding"]
    exact_binding = bool(
        _publication_authority_binding_is_valid(observed)
        and _exact_mapping_equal(observed, expected)
        and _live_reauthorization_binding_is_current(observed)
    )
    reauthorized = _publication_reauthorization_is_valid(
        observed,
        expected_generation_binding=expected,
        result_generation_identity=result_generation_identity,
        validation_run_identity=validation_run_identity,
        validation_result_sha256=validation_result_sha256,
        activation_identity=activation_identity,
    )
    if not exact_binding and not reauthorized:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_MISMATCH",
            "live publication authority does not match the generation binding",
        )
    return observed


def _generation_publication_authority(
    generation: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return a strict immutable pipeline publication capability, if present."""

    sidecars = manifest.get("sidecar_content_identities")
    if not isinstance(sidecars, Mapping):
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID", str(generation)
        )
    expected = sidecars.get(_PUBLICATION_AUTHORITY_SIDECAR)
    if expected is None:
        # Performance evidence is release metadata, not analysis authority.
        # Normal pipeline generations intentionally have no publication
        # authority sidecar and are activated solely from a passed validation
        # attachment bound to these immutable generation bytes.
        return None
    if not _is_sha256_identity(expected):
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID", str(expected)
        )
    path = generation / _PUBLICATION_AUTHORITY_SIDECAR
    try:
        _digest, content, _snapshot = _read_stable_generation_file(
            path, expected_sha256=expected, capture_content=True
        )
        value = json.loads((content or b"").decode("utf-8"))
    except BinaryOutputError as error:
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            f"{path}: {error}",
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            f"{path}: {error}",
        ) from error
    binding = (
        value.get("performance_authority_gate_binding")
        if isinstance(value, Mapping) else None
    )
    valid = bool(
        isinstance(value, Mapping)
        and set(value) == {
            "schema",
            "authority_mode",
            "binding_identity",
            "public_activation_allowed",
            "performance_authority_gate_binding",
        }
        and content == _json_bytes(dict(value))
        and value.get("schema") == _PUBLICATION_AUTHORITY_SCHEMA
        and _publication_authority_binding_is_valid(binding)
        and value.get("authority_mode") == binding.get("authority_mode")
        and value.get("binding_identity") == binding.get("binding_identity")
        and type(value.get("public_activation_allowed")) is bool
        and value.get("public_activation_allowed")
        is (value.get("authority_mode") == "release_evidence")
    )
    if not valid:
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID", str(path)
        )
    return dict(value)


def _require_generation_publication_allowed(
    generation: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any] | None:
    authority = _generation_publication_authority(generation, manifest)
    recapture_context = _RELEASE_RECAPTURE_PUBLICATION_CONTEXT.get()
    recapture_allowed = bool(
        authority is not None
        and authority.get("authority_mode")
        == _RELEASE_RECAPTURE_AUTHORITY_MODE
        and isinstance(recapture_context, tuple)
        and len(recapture_context) == 2
        and recapture_context[0]
        is _RELEASE_RECAPTURE_PUBLICATION_CAPABILITY
        and recapture_context[1] == generation.parent.parent.resolve()
    )
    if (
        authority is not None
        and not authority["public_activation_allowed"]
        and not recapture_allowed
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_FORBIDDEN",
            str(generation),
        )
    return authority


@contextmanager
def _release_recapture_publication(output_root: str | Path):
    """Temporarily authorize one exact benchmark-only output root.

    The immutable generation remains permanently non-publishable.  This
    process-local capability exists only so the performance harness can time
    the real descriptor transaction and then remove it before returning.
    """

    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_RELEASE_RECAPTURE_CLEANUP_FORBIDDEN",
    )
    token = _RELEASE_RECAPTURE_PUBLICATION_CONTEXT.set(
        (_RELEASE_RECAPTURE_PUBLICATION_CAPABILITY, root)
    )
    try:
        yield
    finally:
        _RELEASE_RECAPTURE_PUBLICATION_CONTEXT.reset(token)


def _require_generation_identity_publication_allowed(
    root: Path,
    generation_identity: str,
) -> dict[str, Any] | None:
    generations = _physical_generation_namespace(
        root,
        create=False,
        reason_code="BINARY_GENERATION_MANIFEST_INVALID",
    )
    generation = _physical_generation_directory(
        generations,
        generation_identity,
        reason_code="BINARY_GENERATION_MANIFEST_INVALID",
    )
    manifest_path = generation / "result_generation.json"
    try:
        _digest, content, _snapshot = _read_stable_generation_file(
            manifest_path, capture_content=True
        )
        manifest = json.loads((content or b"").decode("utf-8"))
    except BinaryOutputError as error:
        raise BinaryOutputError(
            "BINARY_GENERATION_MANIFEST_INVALID",
            f"{manifest_path}: {error}",
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryOutputError(
            "BINARY_GENERATION_MANIFEST_INVALID",
            f"{manifest_path}: {error}",
        ) from error
    if (
        not isinstance(manifest, Mapping)
        or content != _json_bytes(dict(manifest))
        or manifest.get("result_generation_identity") != generation_identity
        or _result_generation_identity_from_manifest(manifest)
        != generation_identity
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_MANIFEST_INVALID",
            str(manifest_path),
        )
    return _require_generation_publication_allowed(generation, manifest)


def read_binary_generation_publication_authority_binding(
    output_root: str | Path,
    generation_identity: str,
) -> dict[str, Any]:
    """Read the immutable generation binding for a live reauthorization."""

    if type(generation_identity) is not str or not _is_sha256_identity(
        generation_identity
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            str(generation_identity),
        )
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
    )
    authority = _require_generation_identity_publication_allowed(
        root, generation_identity
    )
    binding = (
        authority.get("performance_authority_gate_binding")
        if isinstance(authority, Mapping) else None
    )
    if not _publication_authority_binding_is_valid(binding):
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            generation_identity,
        )
    return dict(binding)


def _verify_pending_generation_integrity(
    root: Path,
    pending: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Re-prove the pending generation and validation at public commit time."""

    generation_identity = str(pending.get("result_generation_identity") or "")
    validation_identity = str(pending.get("validation_run_identity") or "")
    validation_sha256 = str(pending.get("validation_result_sha256") or "")
    if not all(
        _is_sha256_identity(value)
        for value in (generation_identity, validation_identity, validation_sha256)
    ):
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", generation_identity
        )
    try:
        root = root.resolve(strict=True)
        generations = root / "binary_generations"
        generation = generations / generation_identity
        validation_directory = generation / "validation"
        if (
            generations.resolve(strict=True) != generations
            or generation.resolve(strict=True) != generation
            or generation.parent != generations
            or validation_directory.resolve(strict=True) != validation_directory
            or validation_directory.parent != generation
        ):
            raise OSError("generation path escaped its content-addressed root")
    except (OSError, RuntimeError) as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"{generation_identity}: {error}",
        ) from error

    directory_snapshots = {
        root: _directory_snapshot(root),
        generations: _directory_snapshot(generations),
        generation: _directory_snapshot(generation),
        validation_directory: _directory_snapshot(validation_directory),
    }
    file_snapshots: dict[Path, _StatSnapshot] = {}
    manifest_path = generation / "result_generation.json"
    _manifest_digest, manifest_content, manifest_snapshot = (
        _read_stable_generation_file(manifest_path, capture_content=True)
    )
    file_snapshots[manifest_path] = manifest_snapshot
    try:
        manifest = json.loads((manifest_content or b"").decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"{manifest_path}: {error}",
        ) from error
    sidecars = manifest.get("sidecar_content_identities") if isinstance(
        manifest, Mapping
    ) else None
    if (
        not isinstance(manifest, Mapping)
        or manifest_content != _json_bytes(dict(manifest))
        or manifest.get("result_generation_identity") != generation_identity
        or _result_generation_identity_from_manifest(manifest)
        != generation_identity
        or not isinstance(sidecars, Mapping)
        or not _REQUIRED_CORE_GENERATION_SIDECARS.issubset(sidecars)
    ):
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", str(manifest_path)
        )
    capture_mode = _INTEGRITY_PROOF_CAPTURE_CONTEXT.get()
    if capture_mode is _CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY:
        publication_authority = _generation_publication_authority(
            generation, manifest
        )
        if (
            publication_authority is None
            or publication_authority.get("authority_mode")
            != "candidate_source_measurement"
            or publication_authority.get("public_activation_allowed")
        ):
            raise BinaryOutputError(
                "BINARY_GENERATION_PUBLICATION_DRY_RUN_FORBIDDEN",
                str(generation),
            )
    else:
        publication_authority = _require_generation_publication_allowed(
            generation, manifest
        )
    for name, expected in sidecars.items():
        if not _is_safe_sidecar_basename(name) or not _is_sha256_identity(expected):
            raise BinaryOutputError(
                "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", str(name)
            )
        path = generation / name
        _digest, _content, snapshot = _read_stable_generation_file(
            path, expected_sha256=expected
        )
        file_snapshots[path] = snapshot
    for name in _TRANSIENT_FACT_STORE_SIDECARS:
        transient = generation / name
        if transient.exists() or transient.is_symlink():
            raise BinaryOutputError(
                "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", str(transient)
            )
    obsolete_attachment = generation / "generation_attachments.json"
    if obsolete_attachment.exists() or obsolete_attachment.is_symlink():
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            str(obsolete_attachment),
        )

    validation_path = validation_directory / f"{validation_identity}.json"
    _digest, validation_content, validation_snapshot = (
        _read_stable_generation_file(
            validation_path,
            expected_sha256=validation_sha256,
            capture_content=True,
        )
    )
    file_snapshots[validation_path] = validation_snapshot
    try:
        validation = json.loads((validation_content or b"").decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            f"{validation_path}: {error}",
        ) from error
    if (
        not isinstance(validation, Mapping)
        or validation_content != _json_bytes(dict(validation))
        or validation.get("validation_run_identity") != validation_identity
        or not is_complete_v3_validation_result(validation, manifest)
    ):
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED", str(validation_path)
        )
    _assert_generation_snapshot_unchanged(
        file_snapshots, directory_snapshots
    )
    if (
        capture_mode is _INTEGRITY_PROOF_CAPTURE_CAPABILITY
        or capture_mode
        is _CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY
    ):
        authority_bytes = (
            _json_bytes(dict(publication_authority))
            if publication_authority is not None else None
        )
        _INTEGRITY_PROOF_RESULT_CONTEXT.set(_GenerationIntegrityProof(
            publication_authority_bytes=authority_bytes,
            directory_snapshots=tuple(sorted(
                directory_snapshots.items(), key=lambda item: str(item[0])
            )),
            file_snapshots=tuple(sorted(
                file_snapshots.items(), key=lambda item: str(item[0])
            )),
        ))
    return publication_authority


def _verify_pending_generation_integrity_with_proof(
    root: Path,
    pending: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, _GenerationIntegrityProof | None]:
    """Capture a proof only through a module-owned context, never a public arg."""

    capture_token = _INTEGRITY_PROOF_CAPTURE_CONTEXT.set(
        _INTEGRITY_PROOF_CAPTURE_CAPABILITY
    )
    result_token = _INTEGRITY_PROOF_RESULT_CONTEXT.set(None)
    try:
        publication_authority = _verify_pending_generation_integrity(
            root, pending
        )
        proof = _INTEGRITY_PROOF_RESULT_CONTEXT.get()
    finally:
        _INTEGRITY_PROOF_RESULT_CONTEXT.reset(result_token)
        _INTEGRITY_PROOF_CAPTURE_CONTEXT.reset(capture_token)
    return (
        publication_authority,
        proof if isinstance(proof, _GenerationIntegrityProof) else None,
    )


def _verify_candidate_generation_integrity_with_proof(
    root: Path,
    pending: Mapping[str, Any],
) -> tuple[dict[str, Any], _GenerationIntegrityProof | None]:
    """Prove a non-publishable measurement candidate without authorizing it."""

    capture_token = _INTEGRITY_PROOF_CAPTURE_CONTEXT.set(
        _CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY
    )
    result_token = _INTEGRITY_PROOF_RESULT_CONTEXT.set(None)
    try:
        publication_authority = _verify_pending_generation_integrity(
            root, pending
        )
        proof = _INTEGRITY_PROOF_RESULT_CONTEXT.get()
    finally:
        _INTEGRITY_PROOF_RESULT_CONTEXT.reset(result_token)
        _INTEGRITY_PROOF_CAPTURE_CONTEXT.reset(capture_token)
    if publication_authority is None:
        raise BinaryOutputError(
            "BINARY_GENERATION_PUBLICATION_DRY_RUN_FORBIDDEN",
            str(root),
        )
    return (
        publication_authority,
        proof if isinstance(proof, _GenerationIntegrityProof) else None,
    )


def _read_active_descriptor(
    root: Path,
    *,
    missing_ok: bool = False,
    relative_path: str | Path = "active_binary_generation.json",
) -> tuple[dict[str, Any] | None, tuple[int, int] | None]:
    """Read a generation descriptor without following or blocking on hostile files."""

    path = root / Path(relative_path)
    try:
        initial_stat = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID", str(path)
        ) from None
    except OSError as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID", f"{path}: {error}"
        ) from error
    if (
        stat.S_ISLNK(initial_stat.st_mode)
        or not stat.S_ISREG(initial_stat.st_mode)
        or initial_stat.st_nlink != 1
    ):
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            f"active descriptor is not a private regular file: {path}",
        )

    descriptor = None
    try:
        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_NOFOLLOW", 0) or 0)
            | int(getattr(os, "O_NONBLOCK", 0) or 0)
            | int(getattr(os, "O_BINARY", 0) or 0)
        )
        descriptor = os.open(path, flags)
        opened_stat = os.fstat(descriptor)
        current_stat = os.lstat(path)
        expected_identity = _descriptor_file_identity(initial_stat)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_nlink != 1
            or current_stat.st_nlink != 1
            or _descriptor_file_identity(opened_stat) != expected_identity
            or _descriptor_file_identity(current_stat) != expected_identity
        ):
            raise BinaryOutputError(
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
                f"active descriptor changed while opening: {path}",
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw = handle.read()
            final_opened_stat = os.fstat(handle.fileno())
            final_path_stat = os.lstat(path)
            if (
                _descriptor_file_identity(final_opened_stat) != expected_identity
                or _descriptor_file_identity(final_path_stat) != expected_identity
                or final_opened_stat.st_nlink != 1
                or final_path_stat.st_nlink != 1
                or final_opened_stat.st_size != opened_stat.st_size
                or final_opened_stat.st_mtime_ns != opened_stat.st_mtime_ns
                or (
                    os.name != "nt"
                    and final_opened_stat.st_ctime_ns
                    != opened_stat.st_ctime_ns
                )
            ):
                raise BinaryOutputError(
                    "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
                    f"active descriptor changed while reading: {path}",
                )
        value = json.loads(raw.decode("utf-8"))
    except BinaryOutputError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID", f"{path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            _attempt_cleanups(
                ((f"close active descriptor for {path}", lambda: os.close(descriptor)),),
                primary=sys.exc_info()[1],
            )
    if not isinstance(value, Mapping):
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            f"active descriptor root is not an object: {path}",
        )
    return dict(value), expected_identity


def read_active_binary_generation(
    output_root: str | Path,
    *,
    missing_ok: bool = False,
    allow_pending_activation: bool = False,
) -> dict[str, Any] | None:
    """Securely read the sealed public active-generation descriptor.

    Legacy interrupted deployments may have written an activation receipt into
    the public descriptor.  They remain readable only by explicit recovery
    callers; ordinary consumers fail closed instead of treating them as active.
    """

    try:
        root = _canonical_physical_output_root(
            output_root,
            reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
        )
    except BinaryOutputError as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID", str(output_root)
        ) from error
    value, _identity = _read_active_descriptor(root, missing_ok=missing_ok)
    if value is None:
        return None
    core = _active_descriptor_core(value)
    if core is None:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            str(root / "active_binary_generation.json"),
        )
    _require_generation_identity_publication_allowed(
        root, core["result_generation_identity"]
    )
    if set(value) == set(core):
        return value
    predecessor_value = value.get("activation_predecessor")
    predecessor = _active_descriptor_core(predecessor_value)
    is_legacy_pending = bool(
        set(value) == {*core, "activation_identity", "activation_predecessor"}
        and _is_sha256_identity(value.get("activation_identity"))
        and (predecessor_value is None or predecessor is not None)
    )
    if not is_legacy_pending:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            str(root / "active_binary_generation.json"),
        )
    if not allow_pending_activation:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PENDING_ACTIVATION",
            str(root / "active_binary_generation.json"),
        )
    return value


def _active_descriptor_path_matches(
    path: Path,
    expected_identity: tuple[int, int] | None,
    *,
    expect_missing: bool = False,
) -> bool:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return expect_missing
    if expect_missing or expected_identity is None:
        return False
    return bool(
        stat.S_ISREG(current.st_mode)
        and current.st_nlink == 1
        and _descriptor_file_identity(current) == expected_identity
    )


def _active_descriptor_destination(
    root: Path,
    relative_path: str | Path,
) -> Path:
    """Bind descriptor writes to a physical directory below ``root``.

    The private pending descriptor lives below ``binary_observability``.  A
    pre-existing directory symlink there must not turn the final activation
    step into an out-of-root write after a multi-hour analysis.  Keep the
    accepted path set deliberately closed and create the one optional child
    with a single-component mkdir so no ancestor link is traversed.
    """

    requested_root = Path(root).expanduser()
    if requested_root.name in {"", ".", ".."}:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            f"{requested_root}: output root must name a dedicated leaf",
        )
    lexical_root = requested_root.parent.resolve() / requested_root.name
    relative = Path(relative_path)
    if relative not in {
        Path("active_binary_generation.json"),
        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
    }:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            f"unsupported active descriptor path: {relative}",
        )
    try:
        root_stat = os.lstat(lexical_root)
        if (
            stat.S_ISLNK(root_stat.st_mode)
            or not stat.S_ISDIR(root_stat.st_mode)
            or lexical_root.resolve(strict=True) != lexical_root
        ):
            raise OSError("output root is not a physical directory")
        parent = lexical_root / relative.parent
        if relative.parent != Path("."):
            try:
                os.mkdir(parent, 0o700)
            except FileExistsError:
                pass
        parent_stat = os.lstat(parent)
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent.resolve(strict=True) != parent
            or (
                relative.parent != Path(".")
                and parent.parent != lexical_root
            )
            or (
                relative.parent == Path(".")
                and parent != lexical_root
            )
        ):
            raise OSError("descriptor parent is not a physical child directory")
    except (OSError, RuntimeError) as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            f"{lexical_root / relative}: {error}",
        ) from error
    return parent / relative.name


def _write_active_descriptor(
    root: Path,
    active: Mapping[str, Any],
    *,
    expected_file_identity: tuple[int, int] | None = None,
    expect_missing: bool = False,
    relative_path: str | Path = "active_binary_generation.json",
) -> Path:
    destination = _active_descriptor_destination(root, relative_path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".active-generation-", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_json_bytes(dict(active)))
            handle.flush()
            os.fsync(handle.fileno())
        if not _active_descriptor_path_matches(
            destination,
            expected_file_identity,
            expect_missing=expect_missing,
        ):
            raise BinaryOutputError(
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED", str(destination)
            )
        os.replace(temporary_name, destination)
        _fsync_directory(destination.parent)
        return destination
    finally:
        primary = sys.exc_info()[1]
        actions = []
        if os.path.exists(temporary_name):
            actions.append((
                f"unlink temporary active descriptor {temporary_name}",
                lambda: _unlink_missing_ok(temporary_name),
            ))
        _attempt_cleanups(actions, primary=primary)


def _active_descriptor_core(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    generation_identity = value.get("result_generation_identity")
    validation_identity = value.get("validation_run_identity")
    validation_sha256 = value.get("validation_result_sha256")
    if (
        value.get("schema") != _ACTIVE_DESCRIPTOR_SCHEMA
        or not _is_sha256_identity(generation_identity)
        or value.get("generation_directory")
        != f"binary_generations/{generation_identity}"
        or not _is_sha256_identity(validation_identity)
        or not _is_sha256_identity(validation_sha256)
    ):
        return None
    return {
        "schema": _ACTIVE_DESCRIPTOR_SCHEMA,
        "result_generation_identity": generation_identity,
        "generation_directory": value["generation_directory"],
        "validation_run_identity": validation_identity,
        "validation_result_sha256": validation_sha256,
    }


_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH = Path(
    "binary_observability/pending_active_binary_generation.json"
)


def _pending_active_descriptor(value: Any) -> dict[str, Any] | None:
    core = _active_descriptor_core(value)
    if core is None or not isinstance(value, Mapping):
        return None
    predecessor_value = value.get("activation_predecessor")
    predecessor = _active_descriptor_core(predecessor_value)
    if (
        set(value)
        != {
            *core,
            "activation_identity",
            "activation_predecessor",
            "activation_state",
        }
        or not _is_sha256_identity(value.get("activation_identity"))
        or value.get("activation_state") not in {"pending", "published"}
        or (predecessor_value is not None and predecessor is None)
    ):
        return None
    return {
        **core,
        "activation_identity": value["activation_identity"],
        "activation_predecessor": predecessor,
        "activation_state": value["activation_state"],
    }


def read_pending_binary_generation(
    output_root: str | Path,
    *,
    expected_activation_identity: str = "",
    missing_ok: bool = False,
) -> dict[str, Any] | None:
    """Read one private activation candidate, never the public active pointer."""

    try:
        root = _canonical_physical_output_root(
            output_root,
            reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
        )
    except BinaryOutputError as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID", str(output_root)
        ) from error
    value, _identity = _read_active_descriptor(
        root,
        missing_ok=missing_ok,
        relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
    )
    if value is None:
        return None
    normalized = _pending_active_descriptor(value)
    if normalized is None:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_ACTIVATION_RECEIPT_INVALID",
            str(root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH),
        )
    expected = str(expected_activation_identity or "")
    if expected and normalized["activation_identity"] != expected:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_ACTIVATION_RECEIPT_INVALID", expected
        )
    return normalized


def prune_unreferenced_binary_generations(
    output_root: str | Path,
    *,
    protected_generation_identities: Iterable[str] = (),
) -> dict[str, Any]:
    """Remove content-addressed generations with no live recovery reference.

    The active descriptor, a pending activation and both of their predecessors
    are read while holding the descriptor lock.  Callers may additionally
    protect a generation referenced by a validated resume checkpoint.  Unknown
    directory names and non-physical leaves are never touched.
    """

    requested_root = Path(output_root).expanduser()
    summary: dict[str, Any] = {
        "schema": "java-upgrade-analyzer.binary-generation-gc.v1",
        "removed_generation_identities": [],
        "retained_generation_identities": [],
        "skipped_entries": [],
        "failures": [],
        "protected_generation_identities": [],
        "removed_count": 0,
        "retained_count": 0,
        "failure_count": 0,
    }
    try:
        root = _canonical_physical_output_root(
            requested_root,
            reason_code="BINARY_GENERATION_GC_ROOT_INVALID",
        )
    except BinaryOutputError as error:
        if not requested_root.exists() and not requested_root.is_symlink():
            return summary
        raise

    protected = set()
    for identity in protected_generation_identities:
        normalized = str(identity or "")
        if not _is_sha256_identity(normalized):
            raise BinaryOutputError(
                "BINARY_GENERATION_GC_PROTECTED_IDENTITY_INVALID", normalized
            )
        protected.add(normalized)

    def protect_descriptor(value: Any) -> None:
        core = _active_descriptor_core(value)
        if core is not None:
            protected.add(core["result_generation_identity"])
        if isinstance(value, Mapping):
            predecessor = _active_descriptor_core(
                value.get("activation_predecessor")
            )
            if predecessor is not None:
                protected.add(predecessor["result_generation_identity"])

    try:
        with _active_generation_lock(root):
            active, _active_identity = _read_active_descriptor(
                root, missing_ok=True
            )
            if active is not None and _active_descriptor_core(active) is None:
                raise BinaryOutputError(
                    "BINARY_GENERATION_GC_REFERENCE_INVALID",
                    str(root / "active_binary_generation.json"),
                )
            pending, _pending_identity = _read_active_descriptor(
                root,
                missing_ok=True,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            if pending is not None and _pending_active_descriptor(pending) is None:
                raise BinaryOutputError(
                    "BINARY_GENERATION_GC_REFERENCE_INVALID",
                    str(root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH),
                )
            protect_descriptor(active)
            protect_descriptor(pending)
            try:
                generations = _physical_generation_namespace(
                    root,
                    create=False,
                    reason_code="BINARY_GENERATION_GC_NAMESPACE_INVALID",
                )
            except BinaryOutputError:
                if not (root / "binary_generations").exists():
                    summary["protected_generation_identities"] = sorted(
                        protected
                    )
                    return summary
                raise

            removed_any = False
            for child in sorted(generations.iterdir(), key=lambda item: item.name):
                identity = child.name
                if not _is_sha256_identity(identity):
                    summary["skipped_entries"].append(identity)
                    continue
                if identity in protected:
                    summary["retained_generation_identities"].append(identity)
                    continue
                try:
                    physical = _physical_generation_directory(
                        generations,
                        identity,
                        reason_code="BINARY_GENERATION_GC_ENTRY_INVALID",
                    )
                    _rmtree_missing_ok(physical)
                    removed_any = True
                    summary["removed_generation_identities"].append(identity)
                except (BinaryOutputError, OSError) as error:
                    summary["failures"].append({
                        "generation_identity": identity,
                        "error_type": type(error).__name__,
                        "detail": str(error),
                    })
            if removed_any:
                try:
                    _fsync_directory(generations)
                except OSError as error:
                    summary["failures"].append({
                        "generation_identity": "",
                        "error_type": type(error).__name__,
                        "detail": f"generation namespace fsync failed: {error}",
                    })
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_GENERATION_GC_LOCK_TIMEOUT", str(error)
        ) from error

    summary["protected_generation_identities"] = sorted(protected)
    summary["removed_count"] = len(summary["removed_generation_identities"])
    summary["retained_count"] = len(summary["retained_generation_identities"])
    summary["failure_count"] = len(summary["failures"])
    return summary


def _public_active_is_sealed(value: Any) -> bool:
    core = _active_descriptor_core(value)
    return bool(core is not None and set(value) == set(core))


def _try_install_direct_seal_capability(
    root: Path,
    active: Mapping[str, Any],
    *,
    predecessor: Mapping[str, Any] | None,
    descriptor_before_identity: tuple[int, int] | None,
    proof: _GenerationIntegrityProof | None,
    probed_device: int | None,
) -> bool:
    """Install a receipt proof only after its durable descriptor transition."""

    if proof is None or probed_device is None:
        return False
    try:
        directory_snapshots = dict(proof.directory_snapshots)
        file_snapshots = dict(proof.file_snapshots)
        proved_root = directory_snapshots.get(root)
        if proved_root is None:
            raise OSError("integrity proof did not bind the canonical root")
        device = proved_root[0]
        if device != probed_device or any(
            snapshot[0] != device
            for snapshot in (
                *directory_snapshots.values(),
                *file_snapshots.values(),
            )
        ):
            raise OSError("integrity proof crosses filesystem devices")
        non_root_directories = {
            path: snapshot
            for path, snapshot in directory_snapshots.items()
            if path != root
        }
        # The descriptor rename changes root metadata, but no generation path.
        # Recheck the fully-hashed tree after the durable rename before taking
        # the refreshed root snapshot used by seal().
        _assert_generation_snapshot_unchanged(
            file_snapshots, non_root_directories
        )
        descriptor_path = root / "active_binary_generation.json"
        expected_descriptor_bytes = _json_bytes(dict(active))
        expected_descriptor_sha256 = hashlib.sha256(
            expected_descriptor_bytes
        ).hexdigest()
        _digest, descriptor_bytes, descriptor_snapshot = (
            _read_stable_generation_file(
                descriptor_path,
                expected_sha256=expected_descriptor_sha256,
                capture_content=True,
            )
        )
        observed, descriptor_after_identity = _read_active_descriptor(root)
        if (
            descriptor_bytes != expected_descriptor_bytes
            or not _exact_mapping_equal(observed, active)
            or descriptor_after_identity is None
            or descriptor_after_identity
            != (descriptor_snapshot[0], descriptor_snapshot[1])
            or (
                descriptor_before_identity is not None
                and descriptor_after_identity
                == descriptor_before_identity
            )
            or ((predecessor is None) is not (
                descriptor_before_identity is None
            ))
        ):
            raise OSError("active descriptor transition did not match")
        refreshed_root = _directory_snapshot(root)
        if refreshed_root[0] != device:
            raise OSError("output root filesystem changed")
        # Close the post-rename capture window before installing the token.
        _assert_generation_snapshot_unchanged(
            file_snapshots, non_root_directories
        )
        if (
            _directory_snapshot(root) != refreshed_root
            or _regular_file_snapshot(os.lstat(descriptor_path))
            != descriptor_snapshot
        ):
            raise OSError("descriptor transition changed during capture")

        final_directories = {
            **non_root_directories,
            root: refreshed_root,
        }
        root_identity = (refreshed_root[0], refreshed_root[1])
        operation_key = _direct_seal_operation_key(
            root,
            root_identity,
            result_generation_identity=active[
                "result_generation_identity"
            ],
            validation_run_identity=active["validation_run_identity"],
            validation_result_sha256=active[
                "validation_result_sha256"
            ],
            activation_identity=active["activation_identity"],
        )
        predecessor_bytes = (
            _json_bytes(dict(predecessor))
            if predecessor is not None else None
        )
        _install_direct_seal_capability(_DirectSealCapability(
            sequence=0,
            owner_process_identity=os.getpid(),
            owner_thread_identity=threading.get_ident(),
            canonical_root=root,
            root_identity=root_identity,
            probed_device=probed_device,
            operation_key=operation_key,
            result_generation_identity=active[
                "result_generation_identity"
            ],
            validation_run_identity=active["validation_run_identity"],
            validation_result_sha256=active[
                "validation_result_sha256"
            ],
            activation_identity=active["activation_identity"],
            unsealed_descriptor_bytes=expected_descriptor_bytes,
            predecessor_bytes=predecessor_bytes,
            descriptor_before_identity=descriptor_before_identity,
            descriptor_after_identity=descriptor_after_identity,
            descriptor_snapshot=descriptor_snapshot,
            publication_authority_bytes=(
                proof.publication_authority_bytes
            ),
            directory_snapshots=tuple(sorted(
                final_directories.items(), key=lambda item: str(item[0])
            )),
            file_snapshots=proof.file_snapshots,
        ))
        return True
    except (BinaryOutputError, OSError, KeyError, TypeError, ValueError):
        _discard_current_direct_seal_capability()
        return False


def _direct_seal_fast_publication_authority(
    capability: _DirectSealCapability | None,
    root: Path,
    current: Mapping[str, Any],
    descriptor_identity: tuple[int, int] | None,
) -> tuple[
    bool,
    dict[str, Any] | None,
    _GenerationIntegrityProof | None,
]:
    """Re-lstat an exact one-shot receipt proof without trusting caller data."""

    if capability is None:
        return False, None, None
    try:
        if (
            capability.owner_process_identity != os.getpid()
            or capability.owner_thread_identity != threading.get_ident()
            or capability.canonical_root != root
            or descriptor_identity != capability.descriptor_after_identity
            or _json_bytes(dict(current))
            != capability.unsealed_descriptor_bytes
            or current.get("result_generation_identity")
            != capability.result_generation_identity
            or current.get("validation_run_identity")
            != capability.validation_run_identity
            or current.get("validation_result_sha256")
            != capability.validation_result_sha256
            or current.get("activation_identity")
            != capability.activation_identity
        ):
            return False, None, None
        predecessor = current.get("activation_predecessor")
        predecessor_bytes = (
            _json_bytes(dict(predecessor))
            if isinstance(predecessor, Mapping) else None
        )
        if predecessor_bytes != capability.predecessor_bytes:
            return False, None, None

        directory_snapshots = dict(capability.directory_snapshots)
        file_snapshots = dict(capability.file_snapshots)
        root_snapshot = directory_snapshots.get(root)
        if (
            root_snapshot is None
            or (root_snapshot[0], root_snapshot[1])
            != capability.root_identity
            or root_snapshot[0] != capability.probed_device
            or any(
                snapshot[0] != root_snapshot[0]
                for snapshot in (
                    *directory_snapshots.values(),
                    *file_snapshots.values(),
                    capability.descriptor_snapshot,
                )
            )
        ):
            return False, None, None
        _assert_generation_snapshot_unchanged(
            file_snapshots, directory_snapshots
        )
        descriptor_path = root / "active_binary_generation.json"
        descriptor_stat = os.lstat(descriptor_path)
        if (
            stat.S_ISLNK(descriptor_stat.st_mode)
            or not stat.S_ISREG(descriptor_stat.st_mode)
            or descriptor_stat.st_nlink != 1
            or _regular_file_snapshot(descriptor_stat)
            != capability.descriptor_snapshot
        ):
            return False, None, None
        # Recheck root after the descriptor lstat so a directory mutation in
        # either ordering invalidates the fast proof.
        if _directory_snapshot(root) != root_snapshot:
            return False, None, None

        if capability.publication_authority_bytes is None:
            publication_authority = None
        else:
            parsed = json.loads(
                capability.publication_authority_bytes.decode("utf-8")
            )
            if (
                type(parsed) is not dict
                or capability.publication_authority_bytes
                != _json_bytes(parsed)
            ):
                return False, None, None
            publication_authority = parsed
        proof = _GenerationIntegrityProof(
            publication_authority_bytes=(
                capability.publication_authority_bytes
            ),
            directory_snapshots=capability.directory_snapshots,
            file_snapshots=capability.file_snapshots,
        )
        return True, publication_authority, proof
    except (
        BinaryOutputError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return False, None, None


def _prepare_post_guard_stat_recheck(root: Path) -> int | None:
    """Probe before a proof so the probe itself is included in later snapshots."""

    if os.name != "posix":
        return None
    try:
        device = _directory_snapshot(root)[0]
    except BinaryOutputError:
        return None
    return (
        device
        if _filesystem_supports_direct_seal_fast_path(root, device)
        else None
    )


def _proof_supports_post_guard_stat_recheck(
    proof: _GenerationIntegrityProof | None,
    root: Path,
    *,
    probed_device: int | None,
) -> bool:
    if proof is None or probed_device is None or os.name != "posix":
        return False
    directory_snapshots = dict(proof.directory_snapshots)
    root_snapshot = directory_snapshots.get(root)
    if root_snapshot is None:
        return False
    device = root_snapshot[0]
    if device != probed_device:
        return False
    return all(
        snapshot[0] == device
        for snapshot in (
            *directory_snapshots.values(),
            *(snapshot for _path, snapshot in proof.file_snapshots),
        )
    )


def _stable_reprove_transaction_descriptor(
    root: Path,
    expected: Mapping[str, Any] | None,
    expected_identity: tuple[int, int] | None,
    *,
    relative_path: str | Path = "active_binary_generation.json",
) -> _TransactionDescriptorProof:
    """Re-read exact canonical descriptor bytes and their physical identity."""

    relative = Path(relative_path)
    path = _active_descriptor_destination(root, relative)
    try:
        parent_snapshot = _directory_snapshot(path.parent)
        if expected is None:
            observed, observed_identity = _read_active_descriptor(
                root,
                missing_ok=True,
                relative_path=relative,
            )
            if observed is not None or observed_identity is not None:
                raise OSError("descriptor appeared after the guard")
            if _directory_snapshot(path.parent) != parent_snapshot:
                raise OSError("descriptor parent changed while proving absence")
            return _TransactionDescriptorProof(
                file_snapshot=None,
                parent_snapshot=parent_snapshot,
            )
        if expected_identity is None:
            raise OSError("expected descriptor identity is missing")
        expected_bytes = _json_bytes(dict(expected))
        expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()
        _digest, content, snapshot = _read_stable_generation_file(
            path,
            expected_sha256=expected_sha256,
            capture_content=True,
        )
        observed, observed_identity = _read_active_descriptor(
            root, relative_path=relative
        )
        final = os.lstat(path)
        if (
            content != expected_bytes
            or not _exact_mapping_equal(observed, expected)
            or observed_identity != expected_identity
            or (snapshot[0], snapshot[1]) != expected_identity
            or stat.S_ISLNK(final.st_mode)
            or not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or _regular_file_snapshot(final) != snapshot
            or _directory_snapshot(path.parent) != parent_snapshot
        ):
            raise OSError("descriptor changed after the guard")
        return _TransactionDescriptorProof(
            file_snapshot=snapshot,
            parent_snapshot=parent_snapshot,
        )
    except (BinaryOutputError, OSError, TypeError, ValueError) as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
            f"{path}: {error}",
        ) from error


def _post_guard_generation_integrity_recheck(
    root: Path,
    pending: Mapping[str, Any],
    publication_authority: Mapping[str, Any] | None,
    proof: _GenerationIntegrityProof | None,
    *,
    stat_recheck_allowed: bool,
    candidate_measurement: bool = False,
) -> None:
    """Detect guard-side mutation without treating this as an authority check."""

    if stat_recheck_allowed and proof is not None:
        _assert_generation_snapshot_unchanged(
            dict(proof.file_snapshots),
            dict(proof.directory_snapshots),
        )
        return
    if candidate_measurement:
        reverified_authority, _reverified_proof = (
            _verify_candidate_generation_integrity_with_proof(
                root, pending
            )
        )
    else:
        reverified_authority = _verify_pending_generation_integrity(
            root, pending
        )
    same_authority = bool(
        (publication_authority is None and reverified_authority is None)
        or _exact_mapping_equal(
            publication_authority, reverified_authority
        )
    )
    if not same_authority:
        raise BinaryOutputError(
            "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            "generation publication authority changed after the live guard",
        )


def _assert_descriptor_reproof_unchanged(
    before: _TransactionDescriptorProof,
    after: _TransactionDescriptorProof,
    path: Path,
) -> None:
    if before != after:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED", str(path)
        )


def compare_and_restore_active_binary_generation(
    output_root: str | Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
    previous_active: Mapping[str, Any] | None = None,
) -> bool:
    """Restore the predecessor captured by one exact activation operation."""

    _discard_current_direct_seal_capability()
    if (
        not _is_sha256_identity(expected_current_identity)
        or not _is_sha256_identity(expected_activation_identity)
    ):
        return False
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
    )
    _invalidate_direct_seal_capabilities_for_root(root)
    active_path = root / "active_binary_generation.json"
    try:
        with _active_generation_lock(root):
            pending_raw, pending_identity = _read_active_descriptor(
                root,
                missing_ok=True,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            if pending_raw is not None:
                pending = _pending_active_descriptor(pending_raw)
                if (
                    pending is None
                    or pending["result_generation_identity"]
                    != expected_current_identity
                    or pending["activation_identity"]
                    != expected_activation_identity
                ):
                    return False
                predecessor = pending["activation_predecessor"]
                if previous_active is not None:
                    declared_predecessor = _active_descriptor_core(
                        previous_active
                    )
                    if declared_predecessor != predecessor:
                        return False
                current, descriptor_identity = _read_active_descriptor(
                    root, missing_ok=True
                )
                current_core = _active_descriptor_core(current)
                candidate_core = _active_descriptor_core(pending)
                if current_core == candidate_core and _public_active_is_sealed(
                    current
                ):
                    if predecessor is None:
                        if not _active_descriptor_path_matches(
                            active_path, descriptor_identity
                        ):
                            return False
                        active_path.unlink()
                        _fsync_directory(root)
                    else:
                        _write_active_descriptor(
                            root,
                            predecessor,
                            expected_file_identity=descriptor_identity,
                        )
                elif not (
                    (current is None and predecessor is None)
                    or (
                        current_core == predecessor
                        and _public_active_is_sealed(current)
                    )
                ):
                    return False
                pending_path = root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                if not _active_descriptor_path_matches(
                    pending_path, pending_identity
                ):
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                        str(pending_path),
                    )
                pending_path.unlink()
                _fsync_directory(pending_path.parent)
                return True
            current, descriptor_identity = _read_active_descriptor(root)
            if (
                not isinstance(current, Mapping)
                or current.get("result_generation_identity")
                != expected_current_identity
                or current.get("activation_identity")
                != expected_activation_identity
            ):
                return False
            if "activation_predecessor" not in current:
                return False
            embedded_predecessor = current.get("activation_predecessor")
            predecessor = _active_descriptor_core(embedded_predecessor)
            if embedded_predecessor is not None and predecessor is None:
                return False
            if previous_active is not None:
                declared_predecessor = _active_descriptor_core(previous_active)
                if declared_predecessor != predecessor:
                    return False
            if predecessor is None:
                if not _active_descriptor_path_matches(
                    active_path, descriptor_identity
                ):
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                        str(active_path),
                    )
                try:
                    active_path.unlink()
                except FileNotFoundError:
                    return False
                _fsync_directory(root)
            else:
                _write_active_descriptor(
                    root,
                    predecessor,
                    expected_file_identity=descriptor_identity,
                )
            return True
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error


def _discard_release_recapture_activation(
    output_root: str | Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
    previous_active: Mapping[str, Any] | None = None,
) -> bool:
    """CAS-remove one sealed or interrupted benchmark recapture descriptor."""

    _discard_current_direct_seal_capability()
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_RELEASE_RECAPTURE_CLEANUP_FAILED",
    )
    _invalidate_direct_seal_capabilities_for_root(root)
    context = _RELEASE_RECAPTURE_PUBLICATION_CONTEXT.get()
    if (
        not isinstance(context, tuple)
        or len(context) != 2
        or context[0] is not _RELEASE_RECAPTURE_PUBLICATION_CAPABILITY
        or context[1] != root
    ):
        raise BinaryOutputError(
            "BINARY_RELEASE_RECAPTURE_CLEANUP_FORBIDDEN", str(root)
        )
    if (
        not _is_sha256_identity(expected_current_identity)
        or not _is_sha256_identity(expected_activation_identity)
    ):
        return False

    try:
        authority = _require_generation_identity_publication_allowed(
            root, expected_current_identity
        )
    except BinaryOutputError as error:
        raise BinaryOutputError(
            "BINARY_RELEASE_RECAPTURE_CLEANUP_FAILED",
            f"{expected_current_identity}: {error}",
        ) from error
    if (
        authority is None
        or authority.get("authority_mode")
        != _RELEASE_RECAPTURE_AUTHORITY_MODE
    ):
        raise BinaryOutputError(
            "BINARY_RELEASE_RECAPTURE_CLEANUP_FAILED",
            expected_current_identity,
        )
    declared_predecessor = _active_descriptor_core(previous_active)
    if previous_active is not None and declared_predecessor is None:
        return False
    active_path = root / "active_binary_generation.json"
    try:
        with _active_generation_lock(root):
            pending, _pending_identity = _read_active_descriptor(
                root,
                missing_ok=True,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            if pending is not None:
                return False
            current, descriptor_identity = _read_active_descriptor(
                root, missing_ok=True
            )
            core = _active_descriptor_core(current)
            if (
                core is None
                or core["result_generation_identity"]
                != expected_current_identity
            ):
                return False
            if set(current) == set(core):
                predecessor = declared_predecessor
            else:
                predecessor_value = current.get("activation_predecessor")
                predecessor = _active_descriptor_core(predecessor_value)
                if (
                    current.get("activation_identity")
                    != expected_activation_identity
                    or "activation_predecessor" not in current
                    or (
                        predecessor_value is not None and predecessor is None
                    )
                    or predecessor != declared_predecessor
                ):
                    return False
            if predecessor is None:
                if not _active_descriptor_path_matches(
                    active_path, descriptor_identity
                ):
                    return False
                active_path.unlink()
                _fsync_directory(root)
            else:
                _write_active_descriptor(
                    root,
                    predecessor,
                    expected_file_identity=descriptor_identity,
                )
            remaining, _remaining_identity = _read_active_descriptor(
                root, missing_ok=True
            )
            return _active_descriptor_core(remaining) == predecessor
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error


def publish_pending_binary_generation(
    output_root: str | Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
    publication_guard: Callable[[], Any] | None = None,
) -> bool:
    """Atomically publish a private candidate after its optional final guard."""

    _discard_current_direct_seal_capability()
    if (
        not _is_sha256_identity(expected_current_identity)
        or not _is_sha256_identity(expected_activation_identity)
    ):
        return False
    if publication_guard is not None and not callable(publication_guard):
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_INVALID",
            repr(publication_guard),
        )
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
    )
    _invalidate_direct_seal_capabilities_for_root(root)
    try:
        with _active_generation_lock(root):
            pending_raw, pending_identity = _read_active_descriptor(
                root,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            pending = _pending_active_descriptor(pending_raw)
            if (
                pending is None
                or pending["result_generation_identity"]
                != expected_current_identity
                or pending["activation_identity"]
                != expected_activation_identity
            ):
                return False
            # The candidate can remain private while report rendering and gates
            # run.  Its directory is content-addressed by contract but ordinary
            # files are still writable, so prove the exact generation and its
            # independent-validation attachment again at the public commit
            # boundary.  Keep this inside the activation lock so cooperating
            # publishers cannot race the proof with a pointer update.
            probed_device = _prepare_post_guard_stat_recheck(root)
            publication_authority, integrity_proof = (
                _verify_pending_generation_integrity_with_proof(
                    root, pending
                )
            )
            stat_recheck_allowed = (
                _proof_supports_post_guard_stat_recheck(
                    integrity_proof,
                    root,
                    probed_device=probed_device,
                )
            )
            candidate_core = _active_descriptor_core(pending)
            predecessor = pending["activation_predecessor"]
            current, active_identity = _read_active_descriptor(
                root, missing_ok=True
            )
            current_core = _active_descriptor_core(current)
            publish_active_descriptor = False
            if current_core == candidate_core and _public_active_is_sealed(
                current
            ):
                # Crash recovery after the public pointer rename but before the
                # private receipt state update.
                pass
            elif (
                (current is None and predecessor is None)
                or (
                    current_core == predecessor
                    and _public_active_is_sealed(current)
                )
            ):
                pending_path = root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                if not _active_descriptor_path_matches(
                    pending_path, pending_identity
                ):
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                        str(pending_path),
                    )
                publish_active_descriptor = True
            else:
                return False
            pending_descriptor_before_guard = (
                _stable_reprove_transaction_descriptor(
                    root,
                    pending,
                    pending_identity,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            active_descriptor_before_guard = (
                _stable_reprove_transaction_descriptor(
                    root, current, active_identity
                )
            )
            # This remains the final authority check.  Integrity checks below
            # are deliberately repeated after the caller returns so a
            # re-entrant guard cannot mutate the proved transaction and then
            # have that mutation committed.
            _run_publication_guard(
                publication_authority,
                publication_guard,
                result_generation_identity=pending[
                    "result_generation_identity"
                ],
                validation_run_identity=pending["validation_run_identity"],
                validation_result_sha256=pending[
                    "validation_result_sha256"
                ],
                activation_identity=pending["activation_identity"],
            )
            pending_descriptor_after_guard = (
                _stable_reprove_transaction_descriptor(
                    root,
                    pending,
                    pending_identity,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            active_descriptor_after_guard = (
                _stable_reprove_transaction_descriptor(
                    root, current, active_identity
                )
            )
            _assert_descriptor_reproof_unchanged(
                pending_descriptor_before_guard,
                pending_descriptor_after_guard,
                root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            _assert_descriptor_reproof_unchanged(
                active_descriptor_before_guard,
                active_descriptor_after_guard,
                root / "active_binary_generation.json",
            )
            _post_guard_generation_integrity_recheck(
                root,
                pending,
                publication_authority,
                integrity_proof,
                stat_recheck_allowed=stat_recheck_allowed,
            )
            pending_descriptor_before_commit = (
                _stable_reprove_transaction_descriptor(
                    root,
                    pending,
                    pending_identity,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            active_descriptor_before_commit = (
                _stable_reprove_transaction_descriptor(
                    root, current, active_identity
                )
            )
            _assert_descriptor_reproof_unchanged(
                pending_descriptor_before_guard,
                pending_descriptor_before_commit,
                root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            _assert_descriptor_reproof_unchanged(
                active_descriptor_before_guard,
                active_descriptor_before_commit,
                root / "active_binary_generation.json",
            )
            if publish_active_descriptor:
                _write_active_descriptor(
                    root,
                    candidate_core,
                    expected_file_identity=active_identity,
                    expect_missing=current is None,
                )
            if pending["activation_state"] != "published":
                _write_active_descriptor(
                    root,
                    {**pending, "activation_state": "published"},
                    expected_file_identity=pending_identity,
                    relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                )
            return True
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error


def commit_pending_binary_generation(
    output_root: str | Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
) -> bool:
    """Forget a private activation receipt after its whole release commits."""

    if (
        not _is_sha256_identity(expected_current_identity)
        or not _is_sha256_identity(expected_activation_identity)
    ):
        return False
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
    )
    pending_path = root / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
    try:
        with _active_generation_lock(root):
            pending_raw, pending_identity = _read_active_descriptor(
                root,
                missing_ok=True,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            current, _active_identity = _read_active_descriptor(
                root, missing_ok=True
            )
            current_core = _active_descriptor_core(current)
            if pending_raw is None:
                committed = bool(
                    current_core is not None
                    and _public_active_is_sealed(current)
                    and current_core["result_generation_identity"]
                    == expected_current_identity
                )
                if committed:
                    _require_generation_identity_publication_allowed(
                        root, expected_current_identity
                    )
                return committed
            pending = _pending_active_descriptor(pending_raw)
            if (
                pending is None
                or pending["activation_state"] != "published"
                or pending["result_generation_identity"]
                != expected_current_identity
                or pending["activation_identity"]
                != expected_activation_identity
                or current_core != _active_descriptor_core(pending)
                or not _public_active_is_sealed(current)
            ):
                return False
            _require_generation_identity_publication_allowed(
                root, expected_current_identity
            )
            if not _active_descriptor_path_matches(
                pending_path, pending_identity
            ):
                raise BinaryOutputError(
                    "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                    str(pending_path),
                )
            pending_path.unlink()
            _fsync_directory(pending_path.parent)
            return True
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error


def seal_active_binary_generation(
    output_root: str | Path,
    *,
    expected_current_identity: str,
    expected_activation_identity: str,
    publication_guard: Callable[[], Any] | None = None,
) -> bool:
    """Commit this receipt or prove concurrency cannot undo its generation."""

    if (
        not _is_sha256_identity(expected_current_identity)
        or not _is_sha256_identity(expected_activation_identity)
    ):
        _discard_current_direct_seal_capability()
        return False
    if publication_guard is not None and not callable(publication_guard):
        _discard_current_direct_seal_capability()
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_INVALID",
            repr(publication_guard),
        )
    try:
        root = _canonical_physical_output_root(
            output_root,
            reason_code="BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
        )
    except BinaryOutputError:
        _discard_current_direct_seal_capability()
        raise
    active_path = root / "active_binary_generation.json"
    try:
        with _active_generation_lock(root):
            current, descriptor_identity = _read_active_descriptor(root)
            capability = _consume_direct_seal_capability(
                root,
                expected_current_identity=expected_current_identity,
                expected_activation_identity=expected_activation_identity,
                current=current,
            )
            core = _active_descriptor_core(current)
            if (
                core is None
                or core["result_generation_identity"]
                != expected_current_identity
            ):
                return False
            current_activation_identity = current.get("activation_identity")
            has_predecessor = "activation_predecessor" in current
            predecessor_value = current.get("activation_predecessor")
            predecessor = _active_descriptor_core(predecessor_value)

            if current_activation_identity == expected_activation_identity:
                # An exact receipt must remain structurally valid until it is
                # sealed.  Do not turn a damaged receipt into an apparently
                # committed descriptor.
                if not has_predecessor or (
                    predecessor_value is not None and predecessor is None
                ):
                    return False
                # Direct activation deliberately exposes only an unreadable
                # transaction receipt.  Re-prove every generation sidecar and
                # the exact validation attachment under the same descriptor
                # lock immediately before removing that receipt.  Authority-
                # only validation here would let mutable bytes change between
                # activate() and this actual consumer-visible commit point.
                (
                    fast_path_valid,
                    publication_authority,
                    integrity_proof,
                ) = (
                    _direct_seal_fast_publication_authority(
                        capability,
                        root,
                        current,
                        descriptor_identity,
                    )
                )
                if not fast_path_valid:
                    probed_device = (
                        _prepare_post_guard_stat_recheck(root)
                    )
                    (
                        publication_authority,
                        integrity_proof,
                    ) = _verify_pending_generation_integrity_with_proof(
                        root, current
                    )
                else:
                    root_proof_snapshot = dict(
                        integrity_proof.directory_snapshots
                    ).get(root) if integrity_proof is not None else None
                    probed_device = (
                        root_proof_snapshot[0]
                        if root_proof_snapshot is not None else None
                    )
                stat_recheck_allowed = (
                    _proof_supports_post_guard_stat_recheck(
                        integrity_proof,
                        root,
                        probed_device=probed_device,
                    )
                )
                descriptor_before_guard = (
                    _stable_reprove_transaction_descriptor(
                        root, current, descriptor_identity
                    )
                )
                _run_publication_guard(
                    publication_authority,
                    publication_guard,
                    result_generation_identity=current[
                        "result_generation_identity"
                    ],
                    validation_run_identity=current[
                        "validation_run_identity"
                    ],
                    validation_result_sha256=current[
                        "validation_result_sha256"
                    ],
                    activation_identity=expected_activation_identity,
                )
                descriptor_after_guard = (
                    _stable_reprove_transaction_descriptor(
                        root, current, descriptor_identity
                    )
                )
                _assert_descriptor_reproof_unchanged(
                    descriptor_before_guard,
                    descriptor_after_guard,
                    active_path,
                )
                _post_guard_generation_integrity_recheck(
                    root,
                    current,
                    publication_authority,
                    integrity_proof,
                    stat_recheck_allowed=stat_recheck_allowed,
                )
                descriptor_before_commit = (
                    _stable_reprove_transaction_descriptor(
                        root, current, descriptor_identity
                    )
                )
                _assert_descriptor_reproof_unchanged(
                    descriptor_before_guard,
                    descriptor_before_commit,
                    active_path,
                )
                _write_active_descriptor(
                    root,
                    core,
                    expected_file_identity=descriptor_identity,
                )
                return True

            # Sealing is idempotent after an equivalent caller has already
            # removed the receipt.  Both receipt fields must be absent: a
            # partially damaged receipt is not a committed descriptor.
            if (
                "activation_identity" not in current
                and not has_predecessor
            ):
                _verify_pending_generation_integrity(root, current)
                return True

            # A concurrent activation may supersede this receipt while still
            # targeting the same immutable generation.  It is safe to regard
            # this caller as committed only when that newer receipt would also
            # restore the same generation if it rolled back.  Never seal the
            # other caller's receipt here; that transaction retains ownership
            # of its own commit/rollback decision.
            if (
                _is_sha256_identity(current_activation_identity)
                and has_predecessor
                and predecessor is not None
                and predecessor["result_generation_identity"]
                == expected_current_identity
            ):
                _verify_pending_generation_integrity(root, current)
                return True
            return False
    except _ActiveGenerationLockAcquireTimeout as error:
        _invalidate_direct_seal_capabilities_for_root(root)
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error
    except BaseException:
        _invalidate_direct_seal_capabilities_for_root(root)
        raise


def _result_generation_identity_from_manifest(
    manifest: Mapping[str, Any],
) -> str:
    snapshot_identities = manifest.get("active_snapshot_identities")
    sidecar_identities = manifest.get("sidecar_content_identities")
    policy_identities = manifest.get("policy_identities")
    if (
        manifest.get("schema") != _RESULT_GENERATION_SCHEMA
        or manifest.get("authority") != "binary_first"
        or not isinstance(manifest.get("analysis_context_identity"), str)
        or not manifest.get("analysis_context_identity")
        or not isinstance(manifest.get("trace_result_set_digest"), str)
        or not manifest.get("trace_result_set_digest")
        or not isinstance(snapshot_identities, Mapping)
        or set(snapshot_identities) != _RESULT_GENERATION_SNAPSHOT_LAYERS
        or not all(
            isinstance(value, str) and value
            for value in snapshot_identities.values()
        )
        or not isinstance(sidecar_identities, Mapping)
        or not _REQUIRED_CORE_GENERATION_SIDECARS.issubset(
            sidecar_identities
        )
        or not isinstance(policy_identities, Mapping)
    ):
        return ""
    try:
        return _identity("result_generation_identity", {
            "analysis_context_identity": manifest["analysis_context_identity"],
            "authority": "binary_first",
            "snapshot_identities": dict(snapshot_identities),
            "trace_result_set_digest": manifest["trace_result_set_digest"],
            "sidecar_content_identities": dict(sidecar_identities),
            "policy_identities": dict(policy_identities),
        })
    except (BinaryFirstContractError, TypeError, ValueError):
        return ""


def is_complete_v3_validation_result(
    validation: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> bool:
    if set(validation) != _VALIDATION_V3_FIELDS:
        return False
    issues = validation.get("issues")
    domain_summary = validation.get("domain_summary")
    helper_identities = validation.get("helper_identities")
    skipped_domains = validation.get("skipped_domains")
    active_snapshot_identities = manifest.get("active_snapshot_identities")
    if (
        validation.get("schema")
        != "java-upgrade-analyzer.binary-validation-result.v1"
        or validation.get("result_generation_identity")
        != manifest.get("result_generation_identity")
        or validation.get("validation_policy_version")
        != _INDEPENDENT_VALIDATION_POLICY_VERSION
        or validation.get("status") != "passed"
        or type(validation.get("issue_count")) is not int
        or validation.get("issue_count") != 0
        or not isinstance(issues, list)
        or issues
        or not isinstance(domain_summary, Mapping)
        or domain_summary
        or not isinstance(skipped_domains, list)
        or skipped_domains
        or validation.get("production_identity_influence")
        != "none_validation_attachment_only"
        or not isinstance(helper_identities, Mapping)
        or set(helper_identities) != {"base", "current"}
        or not all(
            _is_sha256_identity(value) for value in helper_identities.values()
        )
        or not isinstance(active_snapshot_identities, Mapping)
    ):
        return False
    identity_fields = (
        "validation_run_identity",
        "oracle_support_manifest_identity",
        "truth_set_identity",
        "issue_set_identity",
        "validator_implementation_identity",
    )
    if not all(
        _is_sha256_identity(validation.get(field)) for field in identity_fields
    ):
        return False
    try:
        expected_issue_set_identity = canonical_identity_streaming(
            "binary_validation_issue_set_identity",
            issues,
            schema_version="1",
        )
        expected_validation_run_identity = _identity(
            "binary_validation_run_identity",
            {
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "active_snapshot_identities": dict(
                    active_snapshot_identities
                ),
                "oracle_support_manifest_identity": validation[
                    "oracle_support_manifest_identity"
                ],
                "truth_set_identity": validation["truth_set_identity"],
                "issue_set_identity": validation["issue_set_identity"],
                "validation_policy_version": validation[
                    "validation_policy_version"
                ],
                "validator_implementation_identity": validation[
                    "validator_implementation_identity"
                ],
                "helper_identities": dict(helper_identities),
            },
        )
    except (BinaryFirstContractError, KeyError, TypeError, ValueError):
        return False
    return bool(
        validation["issue_set_identity"] == expected_issue_set_identity
        and validation["validation_run_identity"]
        == expected_validation_run_identity
    )


def _reported_api_identity(
    decision: Mapping[str, Any],
    *,
    runtime_profile_identity: str,
    analysis_context_identity: str,
) -> str:
    scope = decision.get("fact_scope") or {}
    return _identity("reported_api_identity", {
        "analysis_context_identity": analysis_context_identity,
        "current_runtime_profile_identity": runtime_profile_identity,
        "initiating_loader_realm_identity": scope.get("initiating_loader_realm_identity"),
        "class_name": scope.get("class_name"),
        "member_kind": scope.get("member_kind") or decision.get("fact_kind"),
        "member_name": scope.get("member_name"),
        "descriptor": scope.get("descriptor"),
        "grouping_rule_version": "binary-reported-api-v1",
    })


def _aggregate_by_api(
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
) -> list[dict[str, Any]]:
    decision_by_change = {
        item["change_fact_identity"]: item for item in decisions.authoritative_decisions
    }
    groups: dict[str, list[dict[str, Any]]] = {}
    for result in traces.formal_results:
        decision = decision_by_change.get(result["change_fact_identity"])
        if not decision:
            raise BinaryOutputError(
                "BINARY_OUTPUT_TRACE_DECISION_UNBOUND",
                str(result.get("trace_result_identity")),
            )
        reported = _reported_api_identity(
            decision,
            runtime_profile_identity=profile.identity,
            analysis_context_identity=decisions.analysis_context_identity,
        )
        groups.setdefault(reported, []).append({"result": result, "decision": decision})
    priority = {
        "reachable": 3,
        "uncertain": 2,
        "not_found_in_static_analysis": 1,
        "not_analyzed": 0,
    }
    linkage_priority = {
        "compatible_or_not_applicable": 0,
        "undetermined": 1,
        "incompatible_if_executed": 2,
    }
    output = []
    for reported, items in sorted(groups.items()):
        results = [item["result"] for item in items]
        primary = max(results, key=lambda item: priority[item["reachability_status"]])
        primary_priority = priority[primary["reachability_status"]]
        linkage_results = [
            item for item in results
            if priority[item["reachability_status"]] == primary_priority
        ]
        scopes = [item["decision"]["fact_scope"] for item in items]
        target_scope = scopes[0]
        target_owner = str(target_scope.get("class_name") or "").replace("/", ".")
        target_member = str(target_scope.get("member_name") or "")
        target_descriptor = str(target_scope.get("descriptor") or "")
        target_signature = (
            jvm_method_parameter_signature(target_descriptor)
            if target_descriptor.startswith("(") else ""
        )
        target_label = (
            target_owner
            if not target_member or target_member == "<class>"
            else f"{target_owner}.{target_member}{target_signature}"
        )
        path_records = []
        path_identities = set()
        for result in results:
            for path in result.get("paths") or ():
                if path.get("path_identity") in path_identities:
                    continue
                path_identities.add(path.get("path_identity"))
                nodes = []
                for edge in path.get("edges") or ():
                    owner = str(edge.get("caller_class_name") or "").replace("/", ".")
                    member = str(edge.get("caller_member_name") or "")
                    descriptor = str(edge.get("caller_descriptor") or "")
                    signature = (
                        jvm_method_parameter_signature(descriptor)
                        if descriptor.startswith("(") else ""
                    )
                    label = f"{owner}.{member}{signature}" if owner and member else ""
                    if label and (not nodes or nodes[-1] != label):
                        nodes.append(label)
                if target_label and (not nodes or nodes[-1] != target_label):
                    nodes.append(target_label)
                entrypoint_records = list(path.get("entrypoint_records") or ())
                entry_kinds = sorted({
                    str(item.get("entry_kind") or "")
                    for item in entrypoint_records
                    if item.get("entry_kind")
                })
                mechanism_kinds = []
                for edge in path.get("edges") or ():
                    kind = _public_edge_kind(str(edge.get("edge_kind") or ""))
                    if kind and kind not in mechanism_kinds:
                        mechanism_kinds.append(kind)
                path_records.append({
                    "path_identity": path.get("path_identity"),
                    "path_certainty": path.get("path_certainty"),
                    "path_text": " → ".join(nodes),
                    "edge_count": len(path.get("edges") or ()),
                    "entry_kinds": entry_kinds,
                    "entry_kind_labels": [
                        ENTRY_KIND_LABELS.get(item, item) for item in entry_kinds
                    ],
                    "entrypoint_dependency_coords": sorted({
                        str(item.get("dependency_coord") or "")
                        for item in entrypoint_records
                        if item.get("dependency_coord")
                    }),
                    "entrypoint_activation_reasons": sorted({
                        str(item.get("activation_reason") or "")
                        for item in entrypoint_records
                        if item.get("activation_reason")
                    }),
                    "mechanism_kinds": mechanism_kinds,
                    "mechanism_labels": [
                        EDGE_KIND_LABELS.get(item, item)
                        for item in mechanism_kinds
                    ],
                })
        dependency_artifacts = []
        dependency_keys = set()
        for item in items:
            for artifact in item["decision"].get("dependency_artifacts") or ():
                key = (
                    str(artifact.get("side") or ""),
                    str(artifact.get("artifact_instance_identity") or ""),
                )
                if key not in dependency_keys:
                    dependency_keys.add(key)
                    dependency_artifacts.append(dict(artifact))
        output.append({
            "reported_api_identity": reported,
            "display_owner": scopes[0].get("class_name"),
            "display_member": scopes[0].get("member_name"),
            "display_descriptor": scopes[0].get("descriptor"),
            "display_member_kind": scopes[0].get("member_kind") or items[0]["decision"].get("fact_kind"),
            "reachability_status": primary["reachability_status"],
            "is_reachable": any(item["is_reachable"] for item in results),
            "impact_conclusion": (
                "probable_impact"
                if any(item["impact_conclusion"] == "probable_impact" for item in results)
                else "inconclusive"
            ),
            "static_linkage_status": max(
                (
                    item.get("static_linkage_status") or "undetermined"
                    for item in linkage_results
                ),
                key=lambda value: linkage_priority.get(value, 1),
            ),
            "runtime_verification_status": (
                "required_not_executed"
                if any(bool(item.get("is_reachable")) for item in results)
                else "undetermined"
            ),
            "runtime_verification_executed_by_system": False,
            "path_set_complete": all(item["path_set_complete"] for item in results),
            "exact_path_exists": any(item["exact_path_exists"] for item in results),
            "possible_path_exists": any(item["possible_path_exists"] for item in results),
            "paths": sorted(path_records, key=lambda item: (
                str(item.get("path_certainty") or ""),
                str(item.get("path_text") or ""),
                str(item.get("path_identity") or ""),
            )),
            "contributing_projection_ids": sorted(item["projection_identity"] for item in results),
            "contributing_projection_assessment_ids": sorted(
                item["projection_assessment_identity"] for item in results
            ),
            "contributing_change_fact_ids": sorted(item["change_fact_identity"] for item in results),
            "dependency_artifacts": dependency_artifacts,
            "dependency_lineages": sorted({
                str(item.get("logical_dependency_lineage") or "")
                for item in dependency_artifacts
                if item.get("logical_dependency_lineage")
            }),
            "base_dependency_coords": sorted({
                str(item.get("coord") or "")
                for item in dependency_artifacts
                if item.get("side") == "base" and item.get("coord")
            }),
            "current_dependency_coords": sorted({
                str(item.get("coord") or "")
                for item in dependency_artifacts
                if item.get("side") == "current" and item.get("coord")
            }),
            "target_jvm_identities": [profile.identity],
            "primary_projection_id": primary["projection_identity"],
            "primary_projection_selection_reason": "highest_reachability_then_stable_input_order_v1",
            "projection_coverage_statuses": sorted({
                next(
                    assessment["projection_coverage_status"]
                    for assessment in decisions.projection_assessments
                    if assessment["projection_assessment_identity"]
                    == item["projection_assessment_identity"]
                )
                for item in results
            }),
        })
    return output


def build_output_payloads(
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
    *,
    source_overlay: SourceOverlayResult | None = None,
    source_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_inputs = dict(source_inputs or {})
    assessments = {
        item["projection_assessment_identity"]: item
        for item in decisions.projection_assessments
    }
    unprojectable = [
        decision
        for decision in decisions.authoritative_decisions
        if any(
            assessment["decision_identity"] == decision["decision_identity"]
            and assessment["analysis_projection_status"] == "unsupported"
            for assessment in decisions.projection_assessments
        )
    ]
    by_api = _aggregate_by_api(decisions, traces, profile)
    exact_entrypoints = {
        str(item.get("member_identity") or "")
        for item in traces.entrypoint_records
        if item.get("path_certainty") == "exact" and item.get("member_identity")
    }
    possible_entrypoints = {
        str(item.get("member_identity") or "")
        for item in traces.entrypoint_records
        if item.get("path_certainty") == "possible"
        and item.get("member_identity") not in exact_entrypoints
    }
    summary = {
        "schema": "java-upgrade-analyzer.binary-summary.v1",
        "analysis_context_identity": decisions.analysis_context_identity,
        "current_runtime_profile_identity": profile.identity,
        "authoritative_change_fact_count": len(decisions.authoritative_decisions),
        "diagnostic_candidate_fact_count": len(decisions.diagnostic_decisions),
        "excluded_decision_count": len(decisions.excluded_decisions),
        "confirmed_unprojectable_fact_count": len(unprojectable),
        "formal_projection_count": len(decisions.formal_projections),
        "candidate_projection_plan_count": len(decisions.candidate_projection_plans),
        "formal_trace_result_count": len(traces.formal_results),
        "candidate_trace_result_count": len(traces.candidate_results),
        "unique_reported_api_total": len(by_api),
        "reachable_total": sum(item["reachability_status"] == "reachable" for item in by_api),
        "uncertain_total": sum(item["reachability_status"] == "uncertain" for item in by_api),
        "not_found_in_static_analysis_total": sum(
            item["reachability_status"] == "not_found_in_static_analysis" for item in by_api
        ),
        "not_analyzed_total": sum(item["reachability_status"] == "not_analyzed" for item in by_api),
        "probable_impact_total": sum(item["impact_conclusion"] == "probable_impact" for item in by_api),
        "runtime_verified_total": 0,
        "resource_activation_reachable_total": sum(
            item.get("activation_status") == "reachable"
            for item in traces.resource_activation_results
        ),
        "resource_activation_result_count": len(traces.resource_activation_results),
        "exact_entrypoint_count": len(exact_entrypoints),
        "possible_entrypoint_count": len(possible_entrypoints),
        "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
        "formal_path_set_complete": all(item["path_set_complete"] for item in by_api),
        "decision_coverage_status": decisions.coverage_status,
        "trace_coverage_status": traces.coverage_status,
        "source_inputs": source_inputs,
    }
    return {
        "binary_decisions.json": {
            "schema": "java-upgrade-analyzer.binary-decisions.v1",
            "analysis_context_identity": decisions.analysis_context_identity,
            "active_decision_snapshot_identity": decisions.active_snapshots["decision"].identity,
            "authoritative_change_facts": list(decisions.authoritative_decisions),
            "diagnostic_candidate_facts": list(decisions.diagnostic_decisions),
            "excluded_decisions": list(decisions.excluded_decisions),
        },
        "binary_projections.json": {
            "schema": "java-upgrade-analyzer.binary-projections.v1",
            "active_assessment_snapshot_identity": decisions.active_snapshots["assessment"].identity,
            "active_formal_projection_snapshot_identity": decisions.active_snapshots["formal_projection"].identity,
            "active_candidate_projection_snapshot_identity": decisions.active_snapshots["candidate_projection"].identity,
            "authoritative_projection_assessments": list(decisions.projection_assessments),
            "formal_projections": list(decisions.formal_projections),
            "candidate_projection_plans": list(decisions.candidate_projection_plans),
            "confirmed_unprojectable_facts": unprojectable,
        },
        "binary_formal_results.json": {
            "schema": "java-upgrade-analyzer.binary-formal-results.v1",
            "results": list(traces.formal_results),
            "by_api": by_api,
            "resource_activation_results": list(traces.resource_activation_results),
        },
        "binary_candidate_results.json": {
            "schema": "java-upgrade-analyzer.binary-candidate-results.v1",
            "results": list(traces.candidate_results),
        },
        "binary_entrypoints.json": {
            "schema": "java-upgrade-analyzer.binary-entrypoint-discovery.v1",
            "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
            "coverage_status": traces.entrypoint_coverage_status,
            "coverage_gaps": list(traces.entrypoint_coverage_gaps),
            "exact_entrypoint_count": len(exact_entrypoints),
            "possible_entrypoint_count": len(possible_entrypoints),
            "records": list(traces.entrypoint_records),
        },
        "binary_coverage.json": {
            "schema": "java-upgrade-analyzer.binary-coverage.v1",
            "decision_coverage_status": decisions.coverage_status,
            "decision_coverage_gaps": list(decisions.coverage_gaps),
            "trace_coverage_status": traces.coverage_status,
            "trace_coverage_gaps": list(traces.coverage_gaps),
            "batch_graph_stats": dict(traces.graph_stats or {}),
            "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
            "source_overlay": asdict(source_overlay) if source_overlay else {
                "coverage_status": "not_provided",
            },
            "source_inputs": source_inputs,
        },
        "binary_summary.json": summary,
    }


def _write_csv_sidecar(path: Path, rows: list[dict[str, Any]]) -> Path:
    columns = [
        "reported_api_identity", "display_owner", "display_member", "display_descriptor",
        "reachability_status", "is_reachable", "impact_conclusion", "static_linkage_status",
        "runtime_verification_status", "runtime_verification_executed_by_system",
        "path_set_complete", "exact_path_exists", "possible_path_exists",
        "primary_projection_id",
    ]
    with open_csv_write(path) as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_binary_generation(
    output_root: str | Path,
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
    *,
    policy_identities: Mapping[str, str],
    source_overlay: SourceOverlayResult | None = None,
    source_inputs: Mapping[str, Any] | None = None,
    additional_sidecars: Mapping[str, bytes | Path] | None = None,
) -> dict[str, Any]:
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_OUTPUT_ROOT_INVALID",
        create=True,
    )
    generations = _physical_generation_namespace(
        root,
        create=True,
        reason_code="BINARY_OUTPUT_ROOT_INVALID",
    )
    payloads = build_output_payloads(
        decisions,
        traces,
        profile,
        source_overlay=source_overlay,
        source_inputs=source_inputs,
    )
    staging = make_short_temp_dir(
        prefix="binary-output-sidecars",
        preferred_root=root,
        strict_preferred=True,
    )
    try:
        sidecar_sources: dict[str, Path] = {}
        for name, payload in payloads.items():
            sidecar_sources[name] = write_json_streaming(staging / name, payload)
        sidecar_sources["binary_formal_results.csv"] = _write_csv_sidecar(
            staging / "binary_formal_results.csv",
            payloads["binary_formal_results.json"]["by_api"],
        )
        for name, content in (additional_sidecars or {}).items():
            safe_name = Path(str(name or "")).name
            if not safe_name or safe_name != str(name) or safe_name in sidecar_sources:
                raise BinaryOutputError(
                    "BINARY_OUTPUT_ADDITIONAL_SIDECAR_INVALID", str(name)
                )
            if not isinstance(content, (bytes, Path)) or (
                isinstance(content, Path) and not content.is_file()
            ):
                raise BinaryOutputError(
                    "BINARY_OUTPUT_ADDITIONAL_SIDECAR_INVALID",
                    f"{name} must be bytes or an existing Path",
                )
            if isinstance(content, bytes):
                staged = staging / safe_name
                staged.write_bytes(content)
                sidecar_sources[safe_name] = staged
            else:
                sidecar_sources[safe_name] = content
        sidecar_identities = {
            name: _sha256_file(content)
            for name, content in sidecar_sources.items()
        }
        effective_policy_identities = {
            **dict(policy_identities),
            "generation_attachment": _identity(
                "binary_generation_attachment_policy_identity",
                {"policy": _GENERATION_ATTACHMENT_POLICY},
            ),
        }
        generation = ResultGeneration(
            decisions.analysis_context_identity,
            decisions.active_snapshots,
            traces.trace_result_set_digest,
            sidecar_identities,
            effective_policy_identities,
        )
        destination = generations / generation.identity
        manifest = {
            "schema": _RESULT_GENERATION_SCHEMA,
            "result_generation_identity": generation.identity,
            "analysis_context_identity": decisions.analysis_context_identity,
            "authority": "binary_first",
            "active_snapshot_identities": {
                layer: snapshot.identity
                for layer, snapshot in decisions.active_snapshots.items()
            },
            "trace_result_set_digest": traces.trace_result_set_digest,
            "sidecar_content_identities": sidecar_identities,
            "policy_identities": effective_policy_identities,
            "attachment_policy": _GENERATION_ATTACHMENT_POLICY,
        }

        def existing_generation_is_valid() -> bool:
            try:
                _physical_generation_directory(
                    generations,
                    generation.identity,
                    reason_code="BINARY_GENERATION_IDENTITY_COLLISION",
                )
            except BinaryOutputError:
                return False
            existing_manifest = destination / "result_generation.json"
            try:
                existing = json.loads(existing_manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                return False
            if not isinstance(existing, Mapping):
                return False
            if any(
                (destination / name).exists()
                or (destination / name).is_symlink()
                for name in _TRANSIENT_FACT_STORE_SIDECARS
            ) or (destination / "generation_attachments.json").exists() or (
                destination / "generation_attachments.json"
            ).is_symlink():
                return False
            content_valid = all(
                (destination / name).is_file()
                and _sha256_file(destination / name) == expected
                for name, expected in sidecar_identities.items()
            )
            return bool(
                content_valid
                and existing.get("result_generation_identity") == generation.identity
                and _result_generation_identity_from_manifest(existing)
                == generation.identity
                and existing.get("sidecar_content_identities") == sidecar_identities
            )

        # A generation installed by this call has already had every file and
        # its private directory synchronized.  Existing generations (including
        # one that wins the publication race below) need a fresh durability
        # proof because this process cannot rely on another writer's ordering.
        try:
            os.lstat(destination)
        except FileNotFoundError:
            requires_existing_generation_barrier = False
        except OSError as error:
            raise BinaryOutputError(
                "BINARY_GENERATION_IDENTITY_COLLISION",
                f"{destination}: {error}",
            ) from error
        else:
            requires_existing_generation_barrier = True
        if requires_existing_generation_barrier:
            if not existing_generation_is_valid():
                raise BinaryOutputError(
                    "BINARY_GENERATION_IDENTITY_COLLISION", str(destination)
                )
        else:
            generation_temp = make_short_temp_dir(
                prefix="binary-generation",
                preferred_root=generations,
                strict_preferred=True,
            )
            try:
                for name, content in sidecar_sources.items():
                    target = generation_temp / name
                    shutil.copyfile(content, target)
                    if _sha256_file(target) != sidecar_identities[name]:
                        raise BinaryOutputError(
                            "BINARY_OUTPUT_SIDECAR_CHANGED_DURING_COPY", str(content)
                        )
                    # copyfile does not make the destination bytes durable.
                    # Synchronize every immutable sidecar before the directory
                    # can become visible under its content-addressed name.
                    _fsync_regular_file(target)
                generation_manifest_path = generation_temp / "result_generation.json"
                generation_manifest_path.write_bytes(_json_bytes(manifest))
                _fsync_regular_file(generation_manifest_path)
                # Persist all child entries before making the content-addressed
                # directory visible.  The parent is synchronized after rename,
                # which is the commit point for this generation entry.
                _fsync_directory(generation_temp)
                try:
                    os.replace(generation_temp, destination)
                except OSError as error:
                    # Another process may have atomically published the exact
                    # same content-addressed generation after our existence
                    # check.  Treat that race as idempotent only after full
                    # content verification.
                    if (
                        error.errno not in {errno.EEXIST, errno.ENOTEMPTY}
                        or not existing_generation_is_valid()
                    ):
                        raise
                    requires_existing_generation_barrier = True
                else:
                    _fsync_directory(generations)
            finally:
                primary = sys.exc_info()[1]
                actions = []
                if generation_temp.exists():
                    actions.append((
                        f"remove temporary generation {generation_temp}",
                        lambda: _rmtree_missing_ok(generation_temp),
                    ))
                _attempt_cleanups(actions, primary=primary)
        if requires_existing_generation_barrier:
            # Reused bytes may have been published by a writer that failed
            # before its final parent-directory synchronization.  Re-prove all
            # durability ordering locally before validation.
            _make_generation_durable(
                destination,
                (*sidecar_identities, "result_generation.json"),
            )
        # fsync(binary_generations) commits entries *inside* that directory,
        # but not the binary_generations entry in output_root.  Commit the
        # complete immutable generation namespace before validation starts so
        # a failed/aborted validation remains reusable after a host crash.
        # Activation deliberately repeats this root barrier later because it
        # must also order the validation attachment before the active pointer.
        _fsync_directory(root)
        return {
            **manifest,
            "generation_directory": str(destination),
            "active_generation_descriptor": "",
        }
    finally:
        primary = sys.exc_info()[1]
        actions = []
        if staging.exists():
            actions.append((
                f"remove output staging directory {staging}",
                lambda: _rmtree_missing_ok(staging),
            ))
        _attempt_cleanups(actions, primary=primary)


def activate_binary_generation(
    output_root: str | Path,
    manifest: Mapping[str, Any],
    *,
    validation_result: Mapping[str, Any] | None = None,
    activation_identity: str = "",
    activation_record: MutableMapping[str, Any] | None = None,
    defer_publication: bool = False,
    publication_guard: Callable[[], Any] | None = None,
    publication_dry_run: bool = False,
) -> str:
    _discard_current_direct_seal_capability()
    if publication_guard is not None and not callable(publication_guard):
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_INVALID",
            repr(publication_guard),
        )
    root = _canonical_physical_output_root(
        output_root,
        reason_code="BINARY_GENERATION_ACTIVATION_TARGET_INVALID",
    )
    _invalidate_direct_seal_capabilities_for_root(root)
    generation_identity = manifest.get("result_generation_identity")
    if not _is_sha256_identity(generation_identity):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_TARGET_INVALID", str(generation_identity or "")
        )
    try:
        root_resolved = root
        generations = root_resolved / "binary_generations"
        destination = generations / generation_identity
        generations_resolved = generations.resolve(strict=True)
        destination_resolved = destination.resolve(strict=True)
    except (OSError, RuntimeError):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_TARGET_INVALID",
            str(root / "binary_generations" / generation_identity),
        ) from None
    if (
        generations_resolved != generations
        or destination_resolved != destination
        or destination_resolved.parent != generations_resolved
        or not destination_resolved.is_dir()
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_TARGET_INVALID", str(destination)
        )
    if not isinstance(validation_result, Mapping):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_REQUIRED", generation_identity
        )

    manifest_path = destination / "result_generation.json"
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise OSError("generation manifest is not a regular file")
        persisted_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(manifest_path)
        ) from None
    identity_fields = (
        "schema",
        "result_generation_identity",
        "analysis_context_identity",
        "authority",
        "active_snapshot_identities",
        "trace_result_set_digest",
        "sidecar_content_identities",
        "policy_identities",
        "attachment_policy",
    )
    if not isinstance(persisted_manifest, Mapping) or any(
        persisted_manifest.get(field) != manifest.get(field)
        for field in identity_fields
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_MANIFEST_MISMATCH", str(manifest_path)
        )

    sidecar_identities = manifest.get("sidecar_content_identities")
    if not isinstance(sidecar_identities, Mapping):
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(manifest_path)
        )
    for name in _TRANSIENT_FACT_STORE_SIDECARS:
        transient = destination / name
        if transient.exists() or transient.is_symlink():
            raise BinaryOutputError(
                "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(transient)
            )
    obsolete_attachment = destination / "generation_attachments.json"
    if obsolete_attachment.exists() or obsolete_attachment.is_symlink():
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED",
            str(obsolete_attachment),
        )
    for name, expected in sidecar_identities.items():
        if not _is_safe_sidecar_basename(name) or not _is_sha256_identity(expected):
            raise BinaryOutputError(
                "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(name)
            )
        path = destination / name
        try:
            observed = os.lstat(path)
        except OSError:
            observed = None
        if (
            observed is None
            or stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
        ):
            raise BinaryOutputError(
                "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(path)
            )
    if _result_generation_identity_from_manifest(manifest) != generation_identity:
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_MANIFEST_MISMATCH", str(manifest_path)
        )
    # Content is proved once from stable descriptors immediately before each
    # activation guard below.  Deferred publication is proved once here before
    # its private transaction and once again at its later public boundary.
    publication_authority = _generation_publication_authority(
        destination, persisted_manifest
    )
    if publication_dry_run:
        if (
            publication_authority is None
            or publication_authority["authority_mode"]
            != "candidate_source_measurement"
            or publication_authority["public_activation_allowed"]
        ):
            raise BinaryOutputError(
                "BINARY_GENERATION_PUBLICATION_DRY_RUN_FORBIDDEN",
                str(destination),
            )
    elif publication_authority is not None:
        # Reuse the same capability check used at the integrity/commit
        # boundary.  Candidate generations remain forbidden; only the exact
        # recapture root held by this process may exercise the descriptor
        # transaction for timing.
        _require_generation_publication_allowed(
            destination, persisted_manifest
        )

    expected_validation = {
        key: value
        for key, value in validation_result.items()
        if key != "validation_result_path"
    }
    if not is_complete_v3_validation_result(expected_validation, manifest):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_REQUIRED", generation_identity
        )
    validation_identity = expected_validation["validation_run_identity"]
    validation_dir = destination / "validation"
    validation_path = validation_dir / f"{validation_identity}.json"
    try:
        validation_dir_resolved = validation_dir.resolve(strict=True)
        validation_path_resolved = validation_path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        ) from None
    if (
        validation_dir_resolved != validation_dir
        or validation_path_resolved != validation_path
        or validation_path_resolved.parent != validation_dir_resolved
        or validation_path.is_symlink()
        or not validation_path.is_file()
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    declared_validation_path = validation_result.get("validation_result_path")
    if declared_validation_path:
        try:
            declared_validation_path = Path(str(declared_validation_path)).resolve(
                strict=True
            )
        except (OSError, RuntimeError):
            declared_validation_path = None
        if declared_validation_path != validation_path:
            raise BinaryOutputError(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                str(validation_path),
            )
    try:
        validation_bytes = validation_path.read_bytes()
        persisted_validation = json.loads(validation_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        ) from None
    if (
        not isinstance(persisted_validation, Mapping)
        or not is_complete_v3_validation_result(
            persisted_validation, manifest
        )
        or validation_bytes != _json_bytes(expected_validation)
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID", str(validation_path)
        )
    validation_result_sha256 = hashlib.sha256(validation_bytes).hexdigest()
    # The active descriptor is the final durable commit point. Re-establish
    # durability for every byte it names, including the validation attachment
    # and its newly-created directory entry, before taking the activation lock.
    _make_generation_durable(
        destination,
        (
            *sidecar_identities,
            "result_generation.json",
            validation_path.relative_to(destination),
        ),
        nested_directories=(validation_dir,),
    )
    # ``binary_generations`` itself may have been created by this run.  Commit
    # that entry in the output root before the active pointer can be renamed
    # into the same directory.  The later root fsync in
    # _write_active_descriptor is a separate, ordered commit of the pointer.
    _fsync_directory(root_resolved)
    active = {
        "schema": _ACTIVE_DESCRIPTOR_SCHEMA,
        "result_generation_identity": generation_identity,
        "generation_directory": f"binary_generations/{generation_identity}",
        "validation_run_identity": (
            str((validation_result or {}).get("validation_run_identity") or "")
        ),
        "validation_result_sha256": validation_result_sha256,
    }
    requested_activation_identity = str(activation_identity or "")
    if not requested_activation_identity:
        requested_activation_identity = hashlib.sha256(os.urandom(32)).hexdigest()
    if not _is_sha256_identity(requested_activation_identity):
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_ACTIVATION_IDENTITY_INVALID",
            requested_activation_identity,
        )
    if publication_dry_run:
        probed_device = _prepare_post_guard_stat_recheck(root_resolved)
        verified_publication_authority, integrity_proof = (
            _verify_candidate_generation_integrity_with_proof(
                root_resolved, active
            )
        )
        if not _exact_mapping_equal(
            verified_publication_authority, publication_authority
        ):
            raise BinaryOutputError(
                "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                "candidate publication authority changed before its guard",
            )
        stat_recheck_allowed = (
            _proof_supports_post_guard_stat_recheck(
                integrity_proof,
                root_resolved,
                probed_device=probed_device,
            )
        )
        _run_publication_guard(
            verified_publication_authority,
            publication_guard,
            result_generation_identity=generation_identity,
            validation_run_identity=active["validation_run_identity"],
            validation_result_sha256=active[
                "validation_result_sha256"
            ],
            activation_identity=requested_activation_identity,
        )
        _post_guard_generation_integrity_recheck(
            root_resolved,
            active,
            verified_publication_authority,
            integrity_proof,
            stat_recheck_allowed=stat_recheck_allowed,
            candidate_measurement=True,
        )
        if activation_record is not None:
            activation_record.clear()
            activation_record.update({
                "activation_identity": requested_activation_identity,
                "activation_candidate_private": True,
                "activation_candidate_nonpublishable": True,
                "activation_integrity_dry_run": True,
            })
        return ""
    try:
        with _active_generation_lock(root_resolved):
            active_path = root_resolved / "active_binary_generation.json"
            current, descriptor_identity = _read_active_descriptor(
                root_resolved, missing_ok=True
            )
            pending_raw, pending_identity = _read_active_descriptor(
                root_resolved,
                missing_ok=True,
                relative_path=_PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            if defer_publication:
                predecessor = _active_descriptor_core(current)
                if current is not None and not _public_active_is_sealed(current):
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_ACTIVATION_RECEIPT_INVALID",
                        str(active_path),
                    )
                pending = (
                    _pending_active_descriptor(pending_raw)
                    if pending_raw is not None
                    else None
                )
                expected_pending = {
                    **active,
                    "activation_identity": requested_activation_identity,
                    "activation_predecessor": predecessor,
                    "activation_state": "pending",
                }
                if pending_raw is not None:
                    if pending != expected_pending:
                        raise BinaryOutputError(
                            "BINARY_ACTIVE_GENERATION_ACTIVATION_IN_PROGRESS",
                            str(
                                root_resolved
                                / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                            ),
                        )
                # Materialize/validate the private descriptor parent before
                # the filesystem probe and generation snapshot so those
                # operations cannot invalidate a clean proof themselves.
                _active_descriptor_destination(
                    root_resolved,
                    _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                )
                probed_device = _prepare_post_guard_stat_recheck(
                    root_resolved
                )
                (
                    verified_publication_authority,
                    integrity_proof,
                ) = _verify_pending_generation_integrity_with_proof(
                    root_resolved, expected_pending
                )
                if not (
                    (
                        publication_authority is None
                        and verified_publication_authority is None
                    )
                    or _exact_mapping_equal(
                        publication_authority,
                        verified_publication_authority,
                    )
                ):
                    raise BinaryOutputError(
                        "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                        "publication authority changed before its guard",
                    )
                stat_recheck_allowed = (
                    _proof_supports_post_guard_stat_recheck(
                        integrity_proof,
                        root_resolved,
                        probed_device=probed_device,
                    )
                )
                pending_descriptor_before_guard = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved,
                        pending,
                        pending_identity,
                        relative_path=(
                            _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                        ),
                    )
                )
                current_descriptor_before_guard = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved, current, descriptor_identity
                    )
                )
                # This remains the last authority check; exact descriptor
                # integrity is re-proved after a re-entrant callback returns.
                _run_publication_guard(
                    verified_publication_authority,
                    publication_guard,
                    result_generation_identity=generation_identity,
                    validation_run_identity=active[
                        "validation_run_identity"
                    ],
                    validation_result_sha256=active[
                        "validation_result_sha256"
                    ],
                    activation_identity=requested_activation_identity,
                )
                pending_descriptor_after_guard = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved,
                        pending,
                        pending_identity,
                        relative_path=(
                            _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                        ),
                    )
                )
                current_descriptor_after_guard = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved, current, descriptor_identity
                    )
                )
                _assert_descriptor_reproof_unchanged(
                    pending_descriptor_before_guard,
                    pending_descriptor_after_guard,
                    root_resolved
                    / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                )
                _assert_descriptor_reproof_unchanged(
                    current_descriptor_before_guard,
                    current_descriptor_after_guard,
                    active_path,
                )
                _post_guard_generation_integrity_recheck(
                    root_resolved,
                    expected_pending,
                    verified_publication_authority,
                    integrity_proof,
                    stat_recheck_allowed=stat_recheck_allowed,
                )
                pending_descriptor_before_commit = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved,
                        pending,
                        pending_identity,
                        relative_path=(
                            _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                        ),
                    )
                )
                current_descriptor_before_commit = (
                    _stable_reprove_transaction_descriptor(
                        root_resolved, current, descriptor_identity
                    )
                )
                _assert_descriptor_reproof_unchanged(
                    pending_descriptor_before_guard,
                    pending_descriptor_before_commit,
                    root_resolved
                    / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                )
                _assert_descriptor_reproof_unchanged(
                    current_descriptor_before_guard,
                    current_descriptor_before_commit,
                    active_path,
                )
                if pending_raw is None:
                    _write_active_descriptor(
                        root_resolved,
                        expected_pending,
                        expected_file_identity=pending_identity,
                        expect_missing=True,
                        relative_path=(
                            _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                        ),
                    )
                if activation_record is not None:
                    activation_record.clear()
                    activation_record.update({
                        "activation_identity": requested_activation_identity,
                        "activation_predecessor": predecessor,
                        "activation_candidate_private": True,
                    })
                return str(
                    root_resolved / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                )
            if pending_raw is not None:
                # A private receipt is owned by the deferred report/gate
                # transaction.  Even an exact generation/token match does not
                # authorize the direct path to bypass that transaction or leave
                # a stale receipt capable of rolling the new public pointer
                # back later.
                raise BinaryOutputError(
                    "BINARY_ACTIVE_GENERATION_ACTIVATION_IN_PROGRESS",
                    str(
                        root_resolved
                        / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            publish_active_descriptor = False
            if (
                isinstance(current, Mapping)
                and current.get("activation_identity")
                == requested_activation_identity
            ):
                current_core = _active_descriptor_core(current)
                predecessor_value = current.get("activation_predecessor")
                predecessor = _active_descriptor_core(predecessor_value)
                if (
                    current_core != active
                    or "activation_predecessor" not in current
                    or (
                        predecessor_value is not None and predecessor is None
                    )
                ):
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_ACTIVATION_RECEIPT_INVALID",
                        requested_activation_identity,
                    )
            else:
                predecessor = _active_descriptor_core(current)
                if current is not None and predecessor is None:
                    raise BinaryOutputError(
                        "BINARY_ACTIVE_GENERATION_ACTIVATION_RECEIPT_INVALID",
                        str(active_path),
                    )
                active = {
                    **active,
                    "activation_identity": requested_activation_identity,
                    "activation_predecessor": predecessor,
                }
                publish_active_descriptor = True
            # Direct activation is itself a public commit.  Re-prove every
            # generation and validation byte while holding the same lock that
            # protects the active pointer, then run the caller's authority
            # guard immediately before accepting or writing that pointer.
            # Materialize the private descriptor parent before capturing the
            # generation/root proof.  The stable absence proofs below then
            # detect a re-entrant guard that tries to install a deferred receipt.
            _active_descriptor_destination(
                root_resolved,
                _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            probed_device = _prepare_post_guard_stat_recheck(
                root_resolved
            )
            (
                verified_publication_authority,
                integrity_proof,
            ) = _verify_pending_generation_integrity_with_proof(
                root_resolved, active
            )
            if not (
                (
                    publication_authority is None
                    and verified_publication_authority is None
                )
                or _exact_mapping_equal(
                    publication_authority,
                    verified_publication_authority,
                )
            ):
                raise BinaryOutputError(
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                    "publication authority changed before its guard",
                )
            stat_recheck_allowed = (
                _proof_supports_post_guard_stat_recheck(
                    integrity_proof,
                    root_resolved,
                    probed_device=probed_device,
                )
            )
            current_descriptor_before_guard = (
                _stable_reprove_transaction_descriptor(
                    root_resolved, current, descriptor_identity
                )
            )
            pending_descriptor_before_guard = (
                _stable_reprove_transaction_descriptor(
                    root_resolved,
                    None,
                    None,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            _run_publication_guard(
                verified_publication_authority,
                publication_guard,
                result_generation_identity=generation_identity,
                validation_run_identity=active["validation_run_identity"],
                validation_result_sha256=active[
                    "validation_result_sha256"
                ],
                activation_identity=requested_activation_identity,
            )
            current_descriptor_after_guard = (
                _stable_reprove_transaction_descriptor(
                    root_resolved, current, descriptor_identity
                )
            )
            pending_descriptor_after_guard = (
                _stable_reprove_transaction_descriptor(
                    root_resolved,
                    None,
                    None,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            _assert_descriptor_reproof_unchanged(
                current_descriptor_before_guard,
                current_descriptor_after_guard,
                active_path,
            )
            _assert_descriptor_reproof_unchanged(
                pending_descriptor_before_guard,
                pending_descriptor_after_guard,
                root_resolved / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            _post_guard_generation_integrity_recheck(
                root_resolved,
                active,
                verified_publication_authority,
                integrity_proof,
                stat_recheck_allowed=stat_recheck_allowed,
            )
            current_descriptor_before_commit = (
                _stable_reprove_transaction_descriptor(
                    root_resolved, current, descriptor_identity
                )
            )
            pending_descriptor_before_commit = (
                _stable_reprove_transaction_descriptor(
                    root_resolved,
                    None,
                    None,
                    relative_path=(
                        _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )
            )
            _assert_descriptor_reproof_unchanged(
                current_descriptor_before_guard,
                current_descriptor_before_commit,
                active_path,
            )
            _assert_descriptor_reproof_unchanged(
                pending_descriptor_before_guard,
                pending_descriptor_before_commit,
                root_resolved / _PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            if publish_active_descriptor:
                _write_active_descriptor(
                    root_resolved,
                    active,
                    expected_file_identity=descriptor_identity,
                    expect_missing=current is None,
                )
            if activation_record is not None:
                activation_record.clear()
                activation_record.update({
                    "activation_identity": requested_activation_identity,
                    "activation_predecessor": predecessor,
                })
            if publish_active_descriptor:
                _try_install_direct_seal_capability(
                    root_resolved,
                    active,
                    predecessor=predecessor,
                    descriptor_before_identity=descriptor_identity,
                    proof=integrity_proof,
                    probed_device=probed_device,
                )
            return str(active_path)
    except _ActiveGenerationLockAcquireTimeout as error:
        raise BinaryOutputError(
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT", str(error)
        ) from error


__all__ = [
    "BinaryOutputError",
    "activate_binary_generation",
    "binary_publication_reauthorization_receipt",
    "build_output_payloads",
    "commit_pending_binary_generation",
    "compare_and_restore_active_binary_generation",
    "is_complete_v3_validation_result",
    "publish_pending_binary_generation",
    "prune_unreferenced_binary_generations",
    "read_active_binary_generation",
    "read_binary_generation_publication_authority_binding",
    "read_pending_binary_generation",
    "seal_active_binary_generation",
    "write_binary_generation",
]
