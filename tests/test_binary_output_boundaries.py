from dataclasses import replace
from contextlib import nullcontext
import io
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_output  # noqa: E402
from tests import test_binary_output as binary_output_fixtures  # noqa: E402


class BinaryOutputPureBoundaryTest(unittest.TestCase):
    @staticmethod
    def fixture_bundles():
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        return fixture.profile(), decisions, traces

    def test_public_edge_kind_and_cleanup_failure_matrix(self):
        self.assertEqual(
            binary_output._public_edge_kind("invokedynamic_handle_static"),
            "invokedynamic_handle",
        )
        self.assertEqual(
            binary_output._public_edge_kind("ldc_bootstrap_handle_field"),
            "constant_dynamic_handle",
        )
        self.assertEqual(binary_output._public_edge_kind("invokevirtual"), "invokevirtual")

        primary = RuntimeError("primary")
        binary_output._finish_cleanups(
            primary,
            (("first", OSError("one")), ("second", ValueError("two"))),
        )
        self.assertEqual(len(primary.__notes__), 2)

        first = OSError("first")
        second = ValueError("second")
        with self.assertRaises(OSError) as caught:
            binary_output._finish_cleanups(
                None, (("first-action", first), ("second-action", second)),
            )
        self.assertIs(caught.exception, first)
        self.assertTrue(any("additional cleanup failed" in note for note in first.__notes__))
        self.assertTrue(any("cleanup operation: first-action" in note for note in first.__notes__))
        binary_output._finish_cleanups(None, ())

        class FallbackNotes:
            add_note = None

        fallback = FallbackNotes()
        binary_output._add_cleanup_note(fallback, "first")
        binary_output._add_cleanup_note(fallback, "second")
        self.assertEqual(fallback.__notes__, ["first", "second"])

        class BrokenAddNote:
            __notes__ = ("existing",)

            @staticmethod
            def add_note(_note):
                raise RuntimeError("native notes unavailable")

        broken = BrokenAddNote()
        binary_output._add_cleanup_note(broken, "fallback")
        self.assertEqual(broken.__notes__, ["existing", "fallback"])

        class RejectNotes:
            add_note = None

            def __setattr__(self, name, value):
                if name == "__notes__":
                    raise RuntimeError("read only")
                super().__setattr__(name, value)

        binary_output._add_cleanup_note(RejectNotes(), "ignored")

    @staticmethod
    def stat_result(*, mode=stat.S_IFREG | 0o600, device=1, inode=2,
                    links=1, size=3, mtime=4, ctime=5, atime=6):
        return Mock(
            st_mode=mode,
            st_dev=device,
            st_ino=inode,
            st_nlink=links,
            st_size=size,
            st_mtime_ns=mtime,
            st_ctime_ns=ctime,
            st_atime_ns=atime,
        )

    @staticmethod
    def authority_binding(*, mode="release_evidence", digit="1"):
        binding = {
            "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
            "authority_mode": mode,
            "support_contract_identity": digit * 64,
            "evidence_sha256": str((int(digit) + 1) % 10) * 64,
            "source_implementation_identity": str((int(digit) + 2) % 10) * 64,
        }
        binding["binding_identity"] = binary_output._identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": binding["support_contract_identity"],
                "evidence_sha256": binding["evidence_sha256"],
                "source_implementation_identity": binding[
                    "source_implementation_identity"
                ],
                "authority_mode": binding["authority_mode"],
            },
        )
        return binding

    @staticmethod
    def direct_seal_capability(root: Path, *, digit="1", sequence=0):
        result_identity = digit * 64
        validation_identity = str((int(digit) + 1) % 10) * 64
        validation_sha256 = str((int(digit) + 2) % 10) * 64
        activation_identity = str((int(digit) + 3) % 10) * 64
        root_identity = (1, 2)
        operation_key = binary_output._direct_seal_operation_key(
            root,
            root_identity,
            result_generation_identity=result_identity,
            validation_run_identity=validation_identity,
            validation_result_sha256=validation_sha256,
            activation_identity=activation_identity,
        )
        return binary_output._DirectSealCapability(
            sequence=sequence,
            owner_process_identity=os.getpid(),
            owner_thread_identity=threading.get_ident(),
            canonical_root=root,
            root_identity=root_identity,
            probed_device=1,
            operation_key=operation_key,
            result_generation_identity=result_identity,
            validation_run_identity=validation_identity,
            validation_result_sha256=validation_sha256,
            activation_identity=activation_identity,
            unsealed_descriptor_bytes=b"{}",
            predecessor_bytes=None,
            descriptor_before_identity=None,
            descriptor_after_identity=(3, 4),
            descriptor_snapshot=(1, 2, 1, 2, 3, 4),
            publication_authority_bytes=None,
            directory_snapshots=(),
            file_snapshots=(),
        )

    @staticmethod
    def active_descriptor_core(*, digit="1"):
        generation = digit * 64
        return {
            "schema": binary_output._ACTIVE_DESCRIPTOR_SCHEMA,
            "result_generation_identity": generation,
            "generation_directory": f"binary_generations/{generation}",
            "validation_run_identity": str((int(digit) + 1) % 10) * 64,
            "validation_result_sha256": str((int(digit) + 2) % 10) * 64,
        }

    @staticmethod
    def pending_integrity_fixture(temporary: str):
        root = Path(temporary).resolve()
        generation_identity = "a" * 64
        validation_identity = "b" * 64
        validation_sha256 = "c" * 64
        generation = root / "binary_generations" / generation_identity
        validation_directory = generation / "validation"
        validation_directory.mkdir(parents=True)
        sidecars = {
            name: "d" * 64
            for name in binary_output._REQUIRED_CORE_GENERATION_SIDECARS
        }
        manifest = {
            "result_generation_identity": generation_identity,
            "sidecar_content_identities": sidecars,
        }
        validation = {"validation_run_identity": validation_identity}
        return {
            "root": root,
            "generation": generation,
            "validation_directory": validation_directory,
            "manifest_path": generation / "result_generation.json",
            "validation_path": validation_directory / f"{validation_identity}.json",
            "generation_identity": generation_identity,
            "validation_identity": validation_identity,
            "validation_sha256": validation_sha256,
            "pending": {
                "result_generation_identity": generation_identity,
                "validation_run_identity": validation_identity,
                "validation_result_sha256": validation_sha256,
            },
            "manifest": manifest,
            "validation": validation,
        }

    def run_pending_integrity(
        self,
        fixture,
        *,
        pending=None,
        manifest=None,
        manifest_content=None,
        validation=None,
        validation_content=None,
        computed_generation_identity=None,
        publication_authority=None,
        candidate_authority=None,
        validation_complete=True,
        capture_mode=None,
    ):
        pending = fixture["pending"] if pending is None else pending
        manifest = fixture["manifest"] if manifest is None else manifest
        validation = fixture["validation"] if validation is None else validation
        if manifest_content is None:
            manifest_content = binary_output._json_bytes(manifest)
        if validation_content is None:
            validation_content = binary_output._json_bytes(validation)
        if computed_generation_identity is None:
            computed_generation_identity = fixture["generation_identity"]
        snapshot = (1, 2, 1, 3, 4, 5)

        def read_stable(path, **options):
            if path == fixture["manifest_path"]:
                return "e" * 64, manifest_content, snapshot
            if path == fixture["validation_path"]:
                return fixture["validation_sha256"], validation_content, snapshot
            return options.get("expected_sha256") or "f" * 64, None, snapshot

        capture_token = binary_output._INTEGRITY_PROOF_CAPTURE_CONTEXT.set(
            capture_mode
        )
        result_token = binary_output._INTEGRITY_PROOF_RESULT_CONTEXT.set(None)
        try:
            with patch.object(
                binary_output, "_directory_snapshot", return_value=snapshot,
            ), patch.object(
                binary_output, "_read_stable_generation_file",
                side_effect=read_stable,
            ), patch.object(
                binary_output, "_result_generation_identity_from_manifest",
                return_value=computed_generation_identity,
            ), patch.object(
                binary_output, "_require_generation_publication_allowed",
                return_value=publication_authority,
            ), patch.object(
                binary_output, "_generation_publication_authority",
                return_value=candidate_authority,
            ), patch.object(
                binary_output, "is_complete_v3_validation_result",
                return_value=validation_complete,
            ), patch.object(
                binary_output, "_assert_generation_snapshot_unchanged",
            ):
                result = binary_output._verify_pending_generation_integrity(
                    fixture["root"], pending,
                )
                proof = binary_output._INTEGRITY_PROOF_RESULT_CONTEXT.get()
        finally:
            binary_output._INTEGRITY_PROOF_RESULT_CONTEXT.reset(result_token)
            binary_output._INTEGRITY_PROOF_CAPTURE_CONTEXT.reset(capture_token)
        return result, proof

    def test_low_level_file_durability_and_snapshot_boundaries(self):
        regular = self.stat_result()
        with patch.object(binary_output.os, "name", "nt"):
            self.assertEqual(binary_output._regular_file_snapshot(regular)[-1], 0)
        with patch.object(binary_output.os, "name", "posix"):
            self.assertEqual(binary_output._regular_file_snapshot(regular)[-1], 5)

        for observed in (
            self.stat_result(mode=stat.S_IFLNK | 0o777),
            self.stat_result(mode=stat.S_IFREG | 0o600),
        ):
            with self.subTest(mode=observed.st_mode), patch.object(
                binary_output.os, "lstat", return_value=observed,
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._directory_snapshot(Path("generation"))
        directory = self.stat_result(mode=stat.S_IFDIR | 0o700)
        with patch.object(binary_output.os, "lstat", return_value=directory):
            self.assertEqual(
                binary_output._directory_snapshot(Path("generation")),
                binary_output._regular_file_snapshot(directory),
            )

        with patch.object(binary_output.os, "name", "posix"), patch.object(
            binary_output.os, "O_NOFOLLOW", 0, create=True,
        ), patch.object(
            binary_output.os, "O_BINARY", 8, create=True,
        ), patch.object(
            binary_output.os, "open", return_value=91,
        ) as opened, patch.object(
            binary_output.os, "fstat", return_value=regular,
        ), patch.object(binary_output.os, "fsync") as fsync, patch.object(
            binary_output.os, "close",
        ):
            binary_output._fsync_regular_file(Path("generation.json"))
        self.assertTrue(opened.call_args.args[1] & 8)
        fsync.assert_called_once_with(91)

        with patch.object(
            binary_output.os, "open", return_value=92,
        ), patch.object(
            binary_output.os, "fstat",
            return_value=self.stat_result(mode=stat.S_IFDIR | 0o700),
        ), patch.object(binary_output.os, "close"):
            with self.assertRaises(binary_output.BinaryOutputError) as caught:
                binary_output._fsync_regular_file(Path("directory"))
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_GENERATION_DURABILITY_TARGET_INVALID",
        )

        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary) / "binary_generations" / ("a" * 64)
            generation.mkdir(parents=True)
            for invalid in (Path(temporary).resolve(), Path("../escape")):
                with self.subTest(invalid=str(invalid)), self.assertRaises(
                    binary_output.BinaryOutputError,
                ):
                    binary_output._make_generation_durable(generation, (invalid,))
            with patch.object(binary_output, "_fsync_regular_file") as file_sync, patch.object(
                binary_output, "_fsync_directory", return_value=True,
            ) as directory_sync:
                binary_output._make_generation_durable(
                    generation,
                    ("b.json", "a.json", "a.json"),
                    nested_directories=(generation / "nested",),
                )
            self.assertEqual(
                [call.args[0].name for call in file_sync.call_args_list],
                ["a.json", "b.json"],
            )
            self.assertEqual(directory_sync.call_count, 3)

    def test_physical_output_and_generation_path_boundary_matrix(self):
        with self.assertRaises(binary_output.BinaryOutputError):
            binary_output._canonical_physical_output_root(
                Path("/"), reason_code="OUTPUT_INVALID",
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            nested = base / "missing-parent" / "output"
            created = binary_output._canonical_physical_output_root(
                nested, reason_code="OUTPUT_INVALID", create=True,
            )
            self.assertEqual(created, nested)
            self.assertEqual(
                binary_output._canonical_physical_output_root(
                    nested, reason_code="OUTPUT_INVALID", create=False,
                ),
                nested,
            )
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    base / "absent", reason_code="OUTPUT_INVALID", create=False,
                )

            file_root = base / "file-root"
            file_root.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    file_root, reason_code="OUTPUT_INVALID",
                )

            external = base / "external"
            external.mkdir()
            link_root = base / "link-root"
            try:
                link_root.symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    link_root, reason_code="OUTPUT_INVALID",
                )

            physical_root = base / "physical"
            physical_root.mkdir()
            namespace = binary_output._physical_generation_namespace(
                physical_root, create=True, reason_code="NAMESPACE_INVALID",
            )
            self.assertEqual(namespace, physical_root / "binary_generations")

            identity = "b" * 64
            generation = namespace / identity
            generation.mkdir()
            self.assertEqual(
                binary_output._physical_generation_directory(
                    namespace, identity, reason_code="GENERATION_INVALID",
                ),
                generation,
            )
            for invalid_identity in ("", "g" * 64, "a" * 63):
                with self.subTest(identity=invalid_identity), self.assertRaises(
                    binary_output.BinaryOutputError,
                ):
                    binary_output._physical_generation_directory(
                        namespace, invalid_identity,
                        reason_code="GENERATION_INVALID",
                    )

            file_identity = "c" * 64
            (namespace / file_identity).write_text("file", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._physical_generation_directory(
                    namespace, file_identity, reason_code="GENERATION_INVALID",
                )

            link_identity = "d" * 64
            (namespace / link_identity).symlink_to(generation, target_is_directory=True)
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._physical_generation_directory(
                    namespace, link_identity, reason_code="GENERATION_INVALID",
                )

        with patch.object(Path, "resolve", side_effect=FileNotFoundError("root absent")):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    Path("/owned-output"), reason_code="OUTPUT_INVALID", create=True,
                )

        with patch.object(Path, "resolve", side_effect=FileNotFoundError("missing")):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    Path("/tmp/../missing/output"),
                    reason_code="OUTPUT_INVALID", create=True,
                )

        with patch.object(
            Path, "resolve", return_value=Path("/physical-parent"),
        ), patch.object(
            binary_output.os, "lstat",
            return_value=self.stat_result(mode=stat.S_IFREG | 0o600),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._canonical_physical_output_root(
                    Path("/logical-parent/output"),
                    reason_code="OUTPUT_INVALID", create=True,
                )

        requested = Path("/base/missing/output")
        missing_parent = requested.parent

        def resolve_missing_parent(path, strict=False):
            del strict
            if path == missing_parent:
                raise FileNotFoundError(str(path))
            return Path("/physical-base")

        real_lstat = os.lstat
        for invalid_child in (
            self.stat_result(mode=stat.S_IFLNK | 0o777),
            self.stat_result(mode=stat.S_IFREG | 0o600),
        ):
            lstat_values = iter((
                self.stat_result(mode=stat.S_IFDIR | 0o700),
                invalid_child,
            ))

            def routed_lstat(candidate):
                if str(candidate).startswith("/physical-base"):
                    return next(lstat_values, invalid_child)
                return real_lstat(candidate)

            with self.subTest(intermediate_mode=invalid_child.st_mode), patch.object(
                Path, "resolve", new=resolve_missing_parent,
            ), patch.object(
                binary_output.os, "mkdir",
            ), patch.object(
                binary_output.os, "lstat",
                side_effect=routed_lstat,
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._canonical_physical_output_root(
                        requested, reason_code="OUTPUT_INVALID", create=True,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            file_namespace = root / "binary_generations"
            file_namespace.write_text("file", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._physical_generation_namespace(
                    root, create=False, reason_code="NAMESPACE_INVALID",
                )

        directory_stat = self.stat_result(mode=stat.S_IFDIR | 0o700)
        with patch.object(
            binary_output.os, "lstat", return_value=directory_stat,
        ), patch.object(
            Path, "resolve", return_value=Path("/different-namespace"),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._physical_generation_namespace(
                    Path("/root"), create=False,
                    reason_code="NAMESPACE_INVALID",
                )

        with patch.object(
            binary_output.os, "lstat", return_value=directory_stat,
        ), patch.object(
            Path, "resolve", return_value=Path("/different-generation"),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._physical_generation_directory(
                    Path("/root/binary_generations"), "e" * 64,
                    reason_code="GENERATION_INVALID",
                )

    def test_stable_generation_file_open_read_and_race_matrix(self):
        path = Path("generation.json")
        regular = self.stat_result(size=1)
        real_lstat = os.lstat

        def lstat_sequence(*values):
            iterator = iter(values)
            last = values[-1]

            def routed(candidate):
                if os.fspath(candidate) == os.fspath(path):
                    return next(iterator, last)
                return real_lstat(candidate)

            return routed

        invalid_initial = (
            self.stat_result(mode=stat.S_IFLNK | 0o777, size=1),
            self.stat_result(mode=stat.S_IFDIR | 0o700, size=1),
            self.stat_result(links=2, size=1),
        )
        for observed in invalid_initial:
            with self.subTest(initial=observed.st_mode), patch.object(
                binary_output.os, "lstat", side_effect=lstat_sequence(observed),
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._read_stable_generation_file(path)

        with patch.object(
            binary_output.os, "O_NOFOLLOW", 0, create=True,
        ), patch.object(
            binary_output.os, "O_NONBLOCK", 0, create=True,
        ), patch.object(
            binary_output.os, "O_BINARY", 8, create=True,
        ), patch.object(
            binary_output.os, "lstat",
            side_effect=lstat_sequence(regular, regular, regular),
        ), patch.object(
            binary_output.os, "open", return_value=91,
        ) as opened, patch.object(
            binary_output.os, "fstat", side_effect=(regular, regular),
        ), patch.object(
            binary_output.os, "read", side_effect=(b"x", b""),
        ), patch.object(binary_output.os, "close"):
            digest, content, snapshot = binary_output._read_stable_generation_file(
                path, capture_content=True,
            )
        self.assertEqual(content, b"x")
        self.assertEqual(snapshot, binary_output._regular_file_snapshot(regular))
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(opened.call_args.args[1] & 8)

        opening_variants = (
            (self.stat_result(mode=stat.S_IFDIR | 0o700, size=1), regular),
            (self.stat_result(links=2, size=1), regular),
            (regular, self.stat_result(links=2, size=1)),
            (self.stat_result(size=2), regular),
            (regular, self.stat_result(size=2)),
        )
        for opened_stat, current_stat in opening_variants:
            with self.subTest(opened=opened_stat, current=current_stat), patch.object(
                binary_output.os, "lstat",
                side_effect=lstat_sequence(regular, current_stat),
            ), patch.object(
                binary_output.os, "open", return_value=92,
            ), patch.object(
                binary_output.os, "fstat", return_value=opened_stat,
            ), patch.object(binary_output.os, "close"):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._read_stable_generation_file(path)

        with patch.object(
            binary_output, "_GENERATION_METADATA_MAX_BYTES", 0,
        ), patch.object(
            binary_output.os, "lstat", side_effect=lstat_sequence(regular, regular),
        ), patch.object(
            binary_output.os, "open", return_value=93,
        ), patch.object(
            binary_output.os, "fstat", return_value=regular,
        ), patch.object(
            binary_output.os, "read", return_value=b"x",
        ), patch.object(binary_output.os, "close"):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._read_stable_generation_file(
                    path, capture_content=True,
                )

        final_variants = (
            (self.stat_result(links=2, size=1), regular),
            (regular, self.stat_result(links=2, size=1)),
            (self.stat_result(size=2), regular),
            (regular, self.stat_result(size=2)),
        )
        for final_opened, final_path in final_variants:
            with self.subTest(final_opened=final_opened, final_path=final_path), patch.object(
                binary_output.os, "lstat",
                side_effect=lstat_sequence(regular, regular, final_path),
            ), patch.object(
                binary_output.os, "open", return_value=94,
            ), patch.object(
                binary_output.os, "fstat",
                side_effect=(regular, final_opened),
            ), patch.object(
                binary_output.os, "read", return_value=b"",
            ), patch.object(binary_output.os, "close"):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._read_stable_generation_file(path)

    def test_direct_seal_capability_registry_and_consumption_matrix(self):
        binary_output._reset_direct_seal_fast_path_after_fork()
        try:
            root = Path("/physical-output")
            first = self.direct_seal_capability(root, digit="1")
            replacement = self.direct_seal_capability(root, digit="1")
            binary_output._install_direct_seal_capability(first)
            binary_output._install_direct_seal_capability(replacement)
            self.assertEqual(len(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY), 1)

            previous_token = object()
            binary_output._reset_direct_seal_fast_path_after_fork()
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY[previous_token] = first
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[
                first.operation_key
            ] = previous_token
            binary_output._install_direct_seal_capability(replacement)
            self.assertNotIn(
                previous_token, binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY,
            )

            binary_output._reset_direct_seal_fast_path_after_fork()
            retained_token = object()
            retained = self.direct_seal_capability(root, digit="3")
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY[retained_token] = retained
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[
                retained.operation_key
            ] = retained_token
            with patch.object(binary_output, "_DIRECT_SEAL_FAST_PATH_MAX_ENTRIES", 1):
                newest = self.direct_seal_capability(root, digit="4")
                binary_output._install_direct_seal_capability(newest)
            self.assertEqual(len(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY), 1)

            binary_output._remove_direct_seal_capability_locked(object())
            mismatched_token = object()
            mismatched_operation_token = object()
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY[mismatched_token] = newest
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[
                newest.operation_key
            ] = mismatched_operation_token
            binary_output._remove_direct_seal_capability_locked(mismatched_token)
            self.assertIs(
                binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[newest.operation_key],
                mismatched_operation_token,
            )

            target_token = object()
            other_token = object()
            target = self.direct_seal_capability(root, digit="5")
            other = self.direct_seal_capability(Path("/other-output"), digit="6")
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY.clear()
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION.clear()
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY.update({
                target_token: target,
                other_token: other,
            })
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION.update({
                target.operation_key: target_token,
                other.operation_key: other_token,
            })
            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(target_token)
            binary_output._invalidate_direct_seal_capabilities_for_root(root)
            self.assertNotIn(target_token, binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY)
            self.assertIn(other_token, binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY)

            valid = self.direct_seal_capability(root, digit="7")
            token = object()
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY[token] = valid
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[
                valid.operation_key
            ] = token
            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(token)
            current = {
                "validation_run_identity": valid.validation_run_identity,
                "validation_result_sha256": valid.validation_result_sha256,
            }
            with patch.object(
                binary_output, "_directory_snapshot",
                return_value=(1, 2, 1, 0, 0, 0),
            ):
                selected = binary_output._consume_direct_seal_capability(
                    root,
                    expected_current_identity=valid.result_generation_identity,
                    expected_activation_identity=valid.activation_identity,
                    current=current,
                )
            self.assertEqual(selected, valid)

            for invalid_current in (
                None,
                {},
                {"validation_run_identity": "short", "validation_result_sha256": "8" * 64},
                {"validation_run_identity": "8" * 64, "validation_result_sha256": "short"},
            ):
                with self.subTest(current=invalid_current), patch.object(
                    binary_output, "_directory_snapshot",
                    return_value=(1, 2, 1, 0, 0, 0),
                ):
                    self.assertIsNone(binary_output._consume_direct_seal_capability(
                        root,
                        expected_current_identity="9" * 64,
                        expected_activation_identity="8" * 64,
                        current=invalid_current,
                    ))

            with patch.object(
                binary_output, "_directory_snapshot",
                side_effect=binary_output.BinaryOutputError("ROOT_INVALID", "broken"),
            ):
                self.assertIsNone(binary_output._consume_direct_seal_capability(
                    root,
                    expected_current_identity="9" * 64,
                    expected_activation_identity="8" * 64,
                    current=None,
                ))

            valid = self.direct_seal_capability(root, digit="2")
            operation_token = object()
            context_token = object()
            binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY[operation_token] = valid
            binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION[
                valid.operation_key
            ] = operation_token
            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(context_token)
            with patch.object(
                binary_output, "_directory_snapshot",
                return_value=(1, 2, 1, 0, 0, 0),
            ):
                self.assertIsNone(binary_output._consume_direct_seal_capability(
                    root,
                    expected_current_identity=valid.result_generation_identity,
                    expected_activation_identity=valid.activation_identity,
                    current={
                        "validation_run_identity": valid.validation_run_identity,
                        "validation_result_sha256": valid.validation_result_sha256,
                    },
                ))
        finally:
            binary_output._reset_direct_seal_fast_path_after_fork()

    def test_direct_seal_filesystem_support_cache_matrix(self):
        binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.clear()
        root = Path("/physical-output")
        with patch.object(binary_output.os, "name", "nt"):
            self.assertFalse(
                binary_output._filesystem_supports_direct_seal_fast_path(root, 1)
            )
        with patch.object(binary_output.os, "name", "posix"), patch.object(
            binary_output, "_directory_snapshot", return_value=(2, 3, 1, 0, 0, 0),
        ):
            self.assertFalse(
                binary_output._filesystem_supports_direct_seal_fast_path(root, 1)
            )
        with patch.object(binary_output.os, "name", "posix"), patch.object(
            binary_output, "_directory_snapshot",
            side_effect=binary_output.BinaryOutputError("ROOT_INVALID", "broken"),
        ):
            self.assertFalse(
                binary_output._filesystem_supports_direct_seal_fast_path(root, 1)
            )

        for cached in (False, True):
            binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.clear()
            binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE[1] = cached
            with self.subTest(cached=cached), patch.object(
                binary_output.os, "name", "posix",
            ), patch.object(
                binary_output, "_directory_snapshot", return_value=(1, 2, 1, 0, 0, 0),
            ), patch.object(binary_output, "_probe_ctime_change_detection") as probe:
                self.assertIs(
                    binary_output._filesystem_supports_direct_seal_fast_path(root, 1),
                    cached,
                )
            probe.assert_not_called()

        binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE.clear()
        binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE[1] = False
        with patch.object(binary_output.os, "name", "posix"), patch.object(
            binary_output, "_directory_snapshot", return_value=(2, 3, 1, 0, 0, 0),
        ), patch.object(
            binary_output, "_probe_ctime_change_detection", return_value=True,
        ), patch.object(binary_output, "_DIRECT_SEAL_CTIME_SUPPORT_MAX_DEVICES", 1):
            self.assertTrue(
                binary_output._filesystem_supports_direct_seal_fast_path(root, 2)
            )
        self.assertNotIn(1, binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE)
        self.assertTrue(binary_output._DIRECT_SEAL_CTIME_SUPPORT_BY_DEVICE[2])

    def test_ctime_probe_preconditions_change_detection_and_cleanup_matrix(self):
        root = Path("/physical-output")
        probe_path = Path("/binary-seal-ctime-probe")
        real_lstat = os.lstat
        baseline = self.stat_result(size=64, ctime=10, mtime=20, atime=30)

        def run_probe(
            *,
            writes=(64, 64),
            baseline_stat=baseline,
            final_descriptor=None,
            final_path=None,
            mkstemp_error=None,
            close_error=None,
            unlink_error=None,
        ):
            final_descriptor = final_descriptor or self.stat_result(
                size=64, ctime=11, mtime=20, atime=30,
            )
            final_path = final_path or final_descriptor
            write_values = iter(writes)

            def routed_lstat(candidate):
                if Path(candidate) == probe_path:
                    return final_path
                return real_lstat(candidate)

            mkstemp = patch.object(
                binary_output.tempfile,
                "mkstemp",
                side_effect=mkstemp_error,
                return_value=(91, str(probe_path)),
            )
            close = patch.object(
                binary_output.os, "close", side_effect=close_error,
            )
            unlink = patch.object(Path, "unlink", side_effect=unlink_error)
            with mkstemp, patch.object(
                binary_output.os, "fchmod",
            ), patch.object(
                binary_output.os, "write", side_effect=lambda *_args: next(write_values),
            ), patch.object(
                binary_output.os, "fsync",
            ), patch.object(
                binary_output.os, "fstat",
                side_effect=(baseline_stat, final_descriptor),
            ), patch.object(
                binary_output.os, "lseek",
            ), patch.object(
                binary_output.os, "utime",
            ), patch.object(
                binary_output.os, "lstat", side_effect=routed_lstat,
            ), close, unlink:
                return binary_output._probe_ctime_change_detection(root, 1)

        self.assertTrue(run_probe())
        self.assertFalse(run_probe(writes=(63,)))

        baseline_variants = (
            self.stat_result(mode=stat.S_IFDIR | 0o700, size=64),
            self.stat_result(device=2, size=64),
            self.stat_result(links=2, size=64),
            self.stat_result(size=63),
        )
        for invalid in baseline_variants:
            with self.subTest(baseline=invalid):
                self.assertFalse(run_probe(writes=(64,), baseline_stat=invalid))
        self.assertFalse(run_probe(writes=(64, 63)))

        final_pairs = (
            (
                self.stat_result(size=64, ctime=11, mtime=20),
                self.stat_result(size=64, ctime=12, mtime=20),
            ),
            (
                self.stat_result(device=2, size=64, ctime=11, mtime=20),
                self.stat_result(device=2, size=64, ctime=11, mtime=20),
            ),
            (
                self.stat_result(links=2, size=64, ctime=11, mtime=20),
                self.stat_result(links=2, size=64, ctime=11, mtime=20),
            ),
            (
                self.stat_result(size=63, ctime=11, mtime=20),
                self.stat_result(size=63, ctime=11, mtime=20),
            ),
            (
                self.stat_result(size=64, ctime=11, mtime=21),
                self.stat_result(size=64, ctime=11, mtime=21),
            ),
            (
                self.stat_result(size=64, ctime=10, mtime=20),
                self.stat_result(size=64, ctime=10, mtime=20),
            ),
        )
        for final_descriptor, final_path in final_pairs:
            with self.subTest(final=final_descriptor):
                self.assertFalse(run_probe(
                    final_descriptor=final_descriptor,
                    final_path=final_path,
                ))

        self.assertFalse(run_probe(mkstemp_error=OSError("no probe file")))
        self.assertFalse(run_probe(close_error=OSError("close failed")))
        self.assertFalse(run_probe(unlink_error=OSError("unlink failed")))

    def test_generation_snapshot_change_matrix(self):
        path = Path("generation.json")
        expected = binary_output._regular_file_snapshot(self.stat_result())
        invalid = (
            self.stat_result(mode=stat.S_IFLNK | 0o777),
            self.stat_result(mode=stat.S_IFDIR | 0o700),
            self.stat_result(links=2),
            self.stat_result(size=999),
        )
        for observed in invalid:
            with self.subTest(mode=observed.st_mode, links=observed.st_nlink), patch.object(
                binary_output.os, "lstat", return_value=observed,
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._assert_generation_snapshot_unchanged(
                        {path: expected}, {},
                    )

        directory = Path("generation")
        with patch.object(
            binary_output, "_directory_snapshot", return_value=tuple(value + 1 for value in expected),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._assert_generation_snapshot_unchanged(
                    {}, {directory: expected},
                )

    def test_exact_mapping_and_publication_receipt_validation_matrix(self):
        self.assertFalse(binary_output._exact_mapping_equal({}, []))
        self.assertFalse(binary_output._exact_mapping_equal({}, {"a": 1}))
        self.assertFalse(binary_output._exact_mapping_equal({"a": True}, {"a": 1}))
        self.assertFalse(binary_output._exact_mapping_equal({"a": 1}, {"a": 2}))
        self.assertTrue(binary_output._exact_mapping_equal({"a": 1}, {"a": 1}))

        generation = self.authority_binding(digit="1")
        current = self.authority_binding(digit="4")
        identities = {
            "result_generation_identity": "5" * 64,
            "validation_run_identity": "6" * 64,
            "validation_result_sha256": "7" * 64,
            "activation_identity": "8" * 64,
        }
        receipt = binary_output.binary_publication_reauthorization_receipt(
            generation_performance_authority_binding=generation,
            current_performance_authority_binding=current,
            **identities,
        )
        self.assertRegex(receipt["reauthorization_identity"], r"^[0-9a-f]{64}$")

        invalid_cases = []
        invalid_cases.append(({}, current, identities))
        invalid_cases.append((generation, {}, identities))
        invalid_cases.append((generation, generation, identities))
        candidate_generation = self.authority_binding(
            mode="candidate_source_measurement", digit="2",
        )
        candidate_current = self.authority_binding(
            mode="candidate_source_measurement", digit="3",
        )
        invalid_cases.append((candidate_generation, current, identities))
        invalid_cases.append((generation, candidate_current, identities))
        for field, value in (
            ("result_generation_identity", None),
            ("validation_run_identity", "short"),
        ):
            changed = dict(identities)
            changed[field] = value
            invalid_cases.append((generation, current, changed))
        for generation_binding, current_binding, values in invalid_cases:
            with self.subTest(values=values), self.assertRaises(
                binary_output.BinaryOutputError,
            ):
                binary_output.binary_publication_reauthorization_receipt(
                    generation_performance_authority_binding=generation_binding,
                    current_performance_authority_binding=current_binding,
                    **values,
                )

    def test_publication_reauthorization_verifier_mutation_matrix(self):
        generation = self.authority_binding(digit="1")
        current = self.authority_binding(digit="4")
        identities = {
            "result_generation_identity": "5" * 64,
            "validation_run_identity": "6" * 64,
            "validation_result_sha256": "7" * 64,
            "activation_identity": "8" * 64,
        }
        receipt = binary_output.binary_publication_reauthorization_receipt(
            generation_performance_authority_binding=generation,
            current_performance_authority_binding=current,
            **identities,
        )

        def validate(value, *, expected=generation, expected_values=identities):
            with patch.object(
                binary_output, "_live_reauthorization_binding_is_current",
                return_value=True,
            ):
                return binary_output._publication_reauthorization_is_valid(
                    value,
                    expected_generation_binding=expected,
                    **expected_values,
                )

        self.assertTrue(validate(receipt))
        self.assertFalse(validate(None))
        self.assertFalse(validate({**receipt, "extra": True}))

        mutations = []
        for field, value in (
            ("generation_performance_authority_binding", None),
            ("current_performance_authority_binding", None),
            ("generation_performance_authority_binding", {}),
            ("current_performance_authority_binding", {}),
        ):
            changed = dict(receipt)
            changed[field] = value
            mutations.append(changed)

        changed = dict(receipt)
        changed["generation_performance_authority_binding"] = self.authority_binding(
            digit="2",
        )
        mutations.append(changed)
        changed = dict(receipt)
        changed["current_performance_authority_binding"] = dict(generation)
        mutations.append(changed)

        for field in (
            "generation_performance_authority_binding",
            "current_performance_authority_binding",
        ):
            changed = dict(receipt)
            binding = self.authority_binding(
                mode="candidate_source_measurement", digit="2",
            )
            changed[field] = binding
            mutations.append(changed)

        for changed in mutations:
            with self.subTest(fields=set(changed)):
                self.assertFalse(validate(changed))

        with patch.object(
            binary_output, "_live_reauthorization_binding_is_current",
            return_value=False,
        ):
            self.assertFalse(binary_output._publication_reauthorization_is_valid(
                receipt,
                expected_generation_binding=generation,
                **identities,
            ))

        for field, value in (
            ("result_generation_identity", None),
            ("validation_run_identity", "9" * 64),
            ("validation_result_sha256", "short"),
        ):
            changed = dict(receipt)
            changed[field] = value
            self.assertFalse(validate(changed))

        candidate_generation = self.authority_binding(
            mode="candidate_source_measurement", digit="2",
        )
        candidate_receipt = dict(receipt)
        candidate_receipt[
            "generation_performance_authority_binding"
        ] = candidate_generation
        self.assertFalse(validate(
            candidate_receipt, expected=candidate_generation,
        ))

        for field, value in (
            ("schema", None),
            ("schema", "wrong-schema"),
            ("reauthorization_identity", None),
            ("reauthorization_identity", "0" * 64),
        ):
            changed = dict(receipt)
            changed[field] = value
            self.assertFalse(validate(changed))

    def test_generation_publication_authority_payload_matrix(self):
        generation = Path("/generation")
        binding = self.authority_binding(digit="1")
        authority = {
            "schema": binary_output._PUBLICATION_AUTHORITY_SCHEMA,
            "authority_mode": binding["authority_mode"],
            "binding_identity": binding["binding_identity"],
            "public_activation_allowed": True,
            "performance_authority_gate_binding": binding,
        }
        content = binary_output._json_bytes(authority)
        manifest = {
            "sidecar_content_identities": {
                binary_output._PUBLICATION_AUTHORITY_SIDECAR: "a" * 64,
            },
        }

        with patch.object(
            binary_output, "_read_stable_generation_file",
            return_value=("a" * 64, content, (1, 2, 1, len(content), 3, 4)),
        ):
            self.assertEqual(
                binary_output._generation_publication_authority(generation, manifest),
                authority,
            )
        self.assertIsNone(binary_output._generation_publication_authority(
            generation, {"sidecar_content_identities": {}},
        ))
        for invalid_manifest in (
            {},
            {"sidecar_content_identities": []},
            {"sidecar_content_identities": {
                binary_output._PUBLICATION_AUTHORITY_SIDECAR: "short",
            }},
        ):
            with self.subTest(manifest=invalid_manifest), self.assertRaises(
                binary_output.BinaryOutputError,
            ):
                binary_output._generation_publication_authority(
                    generation, invalid_manifest,
                )

        invalid_payloads = [b""]
        invalid_payloads.append(binary_output._json_bytes([]))
        for field, value in (
            ("schema", "wrong"),
            ("performance_authority_gate_binding", {}),
            ("authority_mode", "candidate_source_measurement"),
            ("binding_identity", "0" * 64),
            ("public_activation_allowed", 1),
            ("public_activation_allowed", False),
        ):
            changed = dict(authority)
            changed[field] = value
            invalid_payloads.append(binary_output._json_bytes(changed))
        invalid_payloads.append(content + b" ")
        for invalid_content in invalid_payloads:
            with self.subTest(content=invalid_content[:30]), patch.object(
                binary_output, "_read_stable_generation_file",
                return_value=("a" * 64, invalid_content, (1, 2, 1, 0, 0, 0)),
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._generation_publication_authority(
                        generation, manifest,
                    )

        with patch.object(
            binary_output, "_read_stable_generation_file",
            side_effect=binary_output.BinaryOutputError("READ_FAILED", "broken"),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._generation_publication_authority(generation, manifest)

    def test_active_and_pending_descriptor_shape_matrix(self):
        core = self.active_descriptor_core()
        self.assertEqual(binary_output._active_descriptor_core(core), core)
        self.assertIsNone(binary_output._active_descriptor_core(None))
        for field, value in (
            ("schema", "wrong"),
            ("result_generation_identity", "short"),
            ("generation_directory", "binary_generations/wrong"),
            ("validation_run_identity", "short"),
            ("validation_result_sha256", "short"),
        ):
            changed = dict(core)
            changed[field] = value
            with self.subTest(core_field=field):
                self.assertIsNone(binary_output._active_descriptor_core(changed))

        pending = {
            **core,
            "activation_identity": "4" * 64,
            "activation_predecessor": None,
            "activation_state": "pending",
        }
        self.assertEqual(
            binary_output._pending_active_descriptor(pending), pending,
        )
        predecessor = self.active_descriptor_core(digit="5")
        published = {
            **pending,
            "activation_predecessor": predecessor,
            "activation_state": "published",
        }
        self.assertEqual(
            binary_output._pending_active_descriptor(published)[
                "activation_predecessor"
            ],
            predecessor,
        )
        self.assertIsNone(binary_output._pending_active_descriptor(None))
        pending_mutations = []
        changed = dict(pending)
        changed["extra"] = True
        pending_mutations.append(changed)
        for field, value in (
            ("activation_identity", "short"),
            ("activation_state", "sealed"),
            ("activation_predecessor", {"schema": "invalid"}),
        ):
            changed = dict(pending)
            changed[field] = value
            pending_mutations.append(changed)
        for changed in pending_mutations:
            self.assertIsNone(binary_output._pending_active_descriptor(changed))

    def test_active_descriptor_path_and_destination_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "output"
            root.mkdir()
            active = root / "active_binary_generation.json"
            self.assertTrue(binary_output._active_descriptor_path_matches(
                active, None, expect_missing=True,
            ))
            self.assertFalse(binary_output._active_descriptor_path_matches(
                active, None, expect_missing=False,
            ))
            active.write_text("{}", encoding="utf-8")
            observed = os.lstat(active)
            identity = binary_output._descriptor_file_identity(observed)
            self.assertFalse(binary_output._active_descriptor_path_matches(
                active, identity, expect_missing=True,
            ))
            self.assertFalse(binary_output._active_descriptor_path_matches(
                active, None,
            ))
            self.assertTrue(binary_output._active_descriptor_path_matches(
                active, identity,
            ))
            self.assertFalse(binary_output._active_descriptor_path_matches(
                active, (identity[0], identity[1] + 1),
            ))
            directory = root / "descriptor-directory"
            directory.mkdir()
            self.assertFalse(binary_output._active_descriptor_path_matches(
                directory, binary_output._descriptor_file_identity(os.lstat(directory)),
            ))

            self.assertEqual(
                binary_output._active_descriptor_destination(
                    root, "active_binary_generation.json",
                ),
                active,
            )
            pending_destination = binary_output._active_descriptor_destination(
                root, binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
            )
            self.assertEqual(
                pending_destination.parent.name, "binary_observability",
            )
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._active_descriptor_destination(root, "unsupported.json")

        with self.assertRaises(binary_output.BinaryOutputError):
            binary_output._active_descriptor_destination(
                Path("/"), "active_binary_generation.json",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "output"
            root.write_text("file", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._active_descriptor_destination(
                    root, "active_binary_generation.json",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "output"
            root.mkdir()
            invalid_parent = root / "binary_observability"
            invalid_parent.write_text("file", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._active_descriptor_destination(
                    root, binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            external = base / "external"
            external.mkdir()
            root = base / "output"
            root.symlink_to(external, target_is_directory=True)
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._active_descriptor_destination(
                    root, "active_binary_generation.json",
                )

        requested = Path("/logical/output")
        real_lstat = os.lstat

        def mismatched_root_resolve(path, strict=False):
            del strict
            if path == requested.parent:
                return requested.parent
            if path == requested:
                return Path("/different-output")
            return path

        def root_directory_lstat(candidate):
            if Path(candidate) == requested:
                return self.stat_result(mode=stat.S_IFDIR | 0o700)
            return real_lstat(candidate)

        with patch.object(
            Path, "resolve", new=mismatched_root_resolve,
        ), patch.object(
            binary_output.os, "lstat", side_effect=root_directory_lstat,
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._active_descriptor_destination(
                    requested, "active_binary_generation.json",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "output"
            root.mkdir()
            parent = root / "binary_observability"
            parent.mkdir()
            real_resolve = Path.resolve

            def mismatched_parent_resolve(path, strict=False):
                if path == parent:
                    return parent.parent / "different-observability"
                return real_resolve(path, strict=strict)

            with patch.object(Path, "resolve", new=mismatched_parent_resolve):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._active_descriptor_destination(
                        root,
                        binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
                    )

    def test_active_descriptor_stable_read_race_and_type_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._read_active_descriptor(root, missing_ok=False)
            self.assertEqual(
                binary_output._read_active_descriptor(root, missing_ok=True),
                (None, None),
            )

        path = Path("/output/active_binary_generation.json")
        real_lstat = os.lstat

        def lstat_sequence(*values):
            iterator = iter(values)
            last = values[-1]

            def routed(candidate):
                if Path(candidate) == path:
                    return next(iterator, last)
                return real_lstat(candidate)

            return routed

        regular = self.stat_result(size=2)
        with patch.object(
            binary_output.os, "O_NOFOLLOW", 0, create=True,
        ), patch.object(
            binary_output.os, "O_NONBLOCK", 0, create=True,
        ), patch.object(
            binary_output.os, "O_BINARY", 8, create=True,
        ), patch.object(
            binary_output.os, "lstat",
            side_effect=lstat_sequence(regular, regular, regular),
        ), patch.object(
            binary_output.os, "open", return_value=91,
        ) as opened, patch.object(
            binary_output.os, "fstat", side_effect=(regular, regular),
        ), patch.object(
            binary_output.os, "fdopen", return_value=self._descriptor_handle(b"{}"),
        ):
            value, identity = binary_output._read_active_descriptor(Path("/output"))
        self.assertEqual(value, {})
        self.assertEqual(identity, (1, 2))
        self.assertTrue(opened.call_args.args[1] & 8)

        opening_variants = (
            (self.stat_result(mode=stat.S_IFDIR | 0o700, size=2), regular),
            (self.stat_result(links=2, size=2), regular),
            (regular, self.stat_result(links=2, size=2)),
            (self.stat_result(inode=3, size=2), regular),
            (regular, self.stat_result(inode=3, size=2)),
        )
        for opened_stat, current_stat in opening_variants:
            with self.subTest(opened=opened_stat, current=current_stat), patch.object(
                binary_output.os, "lstat",
                side_effect=lstat_sequence(regular, current_stat),
            ), patch.object(
                binary_output.os, "open", return_value=92,
            ), patch.object(
                binary_output.os, "fstat", return_value=opened_stat,
            ), patch.object(binary_output.os, "close"):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._read_active_descriptor(Path("/output"))

        final_variants = (
            (self.stat_result(inode=3, size=2), regular),
            (regular, self.stat_result(inode=3, size=2)),
            (self.stat_result(links=2, size=2), regular),
            (regular, self.stat_result(links=2, size=2)),
            (self.stat_result(size=3), regular),
            (self.stat_result(size=2, mtime=9), regular),
            (self.stat_result(size=2, ctime=9), regular),
        )
        for final_opened, final_path in final_variants:
            with self.subTest(final_opened=final_opened, final_path=final_path), patch.object(
                binary_output.os, "name", "posix",
            ), patch.object(
                binary_output.os, "lstat",
                side_effect=lstat_sequence(regular, regular, final_path),
            ), patch.object(
                binary_output.os, "open", return_value=93,
            ), patch.object(
                binary_output.os, "fstat",
                side_effect=(regular, final_opened),
            ), patch.object(
                binary_output.os, "fdopen", return_value=self._descriptor_handle(b"{}"),
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output._read_active_descriptor(Path("/output"))

        changed_ctime = self.stat_result(size=2, ctime=9)
        windows_os = Mock(wraps=os)
        windows_os.name = "nt"
        windows_os.O_RDONLY = os.O_RDONLY
        windows_os.O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
        windows_os.O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
        windows_os.O_BINARY = getattr(os, "O_BINARY", 0)
        windows_os.lstat.side_effect = lstat_sequence(regular, regular, regular)
        windows_os.open.return_value = 94
        windows_os.fstat.side_effect = (regular, changed_ctime)
        windows_os.fdopen.return_value = self._descriptor_handle(b"{}")
        with patch.object(binary_output, "os", windows_os):
            value, _identity = binary_output._read_active_descriptor(Path("/output"))
        self.assertEqual(value, {})

        with patch.object(
            binary_output.os, "lstat",
            side_effect=lstat_sequence(regular, regular, regular),
        ), patch.object(
            binary_output.os, "open", return_value=95,
        ), patch.object(
            binary_output.os, "fstat", side_effect=(regular, regular),
        ), patch.object(
            binary_output.os, "fdopen", return_value=self._descriptor_handle(b"[]"),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output._read_active_descriptor(Path("/output"))

    @staticmethod
    def _descriptor_handle(content: bytes):
        handle = io.BytesIO(content)
        handle.fileno = Mock(return_value=91)
        return handle

    def test_public_active_and_private_pending_reader_state_matrix(self):
        root = Path("/output")
        core = self.active_descriptor_core()
        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor", return_value=(None, None),
        ):
            self.assertIsNone(binary_output.read_active_binary_generation(root))

        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor", return_value=({"invalid": True}, None),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.read_active_binary_generation(root)

        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor", return_value=(core, (1, 2)),
        ), patch.object(
            binary_output, "_require_generation_identity_publication_allowed",
            return_value=None,
        ):
            self.assertEqual(binary_output.read_active_binary_generation(root), core)

        pending = {
            **core,
            "activation_identity": "4" * 64,
            "activation_predecessor": None,
        }
        predecessor = self.active_descriptor_core(digit="5")
        valid_pending_variants = (
            pending,
            {**pending, "activation_predecessor": predecessor},
        )
        for value in valid_pending_variants:
            with self.subTest(predecessor=value["activation_predecessor"]), patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_read_active_descriptor", return_value=(value, (1, 2)),
            ), patch.object(
                binary_output, "_require_generation_identity_publication_allowed",
                return_value=None,
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.read_active_binary_generation(root)
                self.assertEqual(
                    binary_output.read_active_binary_generation(
                        root, allow_pending_activation=True,
                    ),
                    value,
                )

        invalid_pending = (
            {**core, "extra": True},
            {**pending, "activation_identity": "short"},
            {**pending, "activation_predecessor": {"invalid": True}},
        )
        for value in invalid_pending:
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_read_active_descriptor", return_value=(value, (1, 2)),
            ), patch.object(
                binary_output, "_require_generation_identity_publication_allowed",
                return_value=None,
            ):
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.read_active_binary_generation(
                        root, allow_pending_activation=True,
                    )

        private_pending = {
            **core,
            "activation_identity": "4" * 64,
            "activation_predecessor": None,
            "activation_state": "pending",
        }
        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor", return_value=(None, None),
        ):
            self.assertIsNone(binary_output.read_pending_binary_generation(root))
        for expected in ("", "4" * 64):
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_read_active_descriptor",
                return_value=(private_pending, (1, 2)),
            ):
                self.assertEqual(
                    binary_output.read_pending_binary_generation(
                        root, expected_activation_identity=expected,
                    ),
                    private_pending,
                )
        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor",
            return_value=(private_pending, (1, 2)),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.read_pending_binary_generation(
                    root, expected_activation_identity="9" * 64,
                )
        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_read_active_descriptor",
            return_value=({"invalid": True}, (1, 2)),
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.read_pending_binary_generation(root)

    def test_pending_integrity_identity_path_and_manifest_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.pending_integrity_fixture(temporary)
            for field in (
                "result_generation_identity",
                "validation_run_identity",
                "validation_result_sha256",
            ):
                changed = dict(fixture["pending"])
                changed[field] = None
                with self.subTest(invalid_pending_field=field), self.assertRaises(
                    binary_output.BinaryOutputError,
                ) as caught:
                    self.run_pending_integrity(fixture, pending=changed)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

            real_resolve = Path.resolve
            path_targets = (
                fixture["root"] / "binary_generations",
                fixture["generation"],
                fixture["validation_directory"],
            )
            for target in path_targets:
                def routed_resolve(path, strict=False, *, selected=target):
                    if path == selected:
                        return selected.parent / f"escaped-{selected.name}"
                    return real_resolve(path, strict=strict)

                with self.subTest(escaped_path=target), patch.object(
                    Path, "resolve", new=routed_resolve,
                ), self.assertRaises(binary_output.BinaryOutputError) as caught:
                    self.run_pending_integrity(fixture)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

            for error in (OSError("unreadable root"), RuntimeError("resolve loop")):
                def failing_root_resolve(path, strict=False, *, failure=error):
                    if path == fixture["root"]:
                        raise failure
                    return real_resolve(path, strict=strict)

                with self.subTest(resolve_error=type(error).__name__), patch.object(
                    Path, "resolve", new=failing_root_resolve,
                ), self.assertRaises(binary_output.BinaryOutputError):
                    self.run_pending_integrity(fixture)

            manifest = fixture["manifest"]
            invalid_manifests = (
                (manifest, b""),
                (manifest, b"\xff"),
                ([], binary_output._json_bytes([])),
                (manifest, binary_output._json_bytes(manifest) + b" "),
                (
                    {**manifest, "result_generation_identity": "f" * 64},
                    None,
                ),
                ({**manifest, "sidecar_content_identities": []}, None),
                (
                    {
                        **manifest,
                        "sidecar_content_identities": {
                            name: identity
                            for name, identity in manifest[
                                "sidecar_content_identities"
                            ].items()
                            if name != "binary_summary.json"
                        },
                    },
                    None,
                ),
            )
            for changed_manifest, changed_content in invalid_manifests:
                options = {"manifest": changed_manifest}
                if changed_content is not None or changed_content == b"":
                    options["manifest_content"] = changed_content
                with self.subTest(manifest=changed_manifest), self.assertRaises(
                    binary_output.BinaryOutputError,
                ) as caught:
                    self.run_pending_integrity(fixture, **options)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

            with self.assertRaises(binary_output.BinaryOutputError):
                self.run_pending_integrity(
                    fixture, computed_generation_identity="f" * 64,
                )

            authority = {"authority_mode": "release_evidence"}
            result, proof = self.run_pending_integrity(
                fixture, publication_authority=authority,
            )
            self.assertEqual(result, authority)
            self.assertIsNone(proof)

    def test_pending_integrity_candidate_sidecar_and_forbidden_file_matrix(self):
        candidate = {
            "authority_mode": "candidate_source_measurement",
            "public_activation_allowed": False,
        }
        invalid_authorities = (
            None,
            {
                "authority_mode": "release_evidence",
                "public_activation_allowed": False,
            },
            {
                "authority_mode": "candidate_source_measurement",
                "public_activation_allowed": True,
            },
        )
        for authority in invalid_authorities:
            with self.subTest(authority=authority), tempfile.TemporaryDirectory() as temporary:
                fixture = self.pending_integrity_fixture(temporary)
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    self.run_pending_integrity(
                        fixture,
                        candidate_authority=authority,
                        capture_mode=(
                            binary_output._CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY
                        ),
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_PUBLICATION_DRY_RUN_FORBIDDEN",
                )

        for name, expected in (("../escape", "e" * 64), ("extra.json", "short")):
            with self.subTest(sidecar=name), tempfile.TemporaryDirectory() as temporary:
                fixture = self.pending_integrity_fixture(temporary)
                manifest = {
                    **fixture["manifest"],
                    "sidecar_content_identities": {
                        **fixture["manifest"]["sidecar_content_identities"],
                        name: expected,
                    },
                }
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    self.run_pending_integrity(fixture, manifest=manifest)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

        forbidden_names = (
            next(iter(binary_output._TRANSIENT_FACT_STORE_SIDECARS)),
            "generation_attachments.json",
        )
        for forbidden_name in forbidden_names:
            for kind in ("regular", "broken_symlink"):
                with self.subTest(file=forbidden_name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    fixture = self.pending_integrity_fixture(temporary)
                    forbidden = fixture["generation"] / forbidden_name
                    if kind == "regular":
                        forbidden.write_bytes(b"forbidden")
                    else:
                        try:
                            forbidden.symlink_to(
                                fixture["generation"] / "missing-target"
                            )
                        except OSError as error:
                            self.skipTest(f"symlinks unavailable: {error}")
                        self.assertFalse(forbidden.exists())
                        self.assertTrue(forbidden.is_symlink())
                    with self.assertRaises(binary_output.BinaryOutputError) as caught:
                        self.run_pending_integrity(fixture)
                    self.assertEqual(
                        caught.exception.reason_code,
                        "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                    )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.pending_integrity_fixture(temporary)
            result, proof = self.run_pending_integrity(
                fixture,
                candidate_authority=candidate,
                capture_mode=(
                    binary_output._CANDIDATE_INTEGRITY_PROOF_CAPTURE_CAPABILITY
                ),
            )
            self.assertEqual(result, candidate)
            self.assertIsInstance(proof, binary_output._GenerationIntegrityProof)
            self.assertEqual(
                proof.publication_authority_bytes,
                binary_output._json_bytes(candidate),
            )

    def test_pending_integrity_validation_and_proof_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.pending_integrity_fixture(temporary)
            validation = fixture["validation"]
            invalid_validations = (
                (validation, b"", True),
                (validation, b"\xff", True),
                ([], binary_output._json_bytes([]), True),
                (validation, binary_output._json_bytes(validation) + b" ", True),
                (
                    {**validation, "validation_run_identity": "f" * 64},
                    None,
                    True,
                ),
                (validation, None, False),
            )
            for changed_validation, changed_content, complete in invalid_validations:
                options = {
                    "validation": changed_validation,
                    "validation_complete": complete,
                }
                if changed_content is not None or changed_content == b"":
                    options["validation_content"] = changed_content
                with self.subTest(validation=changed_validation, complete=complete), self.assertRaises(
                    binary_output.BinaryOutputError,
                ) as caught:
                    self.run_pending_integrity(fixture, **options)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

            result, proof = self.run_pending_integrity(
                fixture,
                capture_mode=binary_output._INTEGRITY_PROOF_CAPTURE_CAPABILITY,
            )
            self.assertIsNone(result)
            self.assertIsInstance(proof, binary_output._GenerationIntegrityProof)
            self.assertIsNone(proof.publication_authority_bytes)
            self.assertEqual(len(proof.directory_snapshots), 4)
            self.assertGreaterEqual(len(proof.file_snapshots), 10)

            authority = {"authority_mode": "release_evidence"}
            result, proof = self.run_pending_integrity(
                fixture,
                publication_authority=authority,
                capture_mode=binary_output._INTEGRITY_PROOF_CAPTURE_CAPABILITY,
            )
            self.assertEqual(result, authority)
            self.assertEqual(
                proof.publication_authority_bytes,
                binary_output._json_bytes(authority),
            )

    def test_integrity_proof_wrapper_type_and_candidate_authority_matrix(self):
        root = Path("/output")
        pending = self.active_descriptor_core()
        proof = binary_output._GenerationIntegrityProof(None, (), ())
        authority = {"authority_mode": "candidate_source_measurement"}

        def verified_with(result, captured):
            def verify(_root, _pending):
                binary_output._INTEGRITY_PROOF_RESULT_CONTEXT.set(captured)
                return result
            return verify

        for captured, expected in ((object(), None), (proof, proof)):
            with self.subTest(normal_proof=expected is not None), patch.object(
                binary_output, "_verify_pending_generation_integrity",
                side_effect=verified_with(None, captured),
            ):
                self.assertEqual(
                    binary_output._verify_pending_generation_integrity_with_proof(
                        root, pending,
                    ),
                    (None, expected),
                )

        with patch.object(
            binary_output, "_verify_pending_generation_integrity",
            return_value=None,
        ), self.assertRaises(binary_output.BinaryOutputError) as caught:
            binary_output._verify_candidate_generation_integrity_with_proof(
                root, pending,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_GENERATION_PUBLICATION_DRY_RUN_FORBIDDEN",
        )

        for captured, expected in ((object(), None), (proof, proof)):
            with self.subTest(candidate_proof=expected is not None), patch.object(
                binary_output, "_verify_pending_generation_integrity",
                side_effect=verified_with(authority, captured),
            ):
                self.assertEqual(
                    binary_output._verify_candidate_generation_integrity_with_proof(
                        root, pending,
                    ),
                    (authority, expected),
                )

    def test_generation_identity_manifest_and_public_binding_boundary_matrix(self):
        root = Path("/output")
        generations = root / "binary_generations"
        generation_identity = "a" * 64
        generation = generations / generation_identity
        manifest = {"result_generation_identity": generation_identity}
        canonical = binary_output._json_bytes(manifest)
        authority = {
            "performance_authority_gate_binding": self.authority_binding(digit="1")
        }
        snapshot = (1, 2, 1, len(canonical), 3, 4)

        def invoke(content, *, computed=None, read_error=None, allowed=authority):
            read = Mock(
                side_effect=read_error,
                return_value=("b" * 64, content, snapshot),
            )
            with patch.object(
                binary_output, "_physical_generation_namespace",
                return_value=generations,
            ), patch.object(
                binary_output, "_physical_generation_directory",
                return_value=generation,
            ), patch.object(
                binary_output, "_read_stable_generation_file", read,
            ), patch.object(
                binary_output, "_result_generation_identity_from_manifest",
                return_value=(generation_identity if computed is None else computed),
            ), patch.object(
                binary_output, "_require_generation_publication_allowed",
                return_value=allowed,
            ) as require_allowed:
                result = binary_output._require_generation_identity_publication_allowed(
                    root, generation_identity,
                )
            return result, require_allowed

        for error in (
            binary_output.BinaryOutputError("READ_FAILED", "broken"),
            OSError("unreadable"),
        ):
            with self.subTest(read_error=type(error).__name__), self.assertRaises(
                binary_output.BinaryOutputError,
            ) as caught:
                invoke(canonical, read_error=error)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_GENERATION_MANIFEST_INVALID",
            )

        invalid_inputs = (
            (b"", None),
            (b"\xff", None),
            (binary_output._json_bytes([]), None),
            (canonical + b" ", None),
            (
                binary_output._json_bytes({
                    "result_generation_identity": "f" * 64,
                }),
                None,
            ),
            (canonical, "f" * 64),
        )
        for content, computed in invalid_inputs:
            with self.subTest(content=content[:20], computed=computed), self.assertRaises(
                binary_output.BinaryOutputError,
            ):
                invoke(content, computed=computed)

        result, require_allowed = invoke(canonical)
        self.assertEqual(result, authority)
        require_allowed.assert_called_once_with(generation, manifest)

        for invalid_identity in (None, True, "", "z" * 64):
            with self.subTest(identity=invalid_identity), self.assertRaises(
                binary_output.BinaryOutputError,
            ):
                binary_output.read_binary_generation_publication_authority_binding(
                    root, invalid_identity,
                )

        binding = authority["performance_authority_gate_binding"]
        with patch.object(
            binary_output, "_canonical_physical_output_root", return_value=root,
        ), patch.object(
            binary_output, "_require_generation_identity_publication_allowed",
            return_value=authority,
        ):
            observed = (
                binary_output.read_binary_generation_publication_authority_binding(
                    root, generation_identity,
                )
            )
        self.assertEqual(observed, binding)
        self.assertIsNot(observed, binding)

        for invalid_authority in (None, {}, {"performance_authority_gate_binding": {}}):
            with self.subTest(authority=invalid_authority), patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_require_generation_identity_publication_allowed",
                return_value=invalid_authority,
            ), self.assertRaises(binary_output.BinaryOutputError):
                binary_output.read_binary_generation_publication_authority_binding(
                    root, generation_identity,
                )

    def test_active_descriptor_failed_compare_removes_private_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with patch.object(
                binary_output, "_active_descriptor_path_matches",
                return_value=False,
            ), patch.object(
                binary_output, "_unlink_missing_ok",
                wraps=binary_output._unlink_missing_ok,
            ) as unlink:
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output._write_active_descriptor(
                        root, self.active_descriptor_core(),
                    )
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
            )
            unlink.assert_called_once()
            self.assertEqual(
                list(root.glob(".active-generation-*")),
                [],
            )

    def test_stat_recheck_proof_and_post_guard_boundary_matrix(self):
        root = Path("/output")
        snapshot = (1, 2, 1, 3, 4, 5)
        other = root / "binary_generations"
        valid_proof = binary_output._GenerationIntegrityProof(
            None,
            ((root, snapshot), (other, snapshot)),
            ((other / "sidecar.json", snapshot),),
        )

        windows_os = Mock(wraps=os)
        windows_os.name = "nt"
        with patch.object(binary_output, "os", windows_os):
            self.assertIsNone(binary_output._prepare_post_guard_stat_recheck(root))
            self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
                valid_proof, root, probed_device=1,
            ))

        with patch.object(
            binary_output, "_directory_snapshot",
            side_effect=binary_output.BinaryOutputError("ROOT_INVALID", "broken"),
        ):
            self.assertIsNone(binary_output._prepare_post_guard_stat_recheck(root))
        for supported, expected in ((False, None), (True, 1)):
            with self.subTest(supported=supported), patch.object(
                binary_output, "_directory_snapshot", return_value=snapshot,
            ), patch.object(
                binary_output, "_filesystem_supports_direct_seal_fast_path",
                return_value=supported,
            ):
                self.assertEqual(
                    binary_output._prepare_post_guard_stat_recheck(root), expected,
                )

        self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
            None, root, probed_device=1,
        ))
        self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
            valid_proof, root, probed_device=None,
        ))
        missing_root = binary_output._GenerationIntegrityProof(
            None, ((other, snapshot),), (),
        )
        self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
            missing_root, root, probed_device=1,
        ))
        self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
            valid_proof, root, probed_device=2,
        ))
        wrong_device = (2, 2, 1, 3, 4, 5)
        for changed in (
            binary_output._GenerationIntegrityProof(
                None, ((root, snapshot), (other, wrong_device)), (),
            ),
            binary_output._GenerationIntegrityProof(
                None, ((root, snapshot),), ((other / "sidecar.json", wrong_device),),
            ),
        ):
            self.assertFalse(binary_output._proof_supports_post_guard_stat_recheck(
                changed, root, probed_device=1,
            ))
        self.assertTrue(binary_output._proof_supports_post_guard_stat_recheck(
            valid_proof, root, probed_device=1,
        ))

        with patch.object(
            binary_output, "_assert_generation_snapshot_unchanged",
        ) as unchanged:
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, None, valid_proof, stat_recheck_allowed=True,
            )
        unchanged.assert_called_once()

        with patch.object(
            binary_output, "_verify_pending_generation_integrity",
            return_value=None,
        ) as verify:
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, None, None, stat_recheck_allowed=True,
            )
        verify.assert_called_once()

        authority = {"authority_mode": "release_evidence"}
        with patch.object(
            binary_output, "_verify_pending_generation_integrity",
            return_value=dict(authority),
        ):
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, authority, None, stat_recheck_allowed=False,
            )
        with patch.object(
            binary_output, "_verify_pending_generation_integrity",
            return_value={"authority_mode": "different"},
        ), self.assertRaises(binary_output.BinaryOutputError):
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, authority, None, stat_recheck_allowed=False,
            )
        with patch.object(
            binary_output, "_verify_pending_generation_integrity",
            return_value={"authority_mode": "appeared"},
        ), self.assertRaises(binary_output.BinaryOutputError):
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, None, None, stat_recheck_allowed=False,
            )
        candidate = {"authority_mode": "candidate_source_measurement"}
        with patch.object(
            binary_output, "_verify_candidate_generation_integrity_with_proof",
            return_value=(dict(candidate), None),
        ) as verify_candidate:
            binary_output._post_guard_generation_integrity_recheck(
                root, {}, candidate, None,
                stat_recheck_allowed=False, candidate_measurement=True,
            )
        verify_candidate.assert_called_once()

        descriptor_proof = binary_output._TransactionDescriptorProof(
            file_snapshot=snapshot, parent_snapshot=snapshot,
        )
        binary_output._assert_descriptor_reproof_unchanged(
            descriptor_proof, descriptor_proof, root,
        )
        with self.assertRaises(binary_output.BinaryOutputError):
            binary_output._assert_descriptor_reproof_unchanged(
                descriptor_proof,
                binary_output._TransactionDescriptorProof(None, snapshot),
                root,
            )

    def test_stable_transaction_descriptor_absence_and_mutation_matrix(self):
        root = Path("/output")
        path = root / "active_binary_generation.json"
        parent_snapshot = (1, 2, 1, 3, 4, 5)
        changed_parent = (1, 2, 1, 3, 4, 6)

        absence_cases = (
            (({"appeared": True}, None), (parent_snapshot, parent_snapshot)),
            ((None, (1, 2)), (parent_snapshot, parent_snapshot)),
            ((None, None), (parent_snapshot, changed_parent)),
        )
        for observed, directories in absence_cases:
            with self.subTest(absence=observed), patch.object(
                binary_output, "_active_descriptor_destination", return_value=path,
            ), patch.object(
                binary_output, "_directory_snapshot", side_effect=directories,
            ), patch.object(
                binary_output, "_read_active_descriptor", return_value=observed,
            ), self.assertRaises(binary_output.BinaryOutputError):
                binary_output._stable_reprove_transaction_descriptor(
                    root, None, None,
                )

        with patch.object(
            binary_output, "_active_descriptor_destination", return_value=path,
        ), patch.object(
            binary_output, "_directory_snapshot",
            side_effect=(parent_snapshot, parent_snapshot),
        ), patch.object(
            binary_output, "_read_active_descriptor", return_value=(None, None),
        ):
            proof = binary_output._stable_reprove_transaction_descriptor(
                root, None, None,
            )
        self.assertEqual(proof.file_snapshot, None)
        self.assertEqual(proof.parent_snapshot, parent_snapshot)

        expected = self.active_descriptor_core()
        expected_bytes = binary_output._json_bytes(expected)
        regular = self.stat_result()
        snapshot = binary_output._regular_file_snapshot(regular)
        identity = (snapshot[0], snapshot[1])

        def invoke(
            *, content=expected_bytes, observed=expected,
            observed_identity=identity, file_snapshot=snapshot,
            final_stat=regular, directories=(parent_snapshot, parent_snapshot),
            expected_file_identity=identity,
        ):
            with patch.object(
                binary_output, "_active_descriptor_destination", return_value=path,
            ), patch.object(
                binary_output, "_directory_snapshot", side_effect=directories,
            ), patch.object(
                binary_output, "_read_stable_generation_file",
                return_value=("a" * 64, content, file_snapshot),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                return_value=(observed, observed_identity),
            ), patch.object(
                binary_output.os, "lstat", return_value=final_stat,
            ):
                return binary_output._stable_reprove_transaction_descriptor(
                    root, expected, expected_file_identity,
                )

        with self.assertRaises(binary_output.BinaryOutputError):
            invoke(expected_file_identity=None)
        mutations = (
            {"content": b"{}"},
            {"observed": {"different": True}},
            {"observed_identity": (9, 9)},
            {"file_snapshot": (9, 9, 1, 3, 4, 5)},
            {"final_stat": self.stat_result(mode=stat.S_IFLNK | 0o777)},
            {"final_stat": self.stat_result(mode=stat.S_IFDIR | 0o700)},
            {"final_stat": self.stat_result(links=2)},
            {"final_stat": self.stat_result(size=99)},
            {"directories": (parent_snapshot, changed_parent)},
        )
        for options in mutations:
            with self.subTest(options=options), self.assertRaises(
                binary_output.BinaryOutputError,
            ):
                invoke(**options)
        proof = invoke()
        self.assertEqual(proof.file_snapshot, snapshot)
        self.assertEqual(proof.parent_snapshot, parent_snapshot)

    def test_manifest_and_validation_contract_mutation_matrix(self):
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        profile = fixture.profile()
        with tempfile.TemporaryDirectory() as temporary:
            manifest = binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "boundary-contract"},
            )
            validation = fixture.validation_result(manifest)
        validation.pop("validation_result_path")

        self.assertEqual(
            binary_output._result_generation_identity_from_manifest(manifest),
            manifest["result_generation_identity"],
        )
        manifest_mutations = []
        for field, value in (
            ("schema", "wrong"),
            ("authority", "wrong"),
            ("analysis_context_identity", None),
            ("analysis_context_identity", ""),
            ("trace_result_set_digest", None),
            ("trace_result_set_digest", ""),
            ("active_snapshot_identities", []),
            ("sidecar_content_identities", []),
            ("policy_identities", []),
        ):
            manifest_mutations.append({**manifest, field: value})
        missing_snapshot = dict(manifest["active_snapshot_identities"])
        missing_snapshot.pop(next(iter(missing_snapshot)))
        manifest_mutations.append({
            **manifest, "active_snapshot_identities": missing_snapshot,
        })
        for value in (None, ""):
            changed_snapshots = dict(manifest["active_snapshot_identities"])
            changed_snapshots[next(iter(changed_snapshots))] = value
            manifest_mutations.append({
                **manifest, "active_snapshot_identities": changed_snapshots,
            })
        missing_sidecars = dict(manifest["sidecar_content_identities"])
        missing_sidecars.pop("binary_summary.json")
        manifest_mutations.append({
            **manifest, "sidecar_content_identities": missing_sidecars,
        })
        for changed in manifest_mutations:
            with self.subTest(manifest_fields=set(changed)):
                self.assertEqual(
                    binary_output._result_generation_identity_from_manifest(changed),
                    "",
                )
        with patch.object(
            binary_output, "_identity", side_effect=TypeError("not canonical"),
        ):
            self.assertEqual(
                binary_output._result_generation_identity_from_manifest(manifest),
                "",
            )

        self.assertTrue(binary_output.is_complete_v3_validation_result(
            validation, manifest,
        ))
        validation_mutations = []
        for field, value in (
            ("schema", "wrong"),
            ("result_generation_identity", "f" * 64),
            ("validation_policy_version", "wrong"),
            ("status", "failed"),
            ("issue_count", True),
            ("issue_count", 1),
            ("issues", {}),
            ("issues", [{"issue": True}]),
            ("domain_summary", []),
            ("domain_summary", {"domain": 1}),
            ("skipped_domains", {}),
            ("skipped_domains", ["domain"]),
            ("production_identity_influence", "production"),
            ("helper_identities", []),
            ("helper_identities", {"base": "e" * 64}),
        ):
            validation_mutations.append({**validation, field: value})
        for helper in ("base", "current"):
            changed_helpers = dict(validation["helper_identities"])
            changed_helpers[helper] = "short"
            validation_mutations.append({
                **validation, "helper_identities": changed_helpers,
            })
        for field in (
            "validation_run_identity",
            "oracle_support_manifest_identity",
            "truth_set_identity",
            "issue_set_identity",
            "validator_implementation_identity",
        ):
            validation_mutations.append({**validation, field: "short"})
        validation_mutations.append({**validation, "extra": True})
        for changed in validation_mutations:
            with self.subTest(validation_fields=set(changed)):
                self.assertFalse(binary_output.is_complete_v3_validation_result(
                    changed, manifest,
                ))
        self.assertFalse(binary_output.is_complete_v3_validation_result(
            validation, {**manifest, "active_snapshot_identities": []},
        ))
        with patch.object(
            binary_output, "canonical_identity_streaming",
            side_effect=TypeError("invalid issue data"),
        ):
            self.assertFalse(binary_output.is_complete_v3_validation_result(
                validation, manifest,
            ))
        self.assertFalse(binary_output.is_complete_v3_validation_result(
            {**validation, "issue_set_identity": "0" * 64}, manifest,
        ))
        self.assertFalse(binary_output.is_complete_v3_validation_result(
            {**validation, "validation_run_identity": "0" * 64}, manifest,
        ))

        core = self.active_descriptor_core()
        self.assertTrue(binary_output._public_active_is_sealed(core))
        self.assertFalse(binary_output._public_active_is_sealed({**core, "extra": True}))
        self.assertFalse(binary_output._public_active_is_sealed({"invalid": True}))

    def test_direct_seal_capability_installation_fails_closed_matrix(self):
        root = Path("/output")
        generation = root / "binary_generations" / ("1" * 64)
        active = {
            **self.active_descriptor_core(digit="1"),
            "activation_identity": "4" * 64,
            "activation_predecessor": None,
        }
        descriptor_bytes = binary_output._json_bytes(active)
        descriptor_stat = self.stat_result(size=len(descriptor_bytes))
        descriptor_snapshot = binary_output._regular_file_snapshot(descriptor_stat)
        descriptor_identity = descriptor_snapshot[:2]
        root_snapshot = (1, 10, 1, 3, 4, 5)
        generation_snapshot = (1, 11, 1, 3, 4, 5)
        sidecar_snapshot = (1, 12, 1, 3, 4, 5)
        proof = binary_output._GenerationIntegrityProof(
            None,
            ((root, root_snapshot), (generation, generation_snapshot)),
            ((generation / "sidecar.json", sidecar_snapshot),),
        )
        descriptor_path = root / "active_binary_generation.json"
        real_lstat = os.lstat

        def invoke(
            *, selected_proof=proof, probed_device=1, predecessor=None,
            before_identity=None, content=descriptor_bytes, observed=active,
            after_identity=descriptor_identity, file_snapshot=descriptor_snapshot,
            directory_values=(root_snapshot, root_snapshot),
            final_stat=descriptor_stat,
        ):
            directories = iter(directory_values)

            def routed_lstat(path):
                if Path(path) == descriptor_path:
                    return final_stat
                return real_lstat(path)

            with patch.object(
                binary_output, "_assert_generation_snapshot_unchanged",
            ), patch.object(
                binary_output, "_read_stable_generation_file",
                return_value=("a" * 64, content, file_snapshot),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                return_value=(observed, after_identity),
            ), patch.object(
                binary_output, "_directory_snapshot",
                side_effect=lambda _path: next(directories),
            ), patch.object(
                binary_output.os, "lstat", side_effect=routed_lstat,
            ), patch.object(
                binary_output, "_install_direct_seal_capability",
            ) as install, patch.object(
                binary_output, "_discard_current_direct_seal_capability",
            ) as discard:
                result = binary_output._try_install_direct_seal_capability(
                    root,
                    active,
                    predecessor=predecessor,
                    descriptor_before_identity=before_identity,
                    proof=selected_proof,
                    probed_device=probed_device,
                )
            return result, install, discard

        self.assertFalse(invoke(selected_proof=None)[0])
        self.assertFalse(invoke(probed_device=None)[0])
        missing_root = replace(
            proof, directory_snapshots=((generation, generation_snapshot),),
        )
        self.assertFalse(invoke(selected_proof=missing_root)[0])
        wrong_root_device = replace(
            proof,
            directory_snapshots=((root, (2, 10, 1, 3, 4, 5)),),
            file_snapshots=(),
        )
        self.assertFalse(invoke(selected_proof=wrong_root_device)[0])
        wrong_generation_device = replace(
            proof,
            directory_snapshots=(
                (root, root_snapshot),
                (generation, (2, 11, 1, 3, 4, 5)),
            ),
        )
        self.assertFalse(invoke(selected_proof=wrong_generation_device)[0])
        wrong_sidecar_device = replace(
            proof,
            file_snapshots=((generation / "sidecar.json", (2, 12, 1, 3, 4, 5)),),
        )
        self.assertFalse(invoke(selected_proof=wrong_sidecar_device)[0])

        mutations = (
            {"content": b"{}"},
            {"observed": {"different": True}},
            {"after_identity": None},
            {"after_identity": (9, 9)},
            {
                "predecessor": self.active_descriptor_core(digit="5"),
                "before_identity": descriptor_identity,
            },
            {"before_identity": (8, 8)},
            {"predecessor": self.active_descriptor_core(digit="5")},
            {"directory_values": ((2, 10, 1, 3, 4, 5),)},
            {"directory_values": (root_snapshot, (1, 10, 1, 3, 4, 6))},
            {"final_stat": self.stat_result(size=99)},
        )
        for options in mutations:
            with self.subTest(options=options):
                result, install, discard = invoke(**options)
            self.assertFalse(result)
            install.assert_not_called()
            discard.assert_called_once()

        result, install, discard = invoke()
        self.assertTrue(result)
        install.assert_called_once()
        discard.assert_not_called()
        predecessor = self.active_descriptor_core(digit="5")
        result, install, _discard = invoke(
            predecessor=predecessor, before_identity=(8, 8),
        )
        self.assertTrue(result)
        self.assertEqual(
            install.call_args.args[0].predecessor_bytes,
            binary_output._json_bytes(predecessor),
        )

    def test_direct_seal_fast_authority_rejects_every_stale_binding(self):
        root = Path("/output")
        generation = root / "binary_generations" / ("1" * 64)
        current = {
            **self.active_descriptor_core(digit="1"),
            "activation_identity": "4" * 64,
            "activation_predecessor": None,
        }
        descriptor_bytes = binary_output._json_bytes(current)
        descriptor_stat = self.stat_result(size=len(descriptor_bytes))
        descriptor_snapshot = binary_output._regular_file_snapshot(descriptor_stat)
        root_snapshot = (1, 10, 1, 3, 4, 5)
        generation_snapshot = (1, 11, 1, 3, 4, 5)
        sidecar_snapshot = (1, 12, 1, 3, 4, 5)
        base = self.direct_seal_capability(root, digit="1")
        capability = replace(
            base,
            owner_process_identity=os.getpid(),
            owner_thread_identity=threading.get_ident(),
            root_identity=root_snapshot[:2],
            probed_device=1,
            result_generation_identity=current["result_generation_identity"],
            validation_run_identity=current["validation_run_identity"],
            validation_result_sha256=current["validation_result_sha256"],
            activation_identity=current["activation_identity"],
            unsealed_descriptor_bytes=descriptor_bytes,
            predecessor_bytes=None,
            descriptor_after_identity=descriptor_snapshot[:2],
            descriptor_snapshot=descriptor_snapshot,
            publication_authority_bytes=None,
            directory_snapshots=(
                (root, root_snapshot),
                (generation, generation_snapshot),
            ),
            file_snapshots=((generation / "sidecar.json", sidecar_snapshot),),
        )
        descriptor_path = root / "active_binary_generation.json"
        real_lstat = os.lstat

        def invoke(
            selected=capability, *, value=current, identity=descriptor_snapshot[:2],
            final_stat=descriptor_stat, final_root=root_snapshot,
            snapshot_error=None,
        ):
            def routed_lstat(path):
                if Path(path) == descriptor_path:
                    return final_stat
                return real_lstat(path)

            with patch.object(
                binary_output, "_assert_generation_snapshot_unchanged",
                side_effect=snapshot_error,
            ), patch.object(
                binary_output.os, "lstat", side_effect=routed_lstat,
            ), patch.object(
                binary_output, "_directory_snapshot", return_value=final_root,
            ):
                return binary_output._direct_seal_fast_publication_authority(
                    selected, root, value, identity,
                )

        self.assertEqual(invoke(None), (False, None, None))
        stale_capabilities = (
            replace(capability, owner_process_identity=os.getpid() + 1),
            replace(capability, owner_thread_identity=threading.get_ident() + 1),
            replace(capability, canonical_root=Path("/other")),
            replace(capability, unsealed_descriptor_bytes=b"{}"),
            replace(capability, result_generation_identity="9" * 64),
            replace(capability, validation_run_identity="9" * 64),
            replace(capability, validation_result_sha256="9" * 64),
            replace(capability, activation_identity="9" * 64),
        )
        for stale in stale_capabilities:
            with self.subTest(stale=stale):
                self.assertEqual(invoke(stale), (False, None, None))
        self.assertEqual(invoke(capability, identity=(9, 9)), (False, None, None))

        predecessor = self.active_descriptor_core(digit="5")
        with_predecessor = {**current, "activation_predecessor": predecessor}
        predecessor_bytes = binary_output._json_bytes(predecessor)
        self.assertEqual(
            invoke(capability, value=with_predecessor),
            (False, None, None),
        )
        self.assertEqual(
            invoke(replace(capability, predecessor_bytes=b"{}")),
            (False, None, None),
        )
        predecessor_capability = replace(
            capability,
            unsealed_descriptor_bytes=binary_output._json_bytes(with_predecessor),
            predecessor_bytes=predecessor_bytes,
        )

        invalid_snapshots = (
            replace(capability, directory_snapshots=((generation, generation_snapshot),)),
            replace(capability, root_identity=(9, 9)),
            replace(capability, probed_device=2),
            replace(
                capability,
                directory_snapshots=(
                    (root, root_snapshot),
                    (generation, (2, 11, 1, 3, 4, 5)),
                ),
            ),
            replace(
                capability,
                file_snapshots=((generation / "sidecar.json", (2, 12, 1, 3, 4, 5)),),
            ),
            replace(capability, descriptor_snapshot=(2, 2, 1, 3, 4, 5)),
        )
        for stale in invalid_snapshots:
            with self.subTest(snapshot=stale):
                self.assertEqual(invoke(stale), (False, None, None))

        self.assertEqual(
            invoke(
                capability,
                snapshot_error=binary_output.BinaryOutputError(
                    "SNAPSHOT_CHANGED", "changed",
                ),
            ),
            (False, None, None),
        )
        for invalid_stat in (
            self.stat_result(mode=stat.S_IFLNK | 0o777, size=len(descriptor_bytes)),
            self.stat_result(mode=stat.S_IFDIR | 0o700, size=len(descriptor_bytes)),
            self.stat_result(links=2, size=len(descriptor_bytes)),
            self.stat_result(size=len(descriptor_bytes) + 1),
        ):
            with self.subTest(stat=invalid_stat):
                self.assertEqual(
                    invoke(capability, final_stat=invalid_stat),
                    (False, None, None),
                )
        self.assertEqual(
            invoke(capability, final_root=(1, 10, 1, 3, 4, 6)),
            (False, None, None),
        )

        invalid_authority_bytes = (
            b"\xff",
            binary_output._json_bytes([]),
            b"{} ",
        )
        for content in invalid_authority_bytes:
            with self.subTest(authority=content):
                self.assertEqual(
                    invoke(replace(
                        capability, publication_authority_bytes=content,
                    )),
                    (False, None, None),
                )
        authority = {"authority_mode": "release_evidence"}
        valid_with_authority = replace(
            capability,
            publication_authority_bytes=binary_output._json_bytes(authority),
        )
        valid, observed, proof = invoke(valid_with_authority)
        self.assertTrue(valid)
        self.assertEqual(observed, authority)
        self.assertIsInstance(proof, binary_output._GenerationIntegrityProof)
        valid, observed, proof = invoke(predecessor_capability, value=with_predecessor)
        self.assertTrue(valid)
        self.assertIsNone(observed)
        self.assertIsInstance(proof, binary_output._GenerationIntegrityProof)

    def test_generation_gc_absence_reference_and_durability_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary).resolve() / "missing-output"
            summary = binary_output.prune_unreferenced_binary_generations(missing)
            self.assertEqual(summary["removed_count"], 0)

            file_root = Path(temporary).resolve() / "file-output"
            file_root.write_text("occupied", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.prune_unreferenced_binary_generations(file_root)

            broken_root = Path(temporary).resolve() / "broken-output"
            try:
                broken_root.symlink_to(Path(temporary) / "missing-target")
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.prune_unreferenced_binary_generations(broken_root)

        for invalid in (None, "short"):
            with self.subTest(protected=invalid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.prune_unreferenced_binary_generations(
                        root, protected_generation_identities=(invalid,),
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_GC_PROTECTED_IDENTITY_INVALID",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            summary = binary_output.prune_unreferenced_binary_generations(
                root, protected_generation_identities=("a" * 64,),
            )
            self.assertEqual(
                summary["protected_generation_identities"], ["a" * 64],
            )

        for relative in (
            Path("active_binary_generation.json"),
            binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH,
        ):
            with self.subTest(descriptor=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"{}")
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.prune_unreferenced_binary_generations(root)
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_GC_REFERENCE_INVALID",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "binary_generations").write_text("file", encoding="utf-8")
            with self.assertRaises(binary_output.BinaryOutputError):
                binary_output.prune_unreferenced_binary_generations(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            stale = root / "binary_generations" / ("b" * 64)
            stale.mkdir(parents=True)
            with patch.object(
                binary_output, "_fsync_directory",
                side_effect=OSError("durability unavailable"),
            ):
                summary = binary_output.prune_unreferenced_binary_generations(root)
            self.assertFalse(stale.exists())
            self.assertEqual(summary["removed_count"], 1)
            self.assertEqual(summary["failure_count"], 1)
            self.assertIn("fsync failed", summary["failures"][0]["detail"])

    def test_output_payload_entrypoint_and_summary_boundary_matrix(self):
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        profile = fixture.profile()
        default_payloads = binary_output.build_output_payloads(
            decisions, traces, profile,
        )
        self.assertEqual(
            default_payloads["binary_coverage.json"]["source_overlay"],
            {"coverage_status": "not_provided"},
        )
        self.assertEqual(
            default_payloads["binary_coverage.json"]["batch_graph_stats"], {},
        )

        assessment = dict(decisions.projection_assessments[0])
        unsupported = {
            **assessment,
            "projection_assessment_identity": "unsupported-assessment",
            "analysis_projection_status": "unsupported",
        }
        unrelated = {
            **unsupported,
            "projection_assessment_identity": "unrelated-assessment",
            "decision_identity": "unrelated-decision",
        }
        result = dict(traces.formal_results[0])
        result["path_set_complete"] = False
        rich_traces = replace(
            traces,
            formal_results=(result,),
            entrypoint_records=(
                {"path_certainty": "exact", "member_identity": "entry-exact"},
                {"path_certainty": "exact", "member_identity": ""},
                {"path_certainty": "possible", "member_identity": "entry-exact"},
                {"path_certainty": "possible", "member_identity": "entry-possible"},
                {"path_certainty": "possible", "member_identity": ""},
                {"path_certainty": "unknown", "member_identity": "entry-other"},
            ),
            resource_activation_results=(
                {"activation_status": "reachable"},
                {"activation_status": "not_reachable"},
            ),
            graph_stats={"node_count": 3},
        )
        rich_decisions = replace(
            decisions,
            projection_assessments=(
                *decisions.projection_assessments,
                unrelated,
                unsupported,
            ),
        )
        overlay = binary_output.SourceOverlayResult(
            source_snapshot_identity="source",
            overlay_set_identity="overlay",
            rows=(),
            mapped_count=0,
            ambiguous_count=0,
            binary_only_count=0,
            conflict_count=0,
            coverage_status="complete",
        )
        payloads = binary_output.build_output_payloads(
            rich_decisions,
            rich_traces,
            profile,
            source_overlay=overlay,
            source_inputs={"repository": "fixture"},
        )
        summary = payloads["binary_summary.json"]
        self.assertEqual(summary["confirmed_unprojectable_fact_count"], 1)
        self.assertEqual(summary["exact_entrypoint_count"], 1)
        self.assertEqual(summary["possible_entrypoint_count"], 1)
        self.assertFalse(summary["formal_path_set_complete"])
        self.assertEqual(summary["resource_activation_reachable_total"], 1)
        self.assertEqual(summary["source_inputs"], {"repository": "fixture"})
        coverage = payloads["binary_coverage.json"]
        self.assertEqual(coverage["batch_graph_stats"], {"node_count": 3})
        self.assertEqual(coverage["source_overlay"]["coverage_status"], "complete")

    def test_compare_and_restore_transaction_state_matrix(self):
        root = Path("/output")
        generation_identity = "1" * 64
        activation_identity = "4" * 64
        candidate = self.active_descriptor_core(digit="1")
        predecessor = self.active_descriptor_core(digit="5")
        other = self.active_descriptor_core(digit="6")
        pending_identity = (7, 8)
        active_identity = (1, 2)

        def pending(value, *, prior=None, state="pending"):
            return {
                **value,
                "activation_identity": activation_identity,
                "activation_predecessor": prior,
                "activation_state": state,
            }

        def invoke(
            pending_raw, current, *, previous=None, path_matches=True,
            unlink_error=None,
        ):
            reads = iter(((pending_raw, pending_identity), (current, active_identity)))
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_active_generation_lock", return_value=nullcontext(),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                side_effect=lambda *_args, **_kwargs: next(reads),
            ), patch.object(
                binary_output, "_active_descriptor_path_matches",
                return_value=path_matches,
            ), patch.object(
                Path, "unlink", side_effect=unlink_error,
            ) as unlink, patch.object(
                binary_output, "_fsync_directory",
            ) as fsync, patch.object(
                binary_output, "_write_active_descriptor",
            ) as write:
                result = binary_output.compare_and_restore_active_binary_generation(
                    root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                    previous_active=previous,
                )
            return result, unlink, fsync, write

        for current_identity, activation in (
            ("short", activation_identity),
            (generation_identity, "short"),
        ):
            with patch.object(
                binary_output, "_canonical_physical_output_root",
            ) as canonical:
                self.assertFalse(
                    binary_output.compare_and_restore_active_binary_generation(
                        root,
                        expected_current_identity=current_identity,
                        expected_activation_identity=activation,
                    )
                )
            canonical.assert_not_called()

        invalid_pending = (
            {"invalid": True},
            pending(self.active_descriptor_core(digit="9")),
            {**pending(candidate), "activation_identity": "9" * 64},
        )
        for value in invalid_pending:
            self.assertFalse(invoke(value, candidate)[0])

        receipt_with_predecessor = pending(candidate, prior=predecessor)
        self.assertFalse(invoke(
            receipt_with_predecessor, candidate, previous=other,
        )[0])

        receipt_without_predecessor = pending(candidate)
        self.assertFalse(invoke(
            receipt_without_predecessor, candidate, path_matches=False,
        )[0])
        restored, unlink, fsync, write = invoke(
            receipt_without_predecessor, candidate,
        )
        self.assertTrue(restored)
        unlink.assert_called()
        fsync.assert_called()
        write.assert_not_called()

        restored, _unlink, _fsync, write = invoke(
            receipt_with_predecessor, candidate, previous=predecessor,
        )
        self.assertTrue(restored)
        write.assert_called_once()
        self.assertEqual(write.call_args.args[1], predecessor)

        self.assertTrue(invoke(receipt_without_predecessor, None)[0])
        self.assertTrue(invoke(
            receipt_with_predecessor, predecessor, previous=predecessor,
        )[0])
        self.assertFalse(invoke(
            receipt_without_predecessor, {**candidate, "extra": True},
        )[0])
        self.assertFalse(invoke(receipt_with_predecessor, None)[0])
        self.assertFalse(invoke(
            receipt_with_predecessor, {**predecessor, "extra": True},
        )[0])
        self.assertFalse(invoke(receipt_with_predecessor, other)[0])
        with self.assertRaises(binary_output.BinaryOutputError):
            invoke(receipt_without_predecessor, None, path_matches=False)

        no_pending_invalid_currents = (
            None,
            other,
            {**candidate, "activation_identity": "9" * 64,
             "activation_predecessor": None},
            {**candidate, "activation_identity": activation_identity},
            {**candidate, "activation_identity": activation_identity,
             "activation_predecessor": {"invalid": True}},
        )
        for current in no_pending_invalid_currents:
            self.assertFalse(invoke(None, current)[0])

        direct_receipt = {
            **candidate,
            "activation_identity": activation_identity,
            "activation_predecessor": None,
        }
        with self.assertRaises(binary_output.BinaryOutputError):
            invoke(None, direct_receipt, path_matches=False)
        self.assertTrue(invoke(None, direct_receipt)[0])
        self.assertFalse(invoke(
            None, direct_receipt, unlink_error=FileNotFoundError("raced"),
        )[0])

        direct_with_predecessor = {
            **candidate,
            "activation_identity": activation_identity,
            "activation_predecessor": predecessor,
        }
        self.assertFalse(invoke(
            None, direct_with_predecessor, previous=other,
        )[0])
        restored, _unlink, _fsync, write = invoke(
            None, direct_with_predecessor, previous=predecessor,
        )
        self.assertTrue(restored)
        write.assert_called_once()

    def test_commit_pending_transaction_state_matrix(self):
        root = Path("/output")
        generation_identity = "1" * 64
        activation_identity = "4" * 64
        core = self.active_descriptor_core(digit="1")
        pending_identity = (7, 8)

        def invoke(pending_raw, current, *, path_matches=True):
            reads = iter(((pending_raw, pending_identity), (current, (1, 2))))
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_active_generation_lock", return_value=nullcontext(),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                side_effect=lambda *_args, **_kwargs: next(reads),
            ), patch.object(
                binary_output, "_require_generation_identity_publication_allowed",
            ) as require_allowed, patch.object(
                binary_output, "_active_descriptor_path_matches",
                return_value=path_matches,
            ), patch.object(
                Path, "unlink",
            ) as unlink, patch.object(
                binary_output, "_fsync_directory",
            ):
                result = binary_output.commit_pending_binary_generation(
                    root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                )
            return result, require_allowed, unlink

        for current_identity, activation in (
            ("short", activation_identity),
            (generation_identity, "short"),
        ):
            self.assertFalse(binary_output.commit_pending_binary_generation(
                root,
                expected_current_identity=current_identity,
                expected_activation_identity=activation,
            ))

        self.assertFalse(invoke(None, None)[0])
        self.assertFalse(invoke(None, {**core, "extra": True})[0])
        self.assertFalse(invoke(None, self.active_descriptor_core(digit="5"))[0])
        committed, require_allowed, _unlink = invoke(None, core)
        self.assertTrue(committed)
        require_allowed.assert_called_once_with(root, generation_identity)

        published = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": None,
            "activation_state": "published",
        }
        invalid_pending = (
            {"invalid": True},
            {**published, "activation_state": "pending"},
            {
                **published,
                "result_generation_identity": "9" * 64,
                "generation_directory": f"binary_generations/{'9' * 64}",
            },
            {**published, "activation_identity": "9" * 64},
        )
        for value in invalid_pending:
            self.assertFalse(invoke(value, core)[0])
        self.assertFalse(invoke(published, self.active_descriptor_core(digit="5"))[0])
        self.assertFalse(invoke(published, {**core, "extra": True})[0])
        with self.assertRaises(binary_output.BinaryOutputError):
            invoke(published, core, path_matches=False)
        committed, require_allowed, unlink = invoke(published, core)
        self.assertTrue(committed)
        require_allowed.assert_called_once_with(root, generation_identity)
        unlink.assert_called_once()

    def test_publish_pending_transaction_state_matrix(self):
        root = Path("/output")
        generation_identity = "1" * 64
        activation_identity = "4" * 64
        candidate = self.active_descriptor_core(digit="1")
        predecessor = self.active_descriptor_core(digit="5")
        other = self.active_descriptor_core(digit="6")
        pending_identity = (7, 8)
        active_identity = (1, 2)
        integrity_proof = binary_output._GenerationIntegrityProof(None, (), ())
        descriptor_proof = binary_output._TransactionDescriptorProof(None, (1, 2, 1, 3, 4, 5))

        def receipt(*, prior=None, state="pending", digit="1", activation=None):
            return {
                **self.active_descriptor_core(digit=digit),
                "activation_identity": (
                    activation_identity if activation is None else activation
                ),
                "activation_predecessor": prior,
                "activation_state": state,
            }

        def invoke(pending_raw, current, *, path_matches=True, guard=None):
            reads = iter(((pending_raw, pending_identity), (current, active_identity)))
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_active_generation_lock", return_value=nullcontext(),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                side_effect=lambda *_args, **_kwargs: next(reads),
            ), patch.object(
                binary_output, "_prepare_post_guard_stat_recheck", return_value=None,
            ), patch.object(
                binary_output, "_verify_pending_generation_integrity_with_proof",
                return_value=(None, integrity_proof),
            ), patch.object(
                binary_output, "_proof_supports_post_guard_stat_recheck",
                return_value=False,
            ), patch.object(
                binary_output, "_active_descriptor_path_matches",
                return_value=path_matches,
            ), patch.object(
                binary_output, "_stable_reprove_transaction_descriptor",
                return_value=descriptor_proof,
            ), patch.object(
                binary_output, "_run_publication_guard",
            ), patch.object(
                binary_output, "_assert_descriptor_reproof_unchanged",
            ), patch.object(
                binary_output, "_post_guard_generation_integrity_recheck",
            ), patch.object(
                binary_output, "_write_active_descriptor",
            ) as write:
                result = binary_output.publish_pending_binary_generation(
                    root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                    publication_guard=guard,
                )
            return result, write

        for current_identity, activation in (
            ("short", activation_identity),
            (generation_identity, "short"),
        ):
            self.assertFalse(binary_output.publish_pending_binary_generation(
                root,
                expected_current_identity=current_identity,
                expected_activation_identity=activation,
            ))
        with self.assertRaises(binary_output.BinaryOutputError):
            binary_output.publish_pending_binary_generation(
                root,
                expected_current_identity=generation_identity,
                expected_activation_identity=activation_identity,
                publication_guard=object(),
            )

        invalid_pending = (
            {"invalid": True},
            receipt(digit="9"),
            receipt(activation="9" * 64),
        )
        for value in invalid_pending:
            self.assertFalse(invoke(value, None)[0])

        pending = receipt()
        self.assertFalse(invoke(pending, {**candidate, "extra": True})[0])
        self.assertFalse(invoke(receipt(prior=predecessor), None)[0])
        self.assertFalse(invoke(
            receipt(prior=predecessor), {**predecessor, "extra": True},
        )[0])
        self.assertFalse(invoke(receipt(prior=predecessor), other)[0])

        with self.assertRaises(binary_output.BinaryOutputError):
            invoke(pending, None, path_matches=False)
        published, write = invoke(pending, None, guard=lambda: None)
        self.assertTrue(published)
        self.assertEqual(write.call_count, 2)
        self.assertEqual(write.call_args_list[-1].args[1]["activation_state"], "published")

        published, write = invoke(
            receipt(prior=predecessor), predecessor,
        )
        self.assertTrue(published)
        self.assertEqual(write.call_count, 2)

        published, write = invoke(receipt(state="published"), candidate)
        self.assertTrue(published)
        write.assert_not_called()

        published, write = invoke(pending, candidate)
        self.assertTrue(published)
        write.assert_called_once()
        self.assertEqual(write.call_args.args[1]["activation_state"], "published")

    def test_seal_active_transaction_state_and_fast_path_matrix(self):
        root = Path("/output")
        generation_identity = "1" * 64
        activation_identity = "4" * 64
        core = self.active_descriptor_core(digit="1")
        predecessor = self.active_descriptor_core(digit="5")
        descriptor_identity = (1, 2)
        root_snapshot = (1, 10, 1, 3, 4, 5)
        proof = binary_output._GenerationIntegrityProof(
            None, ((root, root_snapshot),), (),
        )
        descriptor_proof = binary_output._TransactionDescriptorProof(
            None, root_snapshot,
        )

        def invoke(current, *, fast=(False, None, None), guard=None):
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_active_generation_lock", return_value=nullcontext(),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                return_value=(current, descriptor_identity),
            ), patch.object(
                binary_output, "_consume_direct_seal_capability", return_value=None,
            ), patch.object(
                binary_output, "_direct_seal_fast_publication_authority",
                return_value=fast,
            ), patch.object(
                binary_output, "_prepare_post_guard_stat_recheck", return_value=1,
            ), patch.object(
                binary_output, "_verify_pending_generation_integrity_with_proof",
                return_value=(None, proof),
            ), patch.object(
                binary_output, "_proof_supports_post_guard_stat_recheck",
                return_value=False,
            ), patch.object(
                binary_output, "_stable_reprove_transaction_descriptor",
                return_value=descriptor_proof,
            ), patch.object(
                binary_output, "_run_publication_guard",
            ), patch.object(
                binary_output, "_assert_descriptor_reproof_unchanged",
            ), patch.object(
                binary_output, "_post_guard_generation_integrity_recheck",
            ), patch.object(
                binary_output, "_write_active_descriptor",
            ) as write, patch.object(
                binary_output, "_verify_pending_generation_integrity",
            ) as verify:
                result = binary_output.seal_active_binary_generation(
                    root,
                    expected_current_identity=generation_identity,
                    expected_activation_identity=activation_identity,
                    publication_guard=guard,
                )
            return result, write, verify

        for current_identity, activation in (
            ("short", activation_identity),
            (generation_identity, "short"),
        ):
            self.assertFalse(binary_output.seal_active_binary_generation(
                root,
                expected_current_identity=current_identity,
                expected_activation_identity=activation,
            ))
        with self.assertRaises(binary_output.BinaryOutputError):
            binary_output.seal_active_binary_generation(
                root,
                expected_current_identity=generation_identity,
                expected_activation_identity=activation_identity,
                publication_guard=object(),
            )

        self.assertFalse(invoke({"invalid": True})[0])
        self.assertFalse(invoke(self.active_descriptor_core(digit="5"))[0])

        exact_without_predecessor = {
            **core, "activation_identity": activation_identity,
        }
        self.assertFalse(invoke(exact_without_predecessor)[0])
        exact_invalid_predecessor = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": {"invalid": True},
        }
        self.assertFalse(invoke(exact_invalid_predecessor)[0])
        exact = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": None,
        }
        sealed, write, _verify = invoke(exact, guard=lambda: None)
        self.assertTrue(sealed)
        write.assert_called_once_with(
            root, core, expected_file_identity=descriptor_identity,
        )

        sealed, write, _verify = invoke(exact, fast=(True, None, None))
        self.assertTrue(sealed)
        write.assert_called_once()
        sealed, write, _verify = invoke(exact, fast=(True, None, proof))
        self.assertTrue(sealed)
        write.assert_called_once()
        exact_with_predecessor = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": predecessor,
        }
        self.assertTrue(invoke(exact_with_predecessor)[0])

        sealed, _write, verify = invoke(core)
        self.assertTrue(sealed)
        verify.assert_called_once_with(root, core)
        self.assertFalse(invoke({**core, "activation_predecessor": None})[0])
        self.assertFalse(invoke({
            **core,
            "activation_identity": "9" * 64,
            "activation_predecessor": None,
        })[0])
        self.assertFalse(invoke({
            **core,
            "activation_identity": "9" * 64,
        })[0])
        self.assertFalse(invoke({
            **core,
            "activation_identity": "9" * 64,
            "activation_predecessor": predecessor,
        })[0])
        newer = {
            **core,
            "activation_identity": "9" * 64,
            "activation_predecessor": core,
        }
        sealed, _write, verify = invoke(newer)
        self.assertTrue(sealed)
        verify.assert_called_once_with(root, newer)

    def test_release_recapture_cleanup_capability_and_state_matrix(self):
        root = Path("/output")
        generation_identity = "1" * 64
        activation_identity = "4" * 64
        core = self.active_descriptor_core(digit="1")
        predecessor = self.active_descriptor_core(digit="5")
        other = self.active_descriptor_core(digit="6")
        authority = {
            "authority_mode": binary_output._RELEASE_RECAPTURE_AUTHORITY_MODE,
        }

        def call_with_context(context, **options):
            token = binary_output._RELEASE_RECAPTURE_PUBLICATION_CONTEXT.set(context)
            try:
                return invoke(**options)
            finally:
                binary_output._RELEASE_RECAPTURE_PUBLICATION_CONTEXT.reset(token)

        def invoke(
            *, current=core, pending=None, previous=None, remaining=None,
            selected_authority=authority, path_matches=True,
            current_identity=generation_identity,
            activation=activation_identity,
            authority_error=None,
        ):
            reads = iter(((pending, (7, 8)), (current, (1, 2)), (remaining, (9, 10))))
            with patch.object(
                binary_output, "_canonical_physical_output_root", return_value=root,
            ), patch.object(
                binary_output, "_require_generation_identity_publication_allowed",
                side_effect=authority_error,
                return_value=selected_authority,
            ), patch.object(
                binary_output, "_active_generation_lock", return_value=nullcontext(),
            ), patch.object(
                binary_output, "_read_active_descriptor",
                side_effect=lambda *_args, **_kwargs: next(reads),
            ), patch.object(
                binary_output, "_active_descriptor_path_matches",
                return_value=path_matches,
            ), patch.object(
                Path, "unlink",
            ) as unlink, patch.object(
                binary_output, "_fsync_directory",
            ) as fsync, patch.object(
                binary_output, "_write_active_descriptor",
            ) as write:
                result = binary_output._discard_release_recapture_activation(
                    root,
                    expected_current_identity=current_identity,
                    expected_activation_identity=activation,
                    previous_active=previous,
                )
            return result, unlink, fsync, write

        valid_context = (
            binary_output._RELEASE_RECAPTURE_PUBLICATION_CAPABILITY,
            root,
        )
        invalid_contexts = (
            None,
            (binary_output._RELEASE_RECAPTURE_PUBLICATION_CAPABILITY,),
            (object(), root),
            (binary_output._RELEASE_RECAPTURE_PUBLICATION_CAPABILITY, Path("/other")),
        )
        for context in invalid_contexts:
            with self.subTest(context=context), self.assertRaises(
                binary_output.BinaryOutputError,
            ) as caught:
                call_with_context(context)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_RELEASE_RECAPTURE_CLEANUP_FORBIDDEN",
            )

        for current_identity, activation in (
            ("short", activation_identity),
            (generation_identity, "short"),
        ):
            self.assertFalse(call_with_context(
                valid_context,
                current_identity=current_identity,
                activation=activation,
            )[0])

        with self.assertRaises(binary_output.BinaryOutputError) as caught:
            call_with_context(
                valid_context,
                authority_error=binary_output.BinaryOutputError(
                    "MANIFEST_INVALID", "broken",
                ),
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_RELEASE_RECAPTURE_CLEANUP_FAILED",
        )
        for invalid_authority in (
            None,
            {"authority_mode": "release_evidence"},
        ):
            with self.assertRaises(binary_output.BinaryOutputError):
                call_with_context(
                    valid_context, selected_authority=invalid_authority,
                )
        self.assertFalse(call_with_context(
            valid_context, previous={"invalid": True},
        )[0])
        self.assertFalse(call_with_context(
            valid_context, pending={"pending": True},
        )[0])
        self.assertFalse(call_with_context(valid_context, current=None)[0])
        self.assertFalse(call_with_context(valid_context, current=other)[0])

        self.assertFalse(call_with_context(
            valid_context, path_matches=False,
        )[0])
        discarded, unlink, fsync, write = call_with_context(valid_context)
        self.assertTrue(discarded)
        unlink.assert_called_once()
        fsync.assert_called_once()
        write.assert_not_called()
        self.assertFalse(call_with_context(
            valid_context, remaining=other,
        )[0])

        discarded, _unlink, _fsync, write = call_with_context(
            valid_context,
            previous=predecessor,
            remaining=predecessor,
        )
        self.assertTrue(discarded)
        write.assert_called_once()

        invalid_receipts = (
            {**core, "activation_identity": "9" * 64,
             "activation_predecessor": None},
            {**core, "activation_identity": activation_identity},
            {**core, "activation_identity": activation_identity,
             "activation_predecessor": {"invalid": True}},
            {**core, "activation_identity": activation_identity,
             "activation_predecessor": predecessor},
        )
        for current in invalid_receipts:
            self.assertFalse(call_with_context(valid_context, current=current)[0])

        receipt = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": predecessor,
        }
        discarded, _unlink, _fsync, write = call_with_context(
            valid_context,
            current=receipt,
            previous=predecessor,
            remaining=predecessor,
        )
        self.assertTrue(discarded)
        write.assert_called_once()

        receipt_without_predecessor = {
            **core,
            "activation_identity": activation_identity,
            "activation_predecessor": None,
        }
        self.assertTrue(call_with_context(
            valid_context, current=receipt_without_predecessor,
        )[0])

    def test_generation_writer_sidecar_collision_copy_and_race_matrix(self):
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        profile = fixture.profile()
        invalid_sidecars = (
            {None: b"value"},
            {"../escape.json": b"value"},
            {"binary_summary.json": b"value"},
            {"extra.json": object()},
            {"extra.json": Path("/definitely/missing/sidecar.json")},
        )
        for sidecars in invalid_sidecars:
            with self.subTest(sidecars=sidecars), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.write_binary_generation(
                        temporary, decisions, traces, profile,
                        policy_identities={"registry": "writer-boundary"},
                        additional_sidecars=sidecars,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_OUTPUT_ADDITIONAL_SIDECAR_INVALID",
                )

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.bin"
            source.write_bytes(b"source-path")
            manifest = binary_output.write_binary_generation(
                Path(temporary) / "output", decisions, traces, profile,
                policy_identities={"registry": "valid-additional"},
                additional_sidecars={
                    "bytes.bin": b"source-bytes",
                    "path.bin": source,
                },
            )
            self.assertIn("bytes.bin", manifest["sidecar_content_identities"])
            self.assertIn("path.bin", manifest["sidecar_content_identities"])

        real_copyfile = binary_output.shutil.copyfile

        def corrupt_copy(source, destination, *args, **kwargs):
            result = real_copyfile(source, destination, *args, **kwargs)
            Path(destination).write_bytes(Path(destination).read_bytes() + b"tampered")
            return result

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_output.shutil, "copyfile", side_effect=corrupt_copy,
        ):
            with self.assertRaises(binary_output.BinaryOutputError) as caught:
                binary_output.write_binary_generation(
                    temporary, decisions, traces, profile,
                    policy_identities={"registry": "copy-race"},
                )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_OUTPUT_SIDECAR_CHANGED_DURING_COPY",
        )

        real_replace = os.replace

        def generation_replace_failure(error_number, *, publish_first=False):
            def replace_routed(source, destination):
                target = Path(destination)
                if (
                    target.parent.name == "binary_generations"
                    and len(target.name) == 64
                ):
                    if publish_first:
                        real_replace(source, destination)
                    raise OSError(error_number, "injected generation rename race")
                return real_replace(source, destination)
            return replace_routed

        for error_number in (getattr(os, "EACCES", 13),):
            with tempfile.TemporaryDirectory() as temporary, patch.object(
                binary_output.os, "replace",
                side_effect=generation_replace_failure(error_number),
            ), self.assertRaises(OSError):
                binary_output.write_binary_generation(
                    temporary, decisions, traces, profile,
                    policy_identities={"registry": "rename-error"},
                )
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_output.os, "replace",
            side_effect=generation_replace_failure(binary_output.errno.EEXIST),
        ), self.assertRaises(OSError):
            binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "invalid-race"},
            )
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_output.os, "replace",
            side_effect=generation_replace_failure(
                binary_output.errno.EEXIST, publish_first=True,
            ),
        ):
            manifest = binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "valid-race"},
            )
            self.assertTrue(Path(manifest["generation_directory"]).is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            first = binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "valid-existing"},
            )
            second = binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "valid-existing"},
            )
            self.assertEqual(
                first["result_generation_identity"],
                second["result_generation_identity"],
            )

        real_make_short_temp_dir = binary_output.make_short_temp_dir
        staging_holder = {}

        def capture_staging(*args, **kwargs):
            result = real_make_short_temp_dir(*args, **kwargs)
            if kwargs.get("prefix") == "binary-output-sidecars":
                staging_holder["path"] = result
            return result

        def remove_staging_at_root_barrier(path):
            staging = staging_holder.get("path")
            if Path(path).name != "binary-generations" and staging is not None:
                binary_output.shutil.rmtree(staging, ignore_errors=True)
            return True

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_output, "make_short_temp_dir", side_effect=capture_staging,
        ), patch.object(
            binary_output, "_fsync_directory",
            side_effect=remove_staging_at_root_barrier,
        ):
            manifest = binary_output.write_binary_generation(
                temporary, decisions, traces, profile,
                policy_identities={"registry": "staging-raced-away"},
            )
            self.assertTrue(Path(manifest["generation_directory"]).is_dir())

        corruption_modes = (
            "manifest_list",
            "attachment_regular",
            "broken_attachment",
            "missing_sidecar",
            "transient_regular",
            "transient_broken",
        )
        for mode in corruption_modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                manifest = binary_output.write_binary_generation(
                    temporary, decisions, traces, profile,
                    policy_identities={"registry": "existing-corruption"},
                )
                generation = Path(manifest["generation_directory"])
                if mode == "manifest_list":
                    (generation / "result_generation.json").write_bytes(
                        binary_output._json_bytes([]),
                    )
                elif mode == "attachment_regular":
                    (generation / "generation_attachments.json").write_bytes(
                        b"obsolete",
                    )
                elif mode == "broken_attachment":
                    try:
                        (generation / "generation_attachments.json").symlink_to(
                            generation / "missing-attachment"
                        )
                    except OSError as error:
                        self.skipTest(f"symlinks unavailable: {error}")
                elif mode == "missing_sidecar":
                    (generation / "binary_summary.json").unlink()
                else:
                    transient = generation / next(iter(
                        binary_output._TRANSIENT_FACT_STORE_SIDECARS
                    ))
                    if mode == "transient_regular":
                        transient.write_bytes(b"transient")
                    else:
                        try:
                            transient.symlink_to(generation / "missing-transient")
                        except OSError as error:
                            self.skipTest(f"symlinks unavailable: {error}")
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.write_binary_generation(
                        temporary, decisions, traces, profile,
                        policy_identities={"registry": "existing-corruption"},
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_IDENTITY_COLLISION",
                )

    def test_activation_publication_mode_and_transaction_state_matrix(self):
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        profile = fixture.profile()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = binary_output.write_binary_generation(
                root, decisions, traces, profile,
                policy_identities={"registry": "activation-state"},
            )
            validation = fixture.validation_result(manifest)
            validation_bytes = Path(validation["validation_result_path"]).read_bytes()
            active = {
                "schema": binary_output._ACTIVE_DESCRIPTOR_SCHEMA,
                "result_generation_identity": manifest["result_generation_identity"],
                "generation_directory": (
                    f"binary_generations/{manifest['result_generation_identity']}"
                ),
                "validation_run_identity": validation["validation_run_identity"],
                "validation_result_sha256": binary_output.hashlib.sha256(
                    validation_bytes
                ).hexdigest(),
            }
            activation_identity = "4" * 64
            predecessor = self.active_descriptor_core(digit="5")
            proof = binary_output._GenerationIntegrityProof(None, (), ())
            descriptor_proof = binary_output._TransactionDescriptorProof(
                None, (1, 2, 1, 3, 4, 5),
            )
            default_verified = object()

            def invoke(
                *, current=None, pending_raw=None, defer=False, dry_run=False,
                authority=None, verified=default_verified, activation=activation_identity,
                record=None, guard=None, selected_validation=validation,
            ):
                verified_authority = authority if verified is default_verified else verified
                reads = iter(((current, (1, 2)), (pending_raw, (7, 8))))
                with patch.object(
                    binary_output, "_generation_publication_authority",
                    return_value=authority,
                ), patch.object(
                    binary_output, "_require_generation_publication_allowed",
                ) as require_allowed, patch.object(
                    binary_output, "_make_generation_durable",
                ), patch.object(
                    binary_output, "_fsync_directory",
                ), patch.object(
                    binary_output, "_active_generation_lock",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_output, "_read_active_descriptor",
                    side_effect=lambda *_args, **_kwargs: next(reads),
                ), patch.object(
                    binary_output, "_active_descriptor_destination",
                    return_value=(
                        root
                        / binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                ), patch.object(
                    binary_output, "_prepare_post_guard_stat_recheck",
                    return_value=None,
                ), patch.object(
                    binary_output, "_verify_pending_generation_integrity_with_proof",
                    return_value=(verified_authority, proof),
                ), patch.object(
                    binary_output, "_verify_candidate_generation_integrity_with_proof",
                    return_value=(verified_authority, proof),
                ), patch.object(
                    binary_output, "_proof_supports_post_guard_stat_recheck",
                    return_value=False,
                ), patch.object(
                    binary_output, "_stable_reprove_transaction_descriptor",
                    return_value=descriptor_proof,
                ), patch.object(
                    binary_output, "_run_publication_guard",
                ), patch.object(
                    binary_output, "_assert_descriptor_reproof_unchanged",
                ), patch.object(
                    binary_output, "_post_guard_generation_integrity_recheck",
                ), patch.object(
                    binary_output, "_write_active_descriptor",
                ) as write, patch.object(
                    binary_output, "_try_install_direct_seal_capability",
                ) as install:
                    result = binary_output.activate_binary_generation(
                        root,
                        manifest,
                        validation_result=selected_validation,
                        activation_identity=activation,
                        activation_record=record,
                        defer_publication=defer,
                        publication_guard=guard,
                        publication_dry_run=dry_run,
                    )
                return result, write, install, require_allowed

            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(guard=object())
            with self.assertRaises(binary_output.BinaryOutputError) as caught:
                invoke(activation="short")
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_ACTIVATION_IDENTITY_INVALID",
            )
            generated_path, write, install, _require = invoke(activation="")
            self.assertEqual(generated_path, str(root / "active_binary_generation.json"))
            write.assert_called_once()
            install.assert_called_once()

            invalid_dry_run_authorities = (
                None,
                {
                    "authority_mode": "release_evidence",
                    "public_activation_allowed": False,
                },
                {
                    "authority_mode": "candidate_source_measurement",
                    "public_activation_allowed": True,
                },
            )
            for authority in invalid_dry_run_authorities:
                with self.subTest(dry_authority=authority), self.assertRaises(
                    binary_output.BinaryOutputError,
                ):
                    invoke(dry_run=True, authority=authority)
            candidate = {
                "authority_mode": "candidate_source_measurement",
                "public_activation_allowed": False,
            }
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    dry_run=True, authority=candidate,
                    verified={**candidate, "changed": True},
                )
            dry_record = {"stale": True}
            result, write, install, _require = invoke(
                dry_run=True,
                authority=candidate,
                record=dry_record,
                guard=lambda: None,
            )
            self.assertEqual(result, "")
            write.assert_not_called()
            install.assert_not_called()
            self.assertTrue(dry_record["activation_integrity_dry_run"])
            self.assertEqual(
                invoke(dry_run=True, authority=candidate)[0],
                "",
            )

            release_authority = {"authority_mode": "release_evidence"}
            _result, _write, _install, require_allowed = invoke(
                authority=release_authority,
            )
            require_allowed.assert_called_once()

            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    defer=True,
                    current={**predecessor, "extra": True},
                )
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(defer=True, pending_raw={"invalid": True})
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    defer=True,
                    authority=None,
                    verified={"authority_mode": "appeared"},
                )
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    defer=True,
                    authority=release_authority,
                    verified={"authority_mode": "changed"},
                )
            deferred_record = {"stale": True}
            deferred_path, write, install, _require = invoke(
                defer=True,
                authority=release_authority,
                record=deferred_record,
            )
            self.assertEqual(
                deferred_path,
                str(root / binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH),
            )
            write.assert_called_once()
            install.assert_not_called()
            self.assertTrue(deferred_record["activation_candidate_private"])
            deferred_path, write, _install, _require = invoke(
                defer=True,
                current=predecessor,
            )
            self.assertTrue(deferred_path.endswith("pending_active_binary_generation.json"))
            write.assert_called_once()

            expected_pending = {
                **active,
                "activation_identity": activation_identity,
                "activation_predecessor": None,
                "activation_state": "pending",
            }
            deferred_path, write, _install, _require = invoke(
                defer=True, pending_raw=expected_pending,
            )
            self.assertTrue(deferred_path.endswith("pending_active_binary_generation.json"))
            write.assert_not_called()
            validation_without_declared_path = dict(validation)
            validation_without_declared_path.pop("validation_result_path")
            self.assertEqual(
                invoke(selected_validation=validation_without_declared_path)[0],
                str(root / "active_binary_generation.json"),
            )

            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(pending_raw=expected_pending)
            invalid_currents = (
                {"invalid": True},
                {
                    **predecessor,
                    "activation_identity": activation_identity,
                    "activation_predecessor": None,
                },
                {**active, "activation_identity": activation_identity},
                {
                    **active,
                    "activation_identity": activation_identity,
                    "activation_predecessor": {"invalid": True},
                },
            )
            for current in invalid_currents:
                with self.subTest(current=current), self.assertRaises(
                    binary_output.BinaryOutputError,
                ):
                    invoke(current=current)
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    authority=None,
                    verified={"authority_mode": "appeared"},
                )
            with self.assertRaises(binary_output.BinaryOutputError):
                invoke(
                    authority=release_authority,
                    verified={"authority_mode": "changed"},
                )

            direct_record = {"stale": True}
            direct_path, write, install, _require = invoke(
                current=predecessor,
                authority=release_authority,
                record=direct_record,
                guard=lambda: None,
            )
            self.assertEqual(direct_path, str(root / "active_binary_generation.json"))
            write.assert_called_once()
            install.assert_called_once()
            self.assertEqual(direct_record["activation_predecessor"], predecessor)

            existing_receipt = {
                **active,
                "activation_identity": activation_identity,
                "activation_predecessor": None,
            }
            direct_path, write, install, _require = invoke(
                current=existing_receipt,
            )
            self.assertEqual(direct_path, str(root / "active_binary_generation.json"))
            write.assert_not_called()
            install.assert_not_called()
            existing_with_predecessor = {
                **active,
                "activation_identity": activation_identity,
                "activation_predecessor": predecessor,
            }
            self.assertEqual(
                invoke(current=existing_with_predecessor)[0],
                str(root / "active_binary_generation.json"),
            )

    def test_activation_filesystem_manifest_and_validation_boundary_matrix(self):
        fixture = binary_output_fixtures.BinaryOutputTest()
        decisions, traces = fixture.bundles()
        profile = fixture.profile()
        sequence = iter(range(1000))

        def prepare(temporary):
            root = Path(temporary).resolve()
            manifest = binary_output.write_binary_generation(
                root, decisions, traces, profile,
                policy_identities={"registry": f"activation-boundary-{next(sequence)}"},
            )
            validation = fixture.validation_result(manifest)
            return root, manifest, validation

        for invalid_identity in (None, "short"):
            with self.subTest(identity=invalid_identity), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.activate_binary_generation(
                        root,
                        {"result_generation_identity": invalid_identity},
                        validation_result={},
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_ACTIVATION_TARGET_INVALID",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root, manifest, validation = prepare(temporary)
            generation = Path(manifest["generation_directory"])
            generations = generation.parent
            real_resolve = Path.resolve
            for target in (generations, generation):
                def mismatched_resolve(path, strict=False, *, selected=target):
                    if path == selected:
                        return selected.parent / f"different-{selected.name}"
                    return real_resolve(path, strict=strict)

                with self.subTest(path=target), patch.object(
                    Path, "resolve", new=mismatched_resolve,
                ), self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, manifest, validation_result=validation,
                    )

            real_is_dir = Path.is_dir

            def generation_not_directory(path):
                if path == generation:
                    return False
                return real_is_dir(path)

            with patch.object(
                Path, "is_dir", new=generation_not_directory,
            ), self.assertRaises(binary_output.BinaryOutputError):
                binary_output.activate_binary_generation(
                    root, manifest, validation_result=validation,
                )

        for invalid_validation in (None, []):
            with self.subTest(validation=invalid_validation), tempfile.TemporaryDirectory() as temporary:
                root, manifest, _validation = prepare(temporary)
                with self.assertRaises(binary_output.BinaryOutputError) as caught:
                    binary_output.activate_binary_generation(
                        root, manifest, validation_result=invalid_validation,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_GENERATION_VALIDATION_REQUIRED",
                )

        manifest_modes = (
            "reported_symlink",
            "missing",
            "json_list",
            "schema_mismatch",
            "attachment_mismatch",
            "sidecars_not_mapping",
            "identity_recomputed_mismatch",
        )
        for mode in manifest_modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root, manifest, validation = prepare(temporary)
                manifest_path = Path(manifest["generation_directory"]) / "result_generation.json"
                selected_manifest = dict(manifest)
                real_is_symlink = Path.is_symlink

                def manifest_is_symlink(path):
                    if path == manifest_path:
                        return True
                    return real_is_symlink(path)

                symlink_patch = (
                    patch.object(Path, "is_symlink", new=manifest_is_symlink)
                    if mode == "reported_symlink" else nullcontext()
                )
                if mode == "missing":
                    manifest_path.unlink()
                elif mode == "json_list":
                    manifest_path.write_bytes(binary_output._json_bytes([]))
                elif mode in {"schema_mismatch", "attachment_mismatch"}:
                    persisted = dict(manifest)
                    field = "schema" if mode == "schema_mismatch" else "attachment_policy"
                    persisted[field] = "changed"
                    manifest_path.write_bytes(binary_output._json_bytes(persisted))
                elif mode == "sidecars_not_mapping":
                    selected_manifest["sidecar_content_identities"] = []
                    persisted = dict(selected_manifest)
                    persisted.pop("generation_directory", None)
                    persisted.pop("active_generation_descriptor", None)
                    manifest_path.write_bytes(binary_output._json_bytes(persisted))
                elif mode == "identity_recomputed_mismatch":
                    selected_manifest["policy_identities"] = {"changed": "policy"}
                    persisted = dict(selected_manifest)
                    persisted.pop("generation_directory", None)
                    persisted.pop("active_generation_descriptor", None)
                    manifest_path.write_bytes(binary_output._json_bytes(persisted))
                with symlink_patch, self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, selected_manifest, validation_result=validation,
                    )

        forbidden_modes = (
            "transient_regular",
            "transient_reported_symlink",
            "attachment_regular",
            "attachment_reported_symlink",
        )
        for mode in forbidden_modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root, manifest, validation = prepare(temporary)
                generation = Path(manifest["generation_directory"])
                if mode.startswith("transient"):
                    target = generation / next(iter(
                        binary_output._TRANSIENT_FACT_STORE_SIDECARS
                    ))
                else:
                    target = generation / "generation_attachments.json"
                if mode.endswith("regular"):
                    target.write_bytes(b"forbidden")
                    context = nullcontext()
                else:
                    real_exists = Path.exists
                    real_is_symlink = Path.is_symlink

                    def routed_exists(path):
                        return False if path == target else real_exists(path)

                    def routed_is_symlink(path):
                        return True if path == target else real_is_symlink(path)

                    class CombinedPatches:
                        def __enter__(self):
                            self.exists = patch.object(
                                Path, "exists", new=routed_exists,
                            )
                            self.symlink = patch.object(
                                Path, "is_symlink", new=routed_is_symlink,
                            )
                            self.exists.__enter__()
                            self.symlink.__enter__()

                        def __exit__(self, *exc):
                            self.symlink.__exit__(*exc)
                            return self.exists.__exit__(*exc)

                    context = CombinedPatches()
                with context, self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, manifest, validation_result=validation,
                    )

        for name, expected in (("../escape", "e" * 64), ("extra.json", "short")):
            with self.subTest(sidecar=name), tempfile.TemporaryDirectory() as temporary:
                root, manifest, validation = prepare(temporary)
                selected_manifest = dict(manifest)
                selected_manifest["sidecar_content_identities"] = {
                    **manifest["sidecar_content_identities"], name: expected,
                }
                manifest_path = Path(manifest["generation_directory"]) / "result_generation.json"
                persisted = dict(selected_manifest)
                persisted.pop("generation_directory", None)
                persisted.pop("active_generation_descriptor", None)
                manifest_path.write_bytes(binary_output._json_bytes(persisted))
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, selected_manifest, validation_result=validation,
                    )

        stat_modes = (
            None,
            self.stat_result(mode=stat.S_IFLNK | 0o777),
            self.stat_result(mode=stat.S_IFDIR | 0o700),
            self.stat_result(links=2),
        )
        for observed in stat_modes:
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as temporary:
                root, manifest, validation = prepare(temporary)
                target = (
                    Path(manifest["generation_directory"])
                    / "binary_summary.json"
                )
                real_lstat = os.lstat

                def routed_lstat(path):
                    if Path(path) == target:
                        if observed is None:
                            raise FileNotFoundError(str(path))
                        return observed
                    return real_lstat(path)

                with patch.object(
                    binary_output.os, "lstat", side_effect=routed_lstat,
                ), self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, manifest, validation_result=validation,
                    )

        validation_modes = (
            "incomplete_input",
            "directory_resolve_mismatch",
            "path_resolve_mismatch",
            "reported_symlink",
            "reported_missing",
            "declared_missing",
            "declared_other",
            "persisted_json_list",
            "persisted_incomplete",
            "persisted_noncanonical",
        )
        for mode in validation_modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root, manifest, validation = prepare(temporary)
                selected_validation = dict(validation)
                validation_path = Path(validation["validation_result_path"])
                validation_directory = validation_path.parent
                real_resolve = Path.resolve
                real_is_symlink = Path.is_symlink
                real_is_file = Path.is_file

                def routed_resolve(path, strict=False):
                    if mode == "directory_resolve_mismatch" and path == validation_directory:
                        return validation_directory.parent / "different-validation"
                    if mode == "path_resolve_mismatch" and path == validation_path:
                        return validation_path.parent / "different-result.json"
                    if mode == "reported_missing" and path == validation_path:
                        return validation_path
                    return real_resolve(path, strict=strict)

                def routed_is_symlink(path):
                    if mode == "reported_symlink" and path == validation_path:
                        return True
                    return real_is_symlink(path)

                def routed_is_file(path):
                    if mode == "reported_missing" and path == validation_path:
                        return False
                    return real_is_file(path)

                if mode == "incomplete_input":
                    selected_validation["status"] = "failed"
                elif mode == "declared_missing":
                    selected_validation["validation_result_path"] = str(
                        root / "missing-validation.json"
                    )
                elif mode == "declared_other":
                    other = root / "other-validation.json"
                    other.write_bytes(b"{}")
                    selected_validation["validation_result_path"] = str(other)
                elif mode == "persisted_json_list":
                    validation_path.write_bytes(binary_output._json_bytes([]))
                elif mode == "persisted_incomplete":
                    persisted = {
                        key: value
                        for key, value in validation.items()
                        if key != "validation_result_path"
                    }
                    persisted["status"] = "failed"
                    validation_path.write_bytes(binary_output._json_bytes(persisted))
                elif mode == "persisted_noncanonical":
                    validation_path.write_bytes(
                        validation_path.read_bytes() + b" ",
                    )
                with patch.object(
                    Path, "resolve", new=routed_resolve,
                ), patch.object(
                    Path, "is_symlink", new=routed_is_symlink,
                ), patch.object(
                    Path, "is_file", new=routed_is_file,
                ), self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        root, manifest, validation_result=selected_validation,
                    )

    def test_reported_identity_accepts_absent_scope_without_inventing_values(self):
        identity = binary_output._reported_api_identity(
            {"fact_kind": "class"},
            runtime_profile_identity="runtime",
            analysis_context_identity="context",
        )
        self.assertRegex(identity, r"^[0-9a-f]{64}$")

    def test_aggregate_rejects_trace_without_authoritative_decision(self):
        profile, decisions, traces = self.fixture_bundles()
        unbound = dict(traces.formal_results[0])
        unbound["change_fact_identity"] = "missing-change"
        with self.assertRaises(binary_output.BinaryOutputError) as caught:
            binary_output._aggregate_by_api(
                decisions,
                replace(traces, formal_results=(unbound,)),
                profile,
            )
        self.assertEqual(caught.exception.reason_code, "BINARY_OUTPUT_TRACE_DECISION_UNBOUND")

    def test_aggregate_preserves_rich_paths_priorities_and_dependency_lineage(self):
        profile, base_decisions, base_traces = self.fixture_bundles()
        base_decision = dict(base_decisions.authoritative_decisions[0])
        base_assessment = dict(base_decisions.projection_assessments[0])
        base_result = dict(base_traces.formal_results[0])

        decisions = []
        assessments = [{
            **base_assessment,
            "projection_assessment_identity": "assessment-unrelated",
        }]
        results = []
        for index, status in enumerate(("reachable", "uncertain", "reachable")):
            change = f"change-{index}"
            assessment = f"assessment-{index}"
            projection = f"projection-{index}"
            decision = {
                **base_decision,
                "change_fact_identity": change,
                "fact_scope": dict(base_decision["fact_scope"]),
                "dependency_artifacts": [],
            }
            if index == 0:
                decision["dependency_artifacts"] = [
                    {
                        "side": "base",
                        "artifact_instance_identity": "artifact-base",
                        "logical_dependency_lineage": "demo:api",
                        "coord": "demo:api:1.0",
                    },
                    {
                        "side": "current",
                        "artifact_instance_identity": "artifact-current",
                        "logical_dependency_lineage": "demo:api",
                        "coord": "demo:api:2.0",
                    },
                    {
                        "side": "",
                        "artifact_instance_identity": "",
                        "logical_dependency_lineage": "",
                        "coord": "",
                    },
                ]
            elif index == 1:
                decision["dependency_artifacts"] = [{
                    "side": "base",
                    "artifact_instance_identity": "artifact-base",
                    "logical_dependency_lineage": "demo:api",
                    "coord": "demo:api:1.0",
                }]
            decisions.append(decision)
            assessments.append({
                **base_assessment,
                "projection_assessment_identity": assessment,
                "change_fact_identity": change,
            })
            result = {
                **base_result,
                "projection_identity": projection,
                "projection_assessment_identity": assessment,
                "change_fact_identity": change,
                "reachability_status": status,
                "is_reachable": status == "reachable",
                "impact_conclusion": "probable_impact" if index == 0 else "inconclusive",
                "static_linkage_status": (
                    "incompatible_if_executed" if index == 0
                    else "compatible_or_not_applicable" if index == 2
                    else "undetermined"
                ),
                "path_set_complete": index != 1,
                "exact_path_exists": index == 0,
                "possible_path_exists": index == 1,
                "paths": [],
            }
            results.append(result)

        rich_path = {
            "path_identity": "path-rich",
            "path_certainty": "exact",
            "edges": [
                {
                    "caller_class_name": "app/Entry",
                    "caller_member_name": "main",
                    "caller_descriptor": "([Ljava/lang/String;)V",
                    "edge_kind": "invokedynamic_handle_static",
                },
                {
                    "caller_class_name": "app/Entry",
                    "caller_member_name": "main",
                    "caller_descriptor": "([Ljava/lang/String;)V",
                    "edge_kind": "invokedynamic_handle_virtual",
                },
                {
                    "caller_class_name": "app/Fields",
                    "caller_member_name": "VALUE",
                    "caller_descriptor": "I",
                    "edge_kind": "ldc_bootstrap_handle_field",
                },
                {
                    "caller_class_name": "",
                    "caller_member_name": "",
                    "caller_descriptor": "",
                    "edge_kind": "",
                },
                {
                    "caller_class_name": "app/OwnerOnly",
                    "caller_member_name": "",
                    "caller_descriptor": "",
                    "edge_kind": "getstatic",
                },
                {
                    "caller_class_name": "vendor/Api",
                    "caller_member_name": "work",
                    "caller_descriptor": "()V",
                    "edge_kind": "invokevirtual",
                },
            ],
            "entrypoint_records": [
                {
                    "entry_kind": "java_main",
                    "dependency_coord": "demo:app:1.0",
                    "activation_reason": "main method",
                },
                {"entry_kind": "custom", "dependency_coord": "", "activation_reason": ""},
                {"entry_kind": "", "dependency_coord": "", "activation_reason": ""},
            ],
        }
        results[0]["paths"] = [
            rich_path,
            dict(rich_path),
            {
                "path_identity": "path-empty",
                "path_certainty": "",
                "edges": [],
                "entrypoint_records": [],
            },
            {
                "path_identity": "path-different-tail",
                "path_certainty": "possible",
                "edges": [{
                    "caller_class_name": "app/AnotherEntry",
                    "caller_member_name": "start",
                    "caller_descriptor": "()V",
                    "edge_kind": "invokestatic",
                }],
                "entrypoint_records": [],
            },
        ]

        decision_bundle = replace(
            base_decisions,
            authoritative_decisions=tuple(decisions),
            projection_assessments=tuple(assessments),
        )
        trace_bundle = replace(base_traces, formal_results=tuple(results))
        row = binary_output._aggregate_by_api(
            decision_bundle, trace_bundle, profile,
        )[0]

        self.assertEqual(row["reachability_status"], "reachable")
        self.assertEqual(row["impact_conclusion"], "probable_impact")
        self.assertEqual(row["static_linkage_status"], "incompatible_if_executed")
        self.assertFalse(row["path_set_complete"])
        self.assertTrue(row["exact_path_exists"])
        self.assertTrue(row["possible_path_exists"])
        self.assertEqual(len(row["paths"]), 3)
        self.assertEqual(row["dependency_lineages"], ["demo:api"])
        self.assertEqual(row["base_dependency_coords"], ["demo:api:1.0"])
        self.assertEqual(row["current_dependency_coords"], ["demo:api:2.0"])
        self.assertEqual(len(row["dependency_artifacts"]), 3)
        self.assertIn("invokedynamic_handle", row["paths"][1]["mechanism_kinds"])
        self.assertIn("constant_dynamic_handle", row["paths"][1]["mechanism_kinds"])

    def test_aggregate_merges_same_public_provider_identity_across_loader_realms(self):
        profile, base_decisions, base_traces = self.fixture_bundles()
        base_decision = dict(base_decisions.authoritative_decisions[0])
        base_assessment = dict(base_decisions.projection_assessments[0])
        base_result = dict(base_traces.formal_results[0])
        decisions = []
        assessments = []
        results = []
        for index, realm in enumerate(("application-loader", "platform-loader")):
            change = f"provider-change-{index}"
            assessment = f"provider-assessment-{index}"
            projection = f"provider-projection-{index}"
            decisions.append({
                **base_decision,
                "decision_identity": f"provider-decision-{index}",
                "change_fact_identity": change,
                "fact_kind": "provider_topology",
                "fact_scope": {
                    "initiating_loader_realm_identity": realm,
                    "class_name": "vendor/Coroutine$Continuation",
                    "mechanism": "class_provider",
                },
            })
            assessments.append({
                **base_assessment,
                "projection_assessment_identity": assessment,
                "decision_identity": f"provider-decision-{index}",
                "change_fact_identity": change,
            })
            results.append({
                **base_result,
                "projection_identity": projection,
                "projection_assessment_identity": assessment,
                "change_fact_identity": change,
                "reachability_status": "not_found_in_static_analysis",
                "is_reachable": False,
                "impact_conclusion": "inconclusive",
                "exact_path_exists": False,
                "possible_path_exists": False,
                "paths": [],
            })

        rows = binary_output._aggregate_by_api(
            replace(
                base_decisions,
                authoritative_decisions=tuple(decisions),
                projection_assessments=tuple(assessments),
            ),
            replace(base_traces, formal_results=tuple(results)),
            profile,
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["display_member_kind"], "provider_topology")
        self.assertEqual(
            rows[0]["initiating_loader_realms"],
            ["application-loader", "platform-loader"],
        )
        self.assertEqual(
            rows[0]["contributing_change_fact_ids"],
            ["provider-change-0", "provider-change-1"],
        )

    def test_aggregate_class_and_missing_display_values_remain_explicit(self):
        profile, decisions, traces = self.fixture_bundles()
        decision = dict(decisions.authoritative_decisions[0])
        decision["fact_kind"] = "class"
        decision["fact_scope"] = {
            "initiating_loader_realm_identity": None,
            "class_name": None,
            "member_kind": None,
            "member_name": None,
            "descriptor": None,
        }
        result = dict(traces.formal_results[0])
        result.update({
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "reachability_status": "not_analyzed",
            "static_linkage_status": None,
            "path_set_complete": True,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "paths": [{
                "path_identity": None,
                "path_certainty": None,
                "edges": None,
                "entrypoint_records": None,
            }],
        })
        row = binary_output._aggregate_by_api(
            replace(decisions, authoritative_decisions=(decision,)),
            replace(traces, formal_results=(result,)),
            profile,
        )[0]
        self.assertIsNone(row["display_owner"])
        self.assertEqual(row["display_member_kind"], "class")
        self.assertEqual(row["runtime_verification_status"], "undetermined")
        self.assertEqual(row["static_linkage_status"], "undetermined")
        self.assertEqual(row["initiating_loader_realms"], [])
        self.assertEqual(row["paths"][0]["path_text"], "")

        class_decision = dict(decision)
        class_decision["fact_scope"] = {
            **decision["fact_scope"],
            "class_name": "vendor/ClassApi",
            "member_name": "<class>",
            "descriptor": "Lvendor/ClassApi;",
        }
        class_row = binary_output._aggregate_by_api(
            replace(decisions, authoritative_decisions=(class_decision,)),
            replace(traces, formal_results=(result,)),
            profile,
        )[0]
        self.assertEqual(class_row["paths"][0]["path_text"], "vendor.ClassApi")

    def test_aggregate_rejects_unbound_projection_assessment_with_domain_error(self):
        profile, decisions, traces = self.fixture_bundles()
        result = dict(traces.formal_results[0])
        result["projection_assessment_identity"] = "missing-assessment"
        with self.assertRaises(binary_output.BinaryOutputError) as caught:
            binary_output._aggregate_by_api(
                decisions,
                replace(traces, formal_results=(result,)),
                profile,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_OUTPUT_PROJECTION_ASSESSMENT_UNBOUND",
        )


if __name__ == "__main__":
    unittest.main()
