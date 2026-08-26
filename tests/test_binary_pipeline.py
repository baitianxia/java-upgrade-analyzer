import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, Mock, patch
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_output  # noqa: E402
import binary_performance_gate  # noqa: E402
import binary_pipeline  # noqa: E402
import binary_report  # noqa: E402
import binary_semantic_overlay  # noqa: E402
import binary_validation_contract  # noqa: E402
import binary_validation_oracle  # noqa: E402
import gate  # noqa: E402
import s1_dep_diff  # noqa: E402
from binary_first_contract import (  # noqa: E402
    BinaryFirstContractError,
    transport_jvm_text,
)
from binary_pipeline import (  # noqa: E402
    BinaryPipelineError,
    _artifact_snapshot_worker_count,
    _source_inputs_contract,
    run_pipeline,
)
from binary_runtime_materializer import materialize_binary_pipeline_config  # noqa: E402
from binary_report import (  # noqa: E402
    BinaryReportError,
    LEGACY_ALERT_FIELDS,
    commit_report_publication,
    complete_downstream_report_publication_after_gate,
    complete_step4_report_publication_after_gate,
    load_validated_generation,
    mark_report_publication_gate_passed,
    materialize_report_publication_gate_candidate,
    prepare_step5_publication_candidate,
    prepare_step6_publication_candidate,
    publish_step4,
    publish_step5,
    publish_step6,
    publish_report_publication,
    recover_downstream_report_publications,
    reconcile_current_release,
)
from binary_validation_oracle import (  # noqa: E402
    _declared_members,
    _oracle_runtime_contexts,
    _oracle_provider_location,
    _is_bound_jdk8_platform_path,
    _parse_javap_structural,
    _provider_resource_path,
    _resolve_member,
    validate_generation,
)
from s5_query_call_chain import query_scope_call_chain_result  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryPipelineTest(unittest.TestCase):
    def test_checkpoint_identity_ignores_windows_ctime_api_difference(self):
        common = {
            "st_dev": 1,
            "st_ino": 2,
            "st_mode": 0o100600,
            "st_nlink": 1,
            "st_size": 42,
            "st_mtime": 1.0,
            "st_mtime_ns": 123,
        }
        path_stat = Mock(**common, st_ctime_ns=10)
        descriptor_stat = Mock(**common, st_ctime_ns=20)

        self.assertEqual(
            binary_pipeline._checkpoint_stat_identity(path_stat),
            binary_pipeline._checkpoint_stat_identity(descriptor_stat),
        )

    def test_checkpoint_write_roundtrip_fails_before_empty_state_can_flow(self):
        with patch.object(
            binary_pipeline, "_write_resume_checkpoint"
        ) as write_mock, patch.object(
            binary_pipeline, "_read_resume_checkpoint", return_value={}
        ), self.assertRaises(BinaryPipelineError) as caught:
            binary_pipeline._write_resume_checkpoint_roundtrip(
                Path("output"),
                {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
            )

        write_mock.assert_called_once()
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_RESUME_CHECKPOINT_ROUNDTRIP_FAILED",
        )

    def test_validation_checkpoint_rejects_schema_less_source_state(self):
        with patch.object(
            binary_pipeline, "_write_resume_checkpoint_roundtrip"
        ) as write_mock, self.assertRaises(BinaryPipelineError) as caught:
            binary_pipeline._persist_validation_checkpoint(
                Path("output"),
                Path("generation"),
                {"result_generation_identity": "a" * 64},
                {},
                {},
            )

        write_mock.assert_not_called()
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
        )

    def test_validation_checkpoint_compares_large_attachment_without_full_read(self):
        output = self.root / "streamed-validation-checkpoint"
        generation, manifest = self._resume_generation(output)
        generation = generation.resolve()
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": []},
            "current": {"artifacts": []},
        }
        issues = [
            {
                "domain": "provider",
                "reason_code": "ORACLE_ARTIFACT_PROVIDER_MISMATCH",
                "evidence": {"index": index, "path": "C:/workspace/app.jar"},
            }
            for index in range(20_000)
        ]
        validation = self._resume_validation_result(
            generation,
            manifest,
            "failed",
            issues=issues,
            issue_count=len(issues),
            domain_summary={"provider": {"issues": len(issues)}},
        )
        validation_path = Path(validation["validation_result_path"])
        expected_sha256 = hashlib.sha256(validation_path.read_bytes()).hexdigest()
        checkpoint = binary_pipeline._normalized_resume_checkpoint(
            self._resume_checkpoint(config, manifest)
        )
        real_read_bytes = Path.read_bytes

        def guarded_read_bytes(path):
            if Path(path) == validation_path:
                raise AssertionError("whole validation attachment read is forbidden")
            return real_read_bytes(Path(path))

        with patch.object(
            Path, "read_bytes", autospec=True, side_effect=guarded_read_bytes,
        ), patch.object(
            binary_pipeline,
            "_canonical_json_bytes",
            side_effect=AssertionError("full JSON serialization is forbidden"),
        ), patch.object(
            binary_pipeline,
            "_write_resume_checkpoint_roundtrip",
            side_effect=lambda _root, payload, **_kwargs: dict(payload),
        ):
            updated = binary_pipeline._persist_validation_checkpoint(
                output, generation, manifest, checkpoint, validation
            )

        self.assertEqual(updated["validation_result_sha256"], expected_sha256)
        self.assertEqual(
            updated["status"], binary_pipeline._RESUME_VALIDATION_FAILED
        )

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "checkpoint mutation requires POSIX dir_fd support",
    )
    def test_resume_checkpoint_root_swap_before_open_cannot_touch_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            output = parent / "output"
            (output / "binary_observability").mkdir(parents=True)
            moved_output = parent / "output-original"
            replacement = parent / "replacement"
            replacement_observability = replacement / "binary_observability"
            replacement_observability.mkdir(parents=True)
            replacement_checkpoint = (
                replacement_observability / "validation_checkpoint.json"
            )
            replacement_checkpoint.write_text("outside\n", encoding="utf-8")
            real_open = os.open
            real_rename = os.rename
            raced = False

            def swap_root_before_open(name, flags, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == output.name
                    and kwargs.get("dir_fd") is not None
                    and flags & int(getattr(os, "O_DIRECTORY", 0) or 0)
                ):
                    raced = True
                    real_rename(output, moved_output)
                    real_rename(replacement, output)
                return real_open(name, flags, *args, **kwargs)

            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline.os,
                "open",
                side_effect=swap_root_before_open,
            ), self.assertRaises(BinaryPipelineError) as caught:
                binary_pipeline._write_resume_checkpoint(
                    output,
                    {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
                )

            self.assertTrue(raced)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            )
            self.assertEqual(
                (
                    output
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                "outside\n",
            )
            self.assertFalse(
                (
                    moved_output
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).exists()
            )

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "checkpoint mutation requires POSIX dir_fd support",
    )
    def test_resume_checkpoint_observability_replacement_before_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            observability = output / "binary_observability"
            observability.mkdir(parents=True)
            moved_observability = output / "binary_observability-original"
            replacement = output / "replacement-observability"
            replacement.mkdir()
            replacement_checkpoint = replacement / "validation_checkpoint.json"
            replacement_checkpoint.write_text("outside\n", encoding="utf-8")
            real_open = os.open
            real_rename = os.rename
            raced = False

            def swap_observability_before_open(name, flags, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == "binary_observability"
                    and kwargs.get("dir_fd") is not None
                    and flags & int(getattr(os, "O_DIRECTORY", 0) or 0)
                ):
                    raced = True
                    real_rename(observability, moved_observability)
                    real_rename(replacement, observability)
                return real_open(name, flags, *args, **kwargs)

            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline.os,
                "open",
                side_effect=swap_observability_before_open,
            ), self.assertRaises(BinaryPipelineError) as caught:
                binary_pipeline._write_resume_checkpoint(
                    output,
                    {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
                )

            self.assertTrue(raced)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            )
            self.assertEqual(
                (
                    observability / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                "outside\n",
            )
            self.assertFalse(
                (
                    moved_observability / "validation_checkpoint.json"
                ).exists()
            )

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "observability mutation requires POSIX dir_fd support",
    )
    def test_non_authoritative_observability_root_swap_skips_external_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            output = parent / "output"
            (output / "binary_observability").mkdir(parents=True)
            moved_output = parent / "output-original"
            replacement = parent / "replacement"
            replacement_observability = replacement / "binary_observability"
            replacement_observability.mkdir(parents=True)
            external_progress = replacement_observability / "latest_failure.json"
            external_progress.write_text("outside\n", encoding="utf-8")
            real_open = os.open
            real_rename = os.rename
            raced = False

            def swap_root_before_open(name, flags, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == output.name
                    and kwargs.get("dir_fd") is not None
                    and flags & int(getattr(os, "O_DIRECTORY", 0) or 0)
                ):
                    raced = True
                    real_rename(output, moved_output)
                    real_rename(replacement, output)
                return real_open(name, flags, *args, **kwargs)

            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline.os,
                "open",
                side_effect=swap_root_before_open,
            ):
                written = binary_pipeline._write_non_authoritative_json(
                    output / "binary_observability" / "latest_failure.json",
                    {"status": "failed"},
                )

            self.assertTrue(raced)
            self.assertFalse(written)
            self.assertEqual(
                (
                    output
                    / "binary_observability"
                    / "latest_failure.json"
                ).read_text(encoding="utf-8"),
                "outside\n",
            )

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "checkpoint mutation requires POSIX dir_fd support",
    )
    def test_resume_checkpoint_write_parent_swap_cannot_touch_external_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            observability = output / "binary_observability"
            observability.mkdir(parents=True)
            moved_observability = output / "binary_observability-original"
            external = root / "external-observability"
            external.mkdir()
            external_checkpoint = external / "validation_checkpoint.json"
            external_checkpoint.write_text("outside\n", encoding="utf-8")
            real_rename = os.rename
            raced = False

            def swap_parent_before_rename(source, destination, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and destination == "validation_checkpoint.json"
                    and kwargs.get("src_dir_fd") is not None
                    and kwargs.get("dst_dir_fd") is not None
                ):
                    raced = True
                    real_rename(observability, moved_observability)
                    observability.symlink_to(
                        external, target_is_directory=True
                    )
                return real_rename(source, destination, *args, **kwargs)

            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline.os,
                "rename",
                side_effect=swap_parent_before_rename,
            ), self.assertRaises(BinaryPipelineError) as caught:
                binary_pipeline._write_resume_checkpoint(
                    output,
                    {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
                )

            self.assertTrue(raced)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_RESUME_CHECKPOINT_WRITE_FAILED",
            )
            self.assertEqual(
                external_checkpoint.read_text(encoding="utf-8"), "outside\n"
            )
            self.assertTrue(
                (moved_observability / "validation_checkpoint.json").is_file()
            )
            self.assertTrue(observability.is_symlink())

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "checkpoint mutation requires POSIX dir_fd support",
    )
    def test_resume_checkpoint_delete_parent_swap_cannot_touch_external_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            binary_pipeline._write_resume_checkpoint(
                output,
                {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
            )
            observability = output / "binary_observability"
            moved_observability = output / "binary_observability-original"
            external = root / "external-observability"
            external.mkdir()
            external_checkpoint = external / "validation_checkpoint.json"
            external_checkpoint.write_text("outside\n", encoding="utf-8")
            real_unlink = os.unlink
            real_rename = os.rename
            raced = False

            def swap_parent_before_unlink(name, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == "validation_checkpoint.json"
                    and kwargs.get("dir_fd") is not None
                ):
                    raced = True
                    real_rename(observability, moved_observability)
                    observability.symlink_to(
                        external, target_is_directory=True
                    )
                return real_unlink(name, *args, **kwargs)

            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline.os,
                "unlink",
                side_effect=swap_parent_before_unlink,
            ), self.assertRaises(BinaryPipelineError) as caught:
                binary_pipeline._delete_resume_checkpoint_durable(output)

            self.assertTrue(raced)
            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED",
            )
            self.assertEqual(
                external_checkpoint.read_text(encoding="utf-8"), "outside\n"
            )
            self.assertFalse(
                (moved_observability / "validation_checkpoint.json").exists()
            )
            self.assertTrue(observability.is_symlink())

    def test_completed_analysis_does_not_fail_on_checkpoint_cleanup(self):
        error = BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED", "injected"
        )
        with patch.object(
            binary_pipeline,
            "_delete_resume_checkpoint_durable",
            side_effect=error,
        ):
            self.assertFalse(
                binary_pipeline._cleanup_consumed_resume_checkpoint(
                    Path("unused"), None
                )
            )
            with self.assertRaises(BinaryPipelineError):
                binary_pipeline._cleanup_consumed_resume_checkpoint(
                    Path("unused"), {"authority_mode": "measurement"}
                )

    def test_resume_checkpoint_writer_rejects_symlinked_observability_parent_without_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            try:
                (output / "binary_observability").symlink_to(
                    outside, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with self.assertRaises(BinaryPipelineError) as caught:
                binary_pipeline._write_resume_checkpoint(
                    output,
                    {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertEqual(
                sorted(path.name for path in outside.iterdir()),
                ["sentinel.txt"],
            )

    def test_resume_checkpoint_reader_rejects_non_strict_or_special_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            checkpoint = binary_pipeline._resume_checkpoint_path(output)
            checkpoint.parent.mkdir(parents=True)

            checkpoint.write_text('{"status": NaN}\n', encoding="utf-8")
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})

            checkpoint.write_text(
                '{"status": "first", "status": "last"}\n',
                encoding="utf-8",
            )
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})

            checkpoint.unlink()
            external = Path(tmp) / "external.json"
            external.write_text('{"status": "external"}\n', encoding="utf-8")
            try:
                checkpoint.symlink_to(external)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})
            self.assertEqual(
                external.read_text(encoding="utf-8"),
                '{"status": "external"}\n',
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO files are unavailable")
    def test_resume_checkpoint_reader_never_blocks_on_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            checkpoint = binary_pipeline._resume_checkpoint_path(output)
            checkpoint.parent.mkdir(parents=True)
            os.mkfifo(checkpoint)

            started = time.perf_counter()
            result = binary_pipeline._read_resume_checkpoint(output)

            self.assertEqual(result, {})
            self.assertLess(time.perf_counter() - started, 1.0)

    def test_resume_checkpoint_reader_rejects_path_replacement_during_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            checkpoint = binary_pipeline._resume_checkpoint_path(output)
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text('{"status": "original"}\n', encoding="utf-8")
            displaced = checkpoint.with_name("displaced.json")
            original_read = os.read
            replaced = False

            def replace_path_then_read(descriptor, size):
                nonlocal replaced
                if not replaced:
                    replaced = True
                    checkpoint.rename(displaced)
                    checkpoint.write_text(
                        '{"status": "replacement"}\n', encoding="utf-8"
                    )
                return original_read(descriptor, size)

            with patch.object(
                binary_pipeline.os, "read", side_effect=replace_path_then_read
            ):
                result = binary_pipeline._read_resume_checkpoint(output)

            self.assertTrue(replaced)
            self.assertEqual(result, {})

    @unittest.skipUnless(
        binary_pipeline._secure_resume_checkpoint_dirfd_supported(),
        "checkpoint reads require POSIX dir_fd support",
    )
    def test_resume_checkpoint_reader_rejects_root_swap_after_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            output = parent / "output"
            checkpoint = binary_pipeline._resume_checkpoint_path(output)
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text(
                '{"status": "original"}\n', encoding="utf-8"
            )
            moved_output = parent / "output-original"
            replacement = parent / "replacement"
            replacement_checkpoint = (
                replacement
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            replacement_checkpoint.parent.mkdir(parents=True)
            replacement_checkpoint.write_text(
                '{"status": "external"}\n', encoding="utf-8"
            )
            original_bind = (
                binary_pipeline._open_bound_checkpoint_directories
            )
            swapped = False

            def bind_then_swap(*args, **kwargs):
                nonlocal swapped
                binding = original_bind(*args, **kwargs)
                if binding is not None and not swapped:
                    swapped = True
                    output.rename(moved_output)
                    replacement.rename(output)
                return binding

            with patch.object(
                binary_pipeline,
                "_open_bound_checkpoint_directories",
                side_effect=bind_then_swap,
            ):
                result = binary_pipeline._read_resume_checkpoint(output)

            self.assertTrue(swapped)
            self.assertEqual(result, {})
            self.assertEqual(
                (
                    output
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                '{"status": "external"}\n',
            )
            self.assertEqual(
                (
                    moved_output
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                '{"status": "original"}\n',
            )

    def test_pipeline_run_lock_rejects_second_writer_for_same_output_root(self):
        first_entered = threading.Event()
        release_first = threading.Event()
        output = Path(tempfile.mkdtemp()) / "same-output"

        def held_pipeline(_config, *, output_root, **_kwargs):
            first_entered.set()
            if not release_first.wait(timeout=5.0):
                raise AssertionError("test did not release first pipeline")
            return {"output_root": str(output_root)}

        try:
            with patch.object(
                binary_pipeline, "_run_pipeline_under_lock", new=held_pipeline,
            ), patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(
                        binary_pipeline.run_pipeline,
                        {},
                        output_root=output,
                    )
                    self.assertTrue(first_entered.wait(timeout=2.0))
                    second = executor.submit(
                        binary_pipeline.run_pipeline,
                        {},
                        output_root=output,
                    )
                    with self.assertRaises(BinaryPipelineError) as failure:
                        second.result(timeout=2.0)
                    self.assertEqual(
                        failure.exception.reason_code,
                        "BINARY_PIPELINE_RUN_ALREADY_ACTIVE",
                    )
                    release_first.set()
                    self.assertEqual(
                        first.result(timeout=2.0)["output_root"],
                        str(output.resolve()),
                    )
        finally:
            release_first.set()
            shutil.rmtree(output.parent, ignore_errors=True)

    def test_pipeline_run_lock_allows_different_output_roots_concurrently(self):
        root = Path(tempfile.mkdtemp())
        outputs = (root / "first", root / "second")
        both_entered = threading.Barrier(2)

        def synchronized_pipeline(_config, *, output_root, **_kwargs):
            both_entered.wait(timeout=2.0)
            return {"output_root": str(output_root)}

        try:
            with patch.object(
                binary_pipeline,
                "_run_pipeline_under_lock",
                new=synchronized_pipeline,
            ):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [
                        executor.submit(
                            binary_pipeline.run_pipeline,
                            {},
                            output_root=output,
                        )
                        for output in outputs
                    ]
                    results = [future.result(timeout=3.0) for future in futures]
            self.assertEqual(
                {item["output_root"] for item in results},
                {str(output.resolve()) for output in outputs},
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_pipeline_run_lock_does_not_relabel_body_io_or_timeout_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            for body_error in (
                TimeoutError("pipeline body timeout"),
                OSError("pipeline body I/O failure"),
            ):
                with self.subTest(error_type=type(body_error).__name__), \
                        patch.object(
                            binary_pipeline,
                            "_run_pipeline_under_lock",
                            side_effect=body_error,
                        ), self.assertRaises(type(body_error)) as failure:
                    binary_pipeline.run_pipeline({}, output_root=tmp)
                self.assertIs(failure.exception, body_error)

    def test_pipeline_run_lock_maps_only_acquisition_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            for acquisition_error, expected_reason in (
                (
                    TimeoutError("held"),
                    "BINARY_PIPELINE_RUN_ALREADY_ACTIVE",
                ),
                (
                    OSError("unsafe lock"),
                    "BINARY_PIPELINE_RUN_LOCK_UNAVAILABLE",
                ),
            ):
                manager = MagicMock()
                manager.__enter__.side_effect = acquisition_error
                with self.subTest(expected_reason=expected_reason), patch.object(
                    binary_pipeline,
                    "exclusive_file_lock",
                    return_value=manager,
                ), patch.object(
                    binary_pipeline,
                    "_run_pipeline_under_lock",
                    side_effect=AssertionError("body must not execute"),
                ) as body, self.assertRaises(BinaryPipelineError) as failure:
                    binary_pipeline.run_pipeline({}, output_root=tmp)
                self.assertEqual(failure.exception.reason_code, expected_reason)
                body.assert_not_called()
                manager.__exit__.assert_not_called()

    def test_workflow_lock_never_trusts_orchestrated_environment_flag(self):
        manager = MagicMock()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"JUA_ORCHESTRATED": "1"}
        ), patch.object(
            binary_report,
            "exclusive_file_lock",
            return_value=manager,
        ) as acquire:
            with binary_report._standalone_report_workflow_lock(tmp):
                pass

        acquire.assert_called_once()
        manager.__enter__.assert_called_once_with()
        manager.__exit__.assert_called_once_with(None, None, None)

    def test_report_locks_map_only_acquisition_timeout(self):
        lock_cases = (
            (
                binary_report._standalone_report_workflow_lock,
                "BINARY_REPORT_WORKFLOW_MUTATION_ALREADY_ACTIVE",
            ),
            (
                binary_report._active_generation_publication_lock,
                "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT",
            ),
            (
                binary_report._report_workflow_read_lock,
                "BINARY_REPORT_WORKFLOW_MUTATION_ALREADY_ACTIVE",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for lock_factory, expected_reason in lock_cases:
                with self.subTest(
                    lock_factory=lock_factory.__name__, case="body"
                ):
                    body_error = TimeoutError("report operation timed out")
                    with self.assertRaises(TimeoutError) as body_failure:
                        with lock_factory(tmp):
                            raise body_error
                    self.assertIs(body_failure.exception, body_error)

                manager = MagicMock()
                manager.__enter__.side_effect = TimeoutError("held")
                with self.subTest(
                    lock_factory=lock_factory.__name__, case="acquisition"
                ), patch.object(
                    binary_report,
                    "exclusive_file_lock",
                    return_value=manager,
                ), self.assertRaises(BinaryReportError) as acquisition:
                    with lock_factory(tmp):
                        self.fail("unacquired report lock entered its body")
                self.assertEqual(
                    acquisition.exception.reason_code, expected_reason
                )
                manager.__exit__.assert_not_called()

    def test_direct_step4_rejects_candidate_activation_even_with_environment_flag(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"JUA_ORCHESTRATED": "1"}
        ), self.assertRaises(BinaryReportError) as failure:
            publish_step4(
                Path(tmp) / "report",
                Path(tmp) / "report" / "evidence" / "api_changes",
                candidate_activation_identity="a" * 64,
            )

        self.assertEqual(
            failure.exception.reason_code,
            "BINARY_STEP4_CANDIDATE_ACTIVATION_REQUIRES_ORCHESTRATOR",
        )

    def test_direct_step5_ignores_environment_and_completes_formal_gate(self):
        transaction = {
            "transaction_id": "1" * 32,
            "state": "pending_gate",
            "binding": {"report_implementation_identity": "2" * 64},
            "gate_receipt": None,
            "published_content_identity": "3" * 64,
        }
        completion = {
            "publication_receipt": {"gate_receipt": {"gate_name": "binary_report"}},
            "global_release": {"step5": {"status": "current"}},
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"JUA_ORCHESTRATED": "1"}
        ), patch.object(
            binary_report,
            "_publish_step5_with_lock",
            return_value={
                "phase": "step5",
                "publication_transaction": transaction,
            },
        ), patch.object(
            binary_report,
            "materialize_report_publication_gate_candidate",
            return_value={
                "candidate_destinations": ["candidate-call", "candidate-analysis", "candidate-index"]
            },
        ), patch.object(
            gate, "gate_binary_report"
        ) as formal_gate, patch.object(
            binary_report,
            "complete_downstream_report_publication_after_gate",
            return_value=completion,
        ) as complete:
            report = Path(tmp) / "report"
            result = publish_step5(
                report, report / "evidence" / "call_chain"
            )

        formal_gate.assert_called_once()
        complete.assert_called_once()
        self.assertIsNone(result["publication_transaction"])
        self.assertEqual(
            result["publication_receipt"]["gate_receipt"]["gate_name"],
            "binary_report",
        )

    def test_prepare_step6_routes_only_to_pending_candidate_path(self):
        pending = {
            "phase": "step6",
            "publication_transaction": {"state": "pending_gate"},
        }
        with patch.object(
            binary_report,
            "_publish_step6_with_lock",
            return_value=pending,
        ) as stage:
            with binary_report._report_publication_prepare_capability(
                "report", "step6"
            ):
                result = prepare_step6_publication_candidate(
                    "report", "findings", "report.md"
                )

        self.assertIs(result, pending)
        stage.assert_called_once_with(
            "report",
            "findings",
            "report.md",
            prepare_candidate_only=True,
        )

    def test_direct_step6_ignores_environment_and_uses_commit_path(self):
        committed = {
            "phase": "step6",
            "publication_transaction": None,
            "publication_receipt": {"gate_receipt": {"gate_name": "binary_final_report"}},
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"JUA_ORCHESTRATED": "1"}
        ), patch.object(
            binary_report,
            "_publish_step6_with_lock",
            return_value=committed,
        ) as publish:
            result = publish_step6(
                Path(tmp) / "report",
                Path(tmp) / "report" / ".runtime" / "findings" / "s6_findings.json",
                Path(tmp) / "report" / "deliverables" / "report.md",
            )

        self.assertIs(result, committed)
        publish.assert_called_once_with(
            Path(tmp) / "report",
            Path(tmp) / "report" / ".runtime" / "findings" / "s6_findings.json",
            Path(tmp) / "report" / "deliverables" / "report.md",
            prepare_candidate_only=False,
        )

    def test_cli_prepare_mode_is_forbidden_for_every_phase_before_mutation(self):
        for phase in ("step4", "step5", "step6"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp) / "report"
                sentinel = report / "sentinel"
                sentinel.parent.mkdir(parents=True)
                sentinel.write_text("unchanged", encoding="utf-8")
                result_path = Path(tmp) / f"{phase}-result.json"
                with patch.object(
                    binary_report,
                    f"prepare_{phase}_publication_candidate",
                ) as prepare, patch.object(
                    binary_report,
                    f"publish_{phase}",
                ) as direct, patch("builtins.print"):
                    with self.assertRaises(BinaryReportError) as failure:
                        binary_report.main([
                            "--phase", phase,
                            "--report-dir", str(report),
                            "--result-json", str(result_path),
                            "--prepare-publication-candidate",
                        ])

                self.assertEqual(
                    failure.exception.reason_code,
                    "BINARY_REPORT_PREPARE_CLI_FORBIDDEN",
                )
                self.assertEqual(
                    json.loads(result_path.read_text(encoding="utf-8"))[
                        "reason_code"
                    ],
                    "BINARY_REPORT_PREPARE_CLI_FORBIDDEN",
                )
                self.assertEqual(
                    sentinel.read_text(encoding="utf-8"), "unchanged"
                )
                prepare.assert_not_called()
                direct.assert_not_called()

    def test_private_prepare_requires_an_exact_single_use_capability(self):
        pending = {
            "phase": "step4",
            "publication_transaction": {
                "state": "pending_gate",
                "gate_receipt": None,
            },
            "publication_receipt": None,
            "global_release": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            other_report = Path(tmp) / "other-report"

            with patch.object(
                binary_report,
                "_publish_step4_with_lock",
                return_value=pending,
            ) as publish:
                with self.assertRaises(BinaryReportError) as missing:
                    binary_report.prepare_step4_publication_candidate(
                        report, report / "evidence" / "api_changes"
                    )
                self.assertEqual(
                    missing.exception.reason_code,
                    "BINARY_REPORT_PREPARE_CAPABILITY_REQUIRED",
                )
                publish.assert_not_called()

                with binary_report._report_publication_prepare_capability(
                    report, "step4"
                ):
                    with self.assertRaises(BinaryReportError) as wrong_root:
                        binary_report.prepare_step4_publication_candidate(
                            other_report,
                            other_report / "evidence" / "api_changes",
                        )
                    self.assertEqual(
                        wrong_root.exception.reason_code,
                        "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
                    )
                    with self.assertRaises(BinaryReportError) as consumed:
                        binary_report.prepare_step4_publication_candidate(
                            report, report / "evidence" / "api_changes"
                        )
                    self.assertEqual(
                        consumed.exception.reason_code,
                        "BINARY_REPORT_PREPARE_CAPABILITY_REPLAYED",
                    )
                publish.assert_not_called()

                with binary_report._report_publication_prepare_capability(
                    report, "step4"
                ):
                    self.assertIs(
                        binary_report.prepare_step4_publication_candidate(
                            report, report / "evidence" / "api_changes"
                        ),
                        pending,
                    )
                    with self.assertRaises(BinaryReportError) as replay:
                        binary_report.prepare_step4_publication_candidate(
                            report, report / "evidence" / "api_changes"
                        )
                    self.assertEqual(
                        replay.exception.reason_code,
                        "BINARY_REPORT_PREPARE_CAPABILITY_REPLAYED",
                    )
                publish.assert_called_once()

            with patch.object(
                binary_report, "_publish_step5_with_lock"
            ) as publish_step5_candidate:
                with binary_report._report_publication_prepare_capability(
                    report, "step4"
                ):
                    with self.assertRaises(BinaryReportError) as wrong_phase:
                        binary_report.prepare_step5_publication_candidate(
                            report, report / "evidence" / "call_chain"
                        )
                self.assertEqual(
                    wrong_phase.exception.reason_code,
                    "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
                )
                publish_step5_candidate.assert_not_called()

    def test_pending_publication_conflict_preserves_public_and_candidate_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            destinations = (root / "one", root / "two")
            for destination in destinations:
                destination.mkdir()
                (destination / "value").write_text(
                    "public-old", encoding="utf-8"
                )

            def writer(value):
                def write(stage, _prepared):
                    (stage / "value").write_text(value, encoding="utf-8")
                return write

            pending = binary_report._stage_directory_group(
                tuple(
                    (destination, writer("candidate-one"))
                    for destination in destinations
                ),
                retain_transaction=True,
            )
            transaction_path = Path(pending["transaction_path"])
            transaction_before = transaction_path.read_bytes()
            candidates_before = tuple(
                (Path(path) / "value").read_bytes()
                for path in pending["candidate_destinations"]
            )
            second_writer_called = False

            def conflicting_writer(stage, _prepared):
                nonlocal second_writer_called
                second_writer_called = True
                (stage / "value").write_text("candidate-two", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as conflict:
                binary_report._stage_directory_group(
                    tuple(
                        (destination, conflicting_writer)
                        for destination in destinations
                    ),
                    retain_transaction=True,
                )

            self.assertEqual(
                conflict.exception.reason_code,
                "BINARY_REPORT_PUBLICATION_TRANSACTION_IN_PROGRESS",
            )
            self.assertFalse(second_writer_called)
            self.assertEqual(transaction_path.read_bytes(), transaction_before)
            self.assertEqual(
                tuple(
                    (Path(path) / "value").read_bytes()
                    for path in pending["candidate_destinations"]
                ),
                candidates_before,
            )
            self.assertEqual(
                tuple(
                    (destination / "value").read_text(encoding="utf-8")
                    for destination in destinations
                ),
                ("public-old", "public-old"),
            )

    def test_completion_rejects_non_formal_gate_names_before_mutation(self):
        for stage, complete in (
            ("step4", complete_step4_report_publication_after_gate),
            ("step5", complete_downstream_report_publication_after_gate),
            ("step6", complete_downstream_report_publication_after_gate),
        ):
            kwargs = {
                "expected_transaction_id": "1" * 32,
                "expected_binding": {},
                "gate_name": "forged_gate",
                "strict_risk_gate": False,
                "workflow_lock_held": True,
            }
            if stage == "step4":
                call = lambda: complete("missing-report", **kwargs)
            else:
                call = lambda stage=stage: complete(
                    "missing-report", stage, **kwargs
                )
            with self.assertRaises(BinaryReportError) as failure:
                call()
            self.assertEqual(
                failure.exception.reason_code,
                "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
            )

    def _write_step6_upstream_contract(self, report, coord):
        report = Path(report)
        dependencies = report / "evidence" / "dependencies"
        context = report / "evidence" / "context"
        static = report / "evidence" / "static_scan"
        dependencies.mkdir(parents=True, exist_ok=True)
        context.mkdir(parents=True, exist_ok=True)
        static.mkdir(parents=True, exist_ok=True)
        (dependencies / "dep_changes.csv").write_text(
            "coord,old_version,new_version,change_type,risk,scope,"
            "resolution_status,base_lib_entry,current_lib_entry\n"
            f"{coord},1.0,2.0,升级,P1,compile,resolved,"
            "lib/base.jar,lib/current.jar\n",
            encoding="utf-8",
        )
        (dependencies / "build_provenance.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v2",
                "both_builds_succeeded": True,
                "sides": [
                    {"side": "base", "artifact_sha256": "a" * 64},
                    {"side": "current", "artifact_sha256": "b" * 64},
                ],
            }),
            encoding="utf-8",
        )
        (dependencies / "dependency_jars.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": [],
                "business_artifacts": [],
                "runtime_closure": {},
            }),
            encoding="utf-8",
        )
        (context / "context.json").write_text(json.dumps({
            "base_branch": "base",
            "current_branch": "current",
            "jdk_base": "17",
            "jdk_current": "17",
            "build_tool": "maven",
            "jdk_upgraded": False,
            "springboot_major_upgrade": False,
            "tech_flags": {},
        }), encoding="utf-8")
        (static / "s3_dependency_compat.csv").write_text(
            "坐标,版本,依赖范围,风险类型,证据,最终制品内路径\n",
            encoding="utf-8",
        )
        (static / "s3_dependency_classfile.csv").write_text(
            "依赖坐标,版本,依赖范围,最终制品内路径,是否为多版本JAR,"
            "基础区最高Class版本,多版本区最高Class版本,"
            "基础区所需Java版本,多版本区所需Java版本,"
            "最高所需Java版本,目标JDK版本,扫描结论\n",
            encoding="utf-8",
        )
        (static / "s3_database_contract_summary.json").write_text(
            json.dumps({
                "schema": (
                    "java-upgrade-analyzer.database-contract-changes.v1"
                ),
                "coverage_status": "complete",
                "change_count": 0,
                "coverage_gaps": [],
            }),
            encoding="utf-8",
        )
        (static / "s3_database_contract_changes.csv").write_text(
            "依赖包,变化类型,契约类型,可信度,表,列,契约位置,语句或字段,"
            "人工复核建议\n",
            encoding="utf-8",
        )
        (static / "s3_database_contract_changes.md").write_text(
            "# 数据库契约变化明细\n",
            encoding="utf-8",
        )
        coverage = report / ".runtime" / "coverage" / "s3_coverage.json"
        coverage.parent.mkdir(parents=True, exist_ok=True)
        coverage.write_text(json.dumps({
            "schema": "java-upgrade-analyzer.step3-coverage.v1",
            "status": "complete",
            "reason_codes": [],
            "planned_scans": [
                "dep_compat", "dep_classfile", "database_contract",
            ],
            "executed_scans": [
                "dep_compat", "dep_classfile", "database_contract",
            ],
        }), encoding="utf-8")

    @classmethod
    def setUpClass(cls):
        cls.home = jdk_home()
        if not shutil.which("javac") or not cls.home or not (cls.home / "jmods").is_dir():
            raise unittest.SkipTest("full target JDK required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        real_performance_authority_tests = {
            "test_performance_authority_uses_one_evidence_byte_snapshot",
            "test_performance_authority_change_before_activation_fails_closed",
        }
        if self._testMethodName not in real_performance_authority_tests:
            # Pipeline correctness tests depend on a structurally valid
            # capability, not on the mutable multi-hour release capture.  The
            # two explicitly allowlisted tests below exercise the real evidence
            # binder itself; all other tests stay deterministic while a new
            # release fixture or reference pin is being prepared.
            authority = self._synthetic_performance_authority_binding(
                "pipeline-test-default"
            )
            authority_patch = patch.object(
                binary_pipeline,
                "_performance_authority_gate_binding",
                return_value=authority,
            )
            authority_patch.start()
            self.addCleanup(authority_patch.stop)

    def _resume_generation(self, output, *, omitted_sidecar=""):
        snapshots = {
            "decision": "1" * 64,
            "assessment": "2" * 64,
            "formal_projection": "3" * 64,
            "candidate_projection": "4" * 64,
        }
        policies = {
            "analysis_scope": "5" * 64,
            "runtime_comparison": "6" * 64,
            "base_jdk_preflight_identity": "e" * 64,
            "current_jdk_preflight_identity": "f" * 64,
        }
        sidecar_payloads = {
            name: f"fixture:{name}\n".encode("utf-8")
            for name in binary_pipeline._REQUIRED_PIPELINE_GENERATION_SIDECARS
            if name != omitted_sidecar
        }
        sidecar_identities = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sidecar_payloads.items()
        }
        manifest = {
            "schema": "java-upgrade-analyzer.binary-result-generation.v1",
            "analysis_context_identity": "7" * 64,
            "authority": "binary_first",
            "active_snapshot_identities": snapshots,
            "trace_result_set_digest": "8" * 64,
            "sidecar_content_identities": sidecar_identities,
            "policy_identities": policies,
            "attachment_policy": (
                "trace-results-bound-by-generation-attachment-v1"
            ),
        }
        generation_identity = binary_pipeline._identity(
            "result_generation_identity",
            {
                "analysis_context_identity": manifest[
                    "analysis_context_identity"
                ],
                "authority": "binary_first",
                "snapshot_identities": snapshots,
                "trace_result_set_digest": manifest[
                    "trace_result_set_digest"
                ],
                "sidecar_content_identities": sidecar_identities,
                "policy_identities": policies,
            },
        )
        manifest["result_generation_identity"] = generation_identity
        generation = output / "binary_generations" / generation_identity
        generation.mkdir(parents=True)
        for name, payload in sidecar_payloads.items():
            (generation / name).write_bytes(payload)
        (generation / "result_generation.json").write_bytes(
            binary_pipeline._canonical_json_bytes(manifest)
        )
        return generation, manifest

    def _bind_resume_generation_publication_authority(
        self, generation, manifest, performance_binding
    ):
        """Replace the synthetic sidecar with a real immutable release grant."""

        authority = {
            "schema": (
                "java-upgrade-analyzer.binary-publication-authority.v1"
            ),
            "authority_mode": "release_evidence",
            "binding_identity": performance_binding["binding_identity"],
            "public_activation_allowed": True,
            "performance_authority_gate_binding": dict(
                performance_binding
            ),
        }
        authority_bytes = binary_output._json_bytes(authority)
        authority_name = "binary_publication_authority.json"
        (generation / authority_name).write_bytes(authority_bytes)
        rebound_manifest = dict(manifest)
        rebound_manifest["sidecar_content_identities"] = dict(
            manifest["sidecar_content_identities"]
        )
        rebound_manifest["sidecar_content_identities"][authority_name] = (
            hashlib.sha256(authority_bytes).hexdigest()
        )
        rebound_identity = binary_pipeline._identity(
            "result_generation_identity",
            {
                "analysis_context_identity": rebound_manifest[
                    "analysis_context_identity"
                ],
                "authority": "binary_first",
                "snapshot_identities": rebound_manifest[
                    "active_snapshot_identities"
                ],
                "trace_result_set_digest": rebound_manifest[
                    "trace_result_set_digest"
                ],
                "sidecar_content_identities": rebound_manifest[
                    "sidecar_content_identities"
                ],
                "policy_identities": rebound_manifest[
                    "policy_identities"
                ],
            },
        )
        rebound_manifest["result_generation_identity"] = rebound_identity
        rebound_generation = generation.with_name(rebound_identity)
        generation.rename(rebound_generation)
        (rebound_generation / "result_generation.json").write_bytes(
            binary_output._json_bytes(rebound_manifest)
        )
        return rebound_generation, rebound_manifest

    def _resume_result_summary(self):
        return {
            "base_runtime_reconciliation_identity": "9" * 64,
            "current_runtime_reconciliation_identity": "a" * 64,
            "decision_bundle_identity": "b" * 64,
            "trace_bundle_identity": "c" * 64,
            "decision_coverage_status": "complete",
            "trace_coverage_status": "complete",
            "authoritative_change_fact_count": 1,
            "diagnostic_candidate_fact_count": 0,
        }

    def _resume_toolchain_preflight(self, **overrides):
        identities = {"base": "e" * 64, "current": "f" * 64}
        identities.update(overrides)
        return {
            side: {"jdk_preflight_identity": identity}
            for side, identity in identities.items()
        }

    def _resume_performance_authority_binding(self):
        cached = getattr(self, "_cached_resume_performance_binding", None)
        if cached is None:
            # Resume mechanics need a structurally valid bound capability, not
            # the mutable checked-in scale evidence.  Performance authority's
            # real evidence integration has dedicated tests below; keeping it
            # out of this helper lets checkpoint tests run while a new release
            # fixture is intentionally being recorded.
            cached = self._synthetic_performance_authority_binding(
                "resume-default"
            )
            self._cached_resume_performance_binding = cached
        return dict(cached)

    def _synthetic_performance_authority_binding(
        self, label, *, authority_mode="release_evidence"
    ):
        binding = {
            "schema": (
                "java-upgrade-analyzer.performance-authority-binding.v2"
            ),
            "authority_mode": authority_mode,
            "support_contract_identity": hashlib.sha256(
                f"support:{label}".encode("utf-8")
            ).hexdigest(),
            "evidence_sha256": hashlib.sha256(
                f"evidence:{label}".encode("utf-8")
            ).hexdigest(),
            "source_implementation_identity": hashlib.sha256(
                f"source:{label}".encode("utf-8")
            ).hexdigest(),
        }
        binding["binding_identity"] = binary_pipeline._identity(
            "binary_performance_authority_binding_identity",
            {
                key: binding[key]
                for key in (
                    "support_contract_identity",
                    "evidence_sha256",
                    "source_implementation_identity",
                    "authority_mode",
                )
            },
        )
        return binding

    def test_parent_checkpoint_operations_execute_portable_windows_fallbacks(self):
        class WindowsOsProxy:
            name = "nt"

            def __getattr__(self, name):
                return getattr(os, name)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            root.mkdir(mode=0o700)
            proxy = WindowsOsProxy()
            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=False,
            ), patch.object(binary_pipeline, "os", proxy):
                written = binary_pipeline._write_resume_checkpoint(
                    root,
                    {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA},
                )
                checkpoint = binary_pipeline._read_resume_checkpoint(root)
                optional = binary_pipeline._write_non_authoritative_json(
                    root / "binary_observability" / "latest_failure.json",
                    {"status": "failed"},
                    durable=True,
                )
                removed = binary_pipeline._delete_resume_checkpoint_durable(root)

        self.assertEqual(written.name, "validation_checkpoint.json")
        self.assertEqual(checkpoint["schema"], binary_pipeline.RESUME_CHECKPOINT_SCHEMA)
        self.assertTrue(optional)
        self.assertTrue(removed)

    def test_measurement_and_recapture_cleanup_remove_only_bound_private_state(self):
        candidate_binding = self._synthetic_performance_authority_binding(
            "candidate-cleanup",
            authority_mode=binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "candidate"
            root.mkdir(mode=0o700)
            binary_pipeline._write_resume_checkpoint(root, {
                "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
                "performance_authority_gate_binding": candidate_binding,
            })
            token = binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.set(
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY,
            )
            try:
                binary_pipeline._cleanup_performance_measurement_state(root)
            finally:
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.reset(token)
            self.assertFalse(binary_pipeline._resume_checkpoint_path(root).exists())

        recapture_binding = self._synthetic_performance_authority_binding(
            "recapture-cleanup",
            authority_mode=binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
        )
        generation_identity = "a" * 64
        activation_identity = "b" * 64
        active = {
            "schema": binary_output._ACTIVE_DESCRIPTOR_SCHEMA,
            "result_generation_identity": generation_identity,
            "generation_directory": f"binary_generations/{generation_identity}",
            "validation_run_identity": "c" * 64,
            "validation_result_sha256": "d" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = (Path(temporary) / "recapture").resolve()
            root.mkdir(mode=0o700)
            binary_output._write_active_descriptor(
                root, active, expect_missing=True,
            )
            binary_pipeline._write_resume_checkpoint(root, {
                "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
                "performance_authority_gate_binding": recapture_binding,
                "result_generation_identity": generation_identity,
                "activation_identity": activation_identity,
            })
            context_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY,
                )
            )
            root_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(root)
            )
            try:
                with patch.object(
                    binary_output,
                    "_require_generation_identity_publication_allowed",
                    return_value={
                        "authority_mode": (
                            binary_output._RELEASE_RECAPTURE_AUTHORITY_MODE
                        ),
                    },
                ):
                    binary_pipeline._cleanup_performance_recapture_state(root)
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                    root_token,
                )
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    context_token,
                )

            self.assertFalse((root / "active_binary_generation.json").exists())
            self.assertFalse(binary_pipeline._resume_checkpoint_path(root).exists())

    def test_rebind_rejects_invalid_checkpoint_content_identity_with_path_evidence(self):
        old_binding = self._synthetic_performance_authority_binding("old-binding")
        current_binding = self._synthetic_performance_authority_binding(
            "current-binding",
        )
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "performance_authority_gate_binding": old_binding,
            "checkpoint_content_identity": "0" * 64,
        }

        with self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._rebind_resume_checkpoint_performance_authority(
                Path("output"), checkpoint, current_binding,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
        )
        self.assertIn("validation_checkpoint.json", str(raised.exception))

    def test_cli_receipts_bound_mapping_failures_and_structured_error_details(self):
        class BrokenReceipt(dict):
            def __contains__(self, key):
                if key == "schema":
                    raise LookupError("receipt unavailable")
                return super().__contains__(key)

        receipt = binary_pipeline._cli_core_result_receipt(BrokenReceipt())
        self.assertEqual(
            receipt["schema"]["failure_type"], "LookupError",
        )
        self.assertEqual(
            receipt["activation_disposition"],
            "core_completed_without_active_descriptor_receipt",
        )

        payload = binary_pipeline._cli_failure_payload(
            RuntimeError('{"nested":[1,2,3]}'),
            diagnostic_root=None,
            attempt_identity="attempt-1",
        )
        self.assertEqual(payload["cause"], {"nested": [1, 2, 3]})
        self.assertEqual(payload["failure_type"], "RuntimeError")

    def _real_performance_binder_fixture(self):
        """Build a small valid byte/support pair for binder integration tests."""

        records = binary_pipeline._verify_captured_generation_sources()
        implementation = (
            binary_performance_gate._performance_implementation_protocol(
                include_runtime=False
            )
        )
        evidence = {
            "schema": "java-upgrade-analyzer.binary-first-performance-gate.v1",
            "status": "passed",
            "blocks_binary_authority_switch": False,
            "measurement_protocol": {
                "implementation": implementation,
                "source_implementation_identity": implementation[
                    "source_implementation_identity"
                ],
            },
            "recorded_measurements": {"warm_parser_invocations": 0},
            "accuracy_invariants": {"warm_parser_invocations": 0},
        }
        evidence_path = self.root / "binder-performance-gate.json"
        evidence_path.write_text(
            json.dumps(evidence, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        support = binary_pipeline._load_support_manifest_snapshot()
        support["performance_gate"] = {
            "status": "passed",
            "path": binary_pipeline.PERFORMANCE_GATE_CONTRACT_PATH,
            "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
            "warm_parser_invocations": 0,
            "blocks_binary_authority_switch": False,
        }
        return records, support, evidence_path

    def _resume_checkpoint(self, config, manifest, **overrides):
        performance_binding = overrides.pop(
            "performance_authority_gate_binding", None
        )
        support = json.loads(
            binary_pipeline.SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "status": binary_pipeline._RESUME_AWAITING_VALIDATION,
            "created_at": "2026-08-17T00:00:00+00:00",
            "config_identity": binary_pipeline._resume_config_identity(config),
            "implementation_identity": "d" * 64,
            "input_artifact_identity": (
                binary_pipeline._resume_input_artifact_identity(config)
            ),
            "source_input_identity": (
                binary_pipeline._resume_source_input_identity(config)
            ),
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
            "runtime_comparison_identity": manifest["policy_identities"][
                "runtime_comparison"
            ],
            "analysis_scope_identity": manifest["policy_identities"][
                "analysis_scope"
            ],
            "analysis_context_identity": manifest[
                "analysis_context_identity"
            ],
            "base_jdk_preflight_identity": "e" * 64,
            "current_jdk_preflight_identity": "f" * 64,
            "result_summary": self._resume_result_summary(),
            "source_inputs": {},
            "artifact_safety_policy": binary_pipeline._artifact_safety_policy(
                config, support
            ),
            "cache_metrics": {},
            "phase_timings_before_validation": [
                {"phase": phase, "elapsed_seconds": float(index + 1)}
                for index, phase in enumerate(
                    binary_pipeline._PhaseTimingRecorder.ORDER[:7]
                )
            ],
            "performance_authority_gate_binding": (
                dict(performance_binding)
                if performance_binding is not None
                else None
            ),
        }
        checkpoint.update(overrides)
        return checkpoint

    def _resume_validation_result(
        self, generation, manifest, status, **overrides
    ):
        issues = [] if status == "passed" else [{
            "domain": "direct_edge",
            "reason_code": "ORACLE_DIRECT_EDGE_MISSING",
            "evidence": {"edge": ["caller", "callee"]},
        }]
        helper_identities = (
            {"base": "e" * 64, "current": "f" * 64}
            if status == "passed" else {}
        )
        result = {
            "schema": "java-upgrade-analyzer.binary-validation-result.v1",
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
            "oracle_support_manifest_identity": (
                binary_validation_contract.oracle_support_manifest_identity()
            ),
            "truth_set_identity": "1" * 64,
            "validation_policy_version": "binary-independent-validation-v3",
            "validator_implementation_identity": (
                binary_validation_contract.validator_implementation_identity()
            ),
            "status": status,
            "issue_count": len(issues),
            "issues": issues,
            "domain_summary": (
                {} if not issues else {"direct_edge": {"issues": 1}}
            ),
            "helper_identities": helper_identities,
            "skipped_domains": [],
            "production_identity_influence": (
                "none_validation_attachment_only"
            ),
        }
        result.update(overrides)
        result["issue_set_identity"] = (
            binary_pipeline.canonical_identity_streaming(
                "binary_validation_issue_set_identity",
                result["issues"],
                schema_version="1",
            )
        )
        result["validation_run_identity"] = binary_pipeline._identity(
            "binary_validation_run_identity",
            {
                "result_generation_identity": result[
                    "result_generation_identity"
                ],
                "active_snapshot_identities": manifest[
                    "active_snapshot_identities"
                ],
                "oracle_support_manifest_identity": result[
                    "oracle_support_manifest_identity"
                ],
                "truth_set_identity": result["truth_set_identity"],
                "issue_set_identity": result["issue_set_identity"],
                "validation_policy_version": result[
                    "validation_policy_version"
                ],
                "validator_implementation_identity": result[
                    "validator_implementation_identity"
                ],
                "helper_identities": result["helper_identities"],
            },
        )
        validation_dir = generation / "validation"
        validation_dir.mkdir(exist_ok=True)
        path = validation_dir / f"{result['validation_run_identity']}.json"
        path.write_bytes(binary_pipeline._canonical_json_bytes(result))
        return {**result, "validation_result_path": str(path)}

    def test_artifact_snapshot_worker_count_is_bounded_and_exact(self):
        with patch.object(binary_pipeline.os, "cpu_count", return_value=12):
            self.assertEqual(_artifact_snapshot_worker_count(None, 20), 3)
            self.assertEqual(_artifact_snapshot_worker_count(None, 2), 2)
            self.assertEqual(_artifact_snapshot_worker_count(None, 0), 0)
        self.assertEqual(_artifact_snapshot_worker_count(8, 3), 3)
        self.assertEqual(_artifact_snapshot_worker_count("2", 20), 2)
        for value in (True, False, 0, 9, 1.5, "many"):
            with self.subTest(value=value), self.assertRaises(
                BinaryPipelineError
            ) as error:
                _artifact_snapshot_worker_count(value, 20)
            self.assertEqual(
                error.exception.reason_code,
                "BINARY_ARTIFACT_WORKER_COUNT_INVALID",
            )

    def test_cli_keeps_public_failure_trace_free_and_persists_internal_diagnostic(self):
        config = self.root / "config.json"
        config.write_text("{}", encoding="utf-8")
        result_path = self.root / "result.json"
        progress = (
            self.root / "output" / "binary_observability"
            / "latest_in_progress.json"
        )
        progress.parent.mkdir(parents=True)
        progress.write_bytes(b"\xfftruncated")
        with patch.object(
            binary_pipeline, "run_pipeline", side_effect=MemoryError("oom"),
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "output"),
                "--result-json", str(result_path),
            ])

        failure = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            failure["reason_code"], "BINARY_PIPELINE_MEMORY_EXHAUSTED"
        )
        self.assertEqual(failure["failure_type"], "MemoryError")
        self.assertNotIn("traceback", failure)
        diagnostic = json.loads((
            self.root / "output" / "binary_observability" / "latest_failure.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(diagnostic["reason_code"], failure["reason_code"])
        self.assertIn("MemoryError", diagnostic["traceback"])
        self.assertEqual(failure["last_progress"], {})

    def test_cli_failure_phase_accepts_only_this_attempt_progress(self):
        config = self.root / "attempt-config.json"
        config.write_text("{}", encoding="utf-8")
        output = self.root / "attempt-output"
        progress = output / "binary_observability" / "latest_in_progress.json"
        progress.parent.mkdir(parents=True)
        progress.write_text(json.dumps({
            "schema": "java-upgrade-analyzer.binary-progress.v1",
            "attempt_identity": "f" * 64,
            "status": "running",
            "current_phase": "validated_generation_activation",
        }), encoding="utf-8")
        result_path = self.root / "attempt-result.json"
        stderr = io.StringIO()
        with patch.object(
            binary_pipeline,
            "run_pipeline",
            side_effect=BinaryPipelineError(
                "BINARY_PIPELINE_CONFIG_SCHEMA_INVALID", "invalid"
            ),
        ), patch.object(sys, "stderr", stderr):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(output),
                "--result-json", str(result_path),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(failure["failed_phase"], "")
        self.assertEqual(failure["last_progress"], {})
        self.assertFalse(failure["progress_bound_to_attempt"])
        self.assertEqual(failure["core_transaction_status"], "failed")
        self.assertFalse(failure["core_transaction_succeeded"])
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf-8")), failure
        )

    def test_cli_failure_phase_preserves_progress_from_the_same_attempt(self):
        config = self.root / "bound-attempt-config.json"
        config.write_text("{}", encoding="utf-8")
        output = self.root / "bound-attempt-output"
        expected_attempt = hashlib.sha256(b"a" * 32).hexdigest()

        def fail_after_progress(*_args, **_kwargs):
            recorder = binary_pipeline._PhaseTimingRecorder(
                output,
                time.perf_counter(),
                attempt_identity=(
                    binary_pipeline._CLI_PROGRESS_ATTEMPT_CONTEXT.get()
                ),
            )
            recorder.start("static_preflight")
            raise BinaryPipelineError(
                "BINARY_AUTHORITY_MANIFEST_INVALID", "invalid"
            )

        stderr = io.StringIO()
        with patch.object(
            binary_pipeline.os, "urandom", return_value=b"a" * 32
        ), patch.object(
            binary_pipeline, "run_pipeline", side_effect=fail_after_progress
        ), patch.object(sys, "stderr", stderr):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(output),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(failure["attempt_identity"], expected_attempt)
        self.assertEqual(failure["failed_phase"], "static_preflight")
        self.assertTrue(failure["progress_bound_to_attempt"])
        self.assertEqual(
            failure["last_progress"]["attempt_identity"], expected_attempt
        )

    def test_cli_primary_failure_survives_result_json_sink_failure(self):
        config = self.root / "failed-sink-config.json"
        config.write_text("{}", encoding="utf-8")
        invalid_parent = self.root / "failed-sink-parent"
        invalid_parent.write_text("not-a-directory", encoding="utf-8")
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch.object(
            binary_pipeline,
            "run_pipeline",
            side_effect=BinaryPipelineError(
                "BINARY_PRIMARY_FAILURE", "primary failure detail"
            ),
        ), patch.object(sys, "stderr", stderr), patch.object(
            sys, "stdout", stdout
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "failed-sink-output"),
                "--result-json", str(invalid_parent / "result.json"),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(failure["reason_code"], "BINARY_PRIMARY_FAILURE")
        self.assertEqual(failure["detail"], "primary failure detail")
        self.assertEqual(failure["core_transaction_status"], "failed")
        self.assertFalse(failure["result_json_persisted"])
        self.assertEqual(
            failure["result_json_persist_error"]["failure_type"],
            "FileExistsError",
        )
        self.assertNotIn("traceback", failure)

    def test_cli_result_sink_failure_reports_successful_core_activation(self):
        config = self.root / "successful-sink-config.json"
        config.write_text("{}", encoding="utf-8")
        invalid_parent = self.root / "successful-sink-parent"
        invalid_parent.write_text("not-a-directory", encoding="utf-8")
        generation_identity = "a" * 64
        core_result = {
            "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
            "result_generation_identity": generation_identity,
            "validation_run_identity": "b" * 64,
            "validation_status": "passed",
            "active_generation_descriptor": str(
                self.root / "successful-sink-output"
                / "active_binary_generation.json"
            ),
        }
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch.object(
            binary_pipeline, "run_pipeline", return_value=core_result
        ), patch.object(sys, "stderr", stderr), patch.object(
            sys, "stdout", stdout
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "successful-sink-output"),
                "--result-json", str(invalid_parent / "result.json"),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            failure["reason_code"], "BINARY_PIPELINE_RESULT_PERSIST_FAILED"
        )
        self.assertEqual(failure["failed_phase"], "result_delivery")
        self.assertEqual(failure["core_transaction_status"], "succeeded")
        self.assertTrue(failure["core_transaction_succeeded"])
        self.assertFalse(failure["result_json_persisted"])
        self.assertEqual(
            failure["core_result_receipt"]["result_generation_identity"],
            generation_identity,
        )
        self.assertEqual(
            failure["core_result_receipt"]["activation_disposition"],
            "active_generation_committed",
        )
        self.assertNotIn("traceback", failure)

    def test_cli_serialization_failure_receipt_is_bounded_and_json_safe(self):
        config = self.root / "serialization-recovery-config.json"
        config.write_text("{}", encoding="utf-8")
        result_path = self.root / "serialization-recovery-result.json"
        core_result = {
            "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
            "result_generation_identity": "a" * 64,
            # Put the encoder failure inside a receipt field to prove that the
            # recovery payload does not repeat the same serialization fault.
            "active_generation_descriptor": object(),
        }
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch.object(
            binary_pipeline, "run_pipeline", return_value=core_result
        ), patch.object(sys, "stderr", stderr), patch.object(
            sys, "stdout", stdout
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "serialization-output"),
                "--result-json", str(result_path),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            failure["reason_code"],
            "BINARY_PIPELINE_RESULT_SERIALIZATION_FAILED",
        )
        self.assertEqual(failure["core_transaction_status"], "succeeded")
        self.assertEqual(
            failure["core_result_receipt"]["active_generation_descriptor"],
            {
                "value_status": "non_json_value_omitted",
                "value_type": "object",
            },
        )
        self.assertEqual(
            failure["core_result_receipt"]["activation_disposition"],
            "core_completed_without_active_descriptor_receipt",
        )
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf-8")), failure
        )

    def test_cli_failure_handles_an_exception_with_unprintable_detail(self):
        class UnprintableError(Exception):
            def __str__(self):
                raise RuntimeError("formatting failed")

        config = self.root / "unprintable-error-config.json"
        config.write_text("{}", encoding="utf-8")
        stderr = io.StringIO()
        with patch.object(
            binary_pipeline, "run_pipeline", side_effect=UnprintableError()
        ), patch.object(sys, "stderr", stderr):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "unprintable-output"),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            failure["reason_code"], "BINARY_PIPELINE_UNHANDLED_FAILURE"
        )
        self.assertIn("detail unavailable", failure["detail"])
        self.assertNotIn("traceback", failure)

    def test_cli_canonicalization_runtime_error_reaches_public_failure(self):
        config = self.root / "canonicalization-runtime-error-config.json"
        config.write_text("{}", encoding="utf-8")
        result_path = self.root / "canonicalization-runtime-error-result.json"
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch.object(
            binary_pipeline,
            "_canonical_output_root_preserving_leaf",
            side_effect=RuntimeError("symlink loop while resolving parent"),
        ), patch.object(sys, "stderr", stderr), patch.object(
            sys, "stdout", stdout
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "looped-parent" / "output"),
                "--result-json", str(result_path),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            failure["reason_code"], "BINARY_PIPELINE_UNHANDLED_FAILURE"
        )
        self.assertIn("symlink loop", failure["detail"])
        self.assertEqual(failure["last_progress"], {})
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf-8")), failure
        )

    def test_cli_unprintable_result_sink_error_does_not_mask_primary(self):
        class UnprintableSinkError(OSError):
            def __str__(self):
                raise RuntimeError("sink formatting failed")

        config = self.root / "unprintable-sink-config.json"
        config.write_text("{}", encoding="utf-8")
        stderr = io.StringIO()
        with patch.object(
            binary_pipeline,
            "run_pipeline",
            side_effect=BinaryPipelineError(
                "BINARY_PRIMARY_FAILURE", "primary detail"
            ),
        ), patch.object(
            binary_pipeline,
            "_write_text_atomic_durable",
            side_effect=UnprintableSinkError(),
        ), patch.object(sys, "stderr", stderr):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "unprintable-sink-output"),
                "--result-json", str(self.root / "unprintable-result.json"),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(failure["reason_code"], "BINARY_PRIMARY_FAILURE")
        self.assertFalse(failure["result_json_persisted"])
        self.assertEqual(
            failure["result_json_persist_error"]["failure_type"],
            "UnprintableSinkError",
        )
        self.assertIn(
            "detail unavailable",
            failure["result_json_persist_error"]["detail"],
        )

    def test_cli_checkpoint_retention_is_explicit_not_environment_authority(self):
        config = self.root / "config.json"
        config.write_text("{}", encoding="utf-8")
        output = self.root / "output"
        result_path = self.root / "result.json"
        def pipeline_result(*_args, **kwargs):
            if kwargs["retain_validation_checkpoint"]:
                return {
                    "status": "passed",
                    "validation_checkpoint_retained": True,
                    "validation_checkpoint_path": str(
                        output / "binary_observability"
                        / "validation_checkpoint.json"
                    ),
                }
            return {"status": "passed"}

        with patch.dict(
            os.environ, {"JUA_ORCHESTRATED": "1"}
        ), patch.object(
            binary_pipeline,
            "run_pipeline",
            side_effect=pipeline_result,
        ) as run:
            direct_exit = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(output),
                "--result-json", str(result_path),
            ])
            direct_result = json.loads(result_path.read_text())
            retained_exit = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(output),
                "--result-json", str(result_path),
                "--retain-validation-checkpoint",
            ])
            retained_result = json.loads(result_path.read_text())

        self.assertEqual((direct_exit, retained_exit), (0, 0))
        self.assertNotIn("validation_checkpoint_retained", direct_result)
        self.assertTrue(retained_result["validation_checkpoint_retained"])
        self.assertEqual(
            [call.kwargs["retain_validation_checkpoint"] for call in run.call_args_list],
            [False, True],
        )

    def test_optional_resume_json_failures_degrade_to_no_checkpoint(self):
        checkpoint = binary_pipeline._resume_checkpoint_path(self.root)
        checkpoint.parent.mkdir(parents=True)
        for invalid in (b'{"schema":', b"\xff\xfe"):
            with self.subTest(invalid=invalid):
                checkpoint.write_bytes(invalid)
                self.assertEqual(
                    binary_pipeline._read_resume_checkpoint(self.root), {}
                )

    def test_cli_never_invents_a_retained_checkpoint_receipt(self):
        config = self.root / "receipt-config.json"
        config.write_text("{}", encoding="utf-8")
        result_path = self.root / "receipt-result.json"
        with patch.object(
            binary_pipeline,
            "run_pipeline",
            return_value={"status": "passed"},
        ):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(self.root / "receipt-output"),
                "--result-json", str(result_path),
                "--retain-validation-checkpoint",
            ])

        result = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertNotIn("validation_checkpoint_retained", result)
        self.assertNotIn("validation_checkpoint_path", result)

    def test_retained_checkpoint_receipt_requires_matching_durable_state(self):
        output = self.root / "locked-receipt-output"
        checkpoint_path = binary_pipeline._resume_checkpoint_path(output)
        checkpoint_path.parent.mkdir(parents=True)
        generation_identity = "a" * 64
        activation_identity = "b" * 64
        binding = {"binding": "exact"}
        checkpoint_path.write_text(json.dumps({
            "status": binary_pipeline._RESUME_VALIDATION_PASSED,
            "result_generation_identity": generation_identity,
            "activation_identity": activation_identity,
            "performance_authority_gate_binding": binding,
        }), encoding="utf-8")
        pending = {
            "result_generation_identity": generation_identity,
            "activation_identity": activation_identity,
            "activation_state": "pending",
        }
        with patch.object(
            binary_pipeline,
            "read_pending_binary_generation",
            return_value=pending,
        ):
            receipt = binary_pipeline._validation_checkpoint_result_receipt(
                output,
                {"result_generation_identity": generation_identity},
                {"activation_identity": activation_identity},
                binding,
                retain_requested=True,
                candidate_discarded=False,
            )
        self.assertEqual(receipt, {
            "validation_checkpoint_retained": True,
            "validation_checkpoint_path": str(checkpoint_path),
        })

        checkpoint_path.write_text("{}\n", encoding="utf-8")
        with patch.object(
            binary_pipeline,
            "read_pending_binary_generation",
            return_value=pending,
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._validation_checkpoint_result_receipt(
                output,
                {"result_generation_identity": generation_identity},
                {"activation_identity": activation_identity},
                binding,
                retain_requested=True,
                candidate_discarded=False,
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
        )

    def test_non_retained_result_does_not_turn_cleanup_state_into_failure(self):
        output = self.root / "non-retained-pending-output"
        output.mkdir(parents=True)
        pending = {
            "result_generation_identity": "a" * 64,
            "activation_identity": "b" * 64,
            "activation_state": "pending",
        }
        with patch.object(
            binary_pipeline,
            "read_pending_binary_generation",
            return_value=pending,
        ) as read_pending:
            receipt = binary_pipeline._validation_checkpoint_result_receipt(
                output,
                {"result_generation_identity": "a" * 64},
                {"activation_identity": "b" * 64},
                {},
                retain_requested=False,
                candidate_discarded=False,
            )

        self.assertEqual(receipt, {})
        read_pending.assert_not_called()

    def test_validation_directory_is_durable_before_attachment_publish(self):
        generation = self.root / "generation"
        generation.mkdir()
        manifest = {
            "result_generation_identity": "a" * 64,
            "active_snapshot_identities": {},
        }
        events = []
        real_synchronize = binary_validation_oracle._fsync_bound_directory
        real_link = binary_validation_oracle.os.link

        def synchronize(descriptor):
            events.append("directory")
            return real_synchronize(descriptor)

        def publish(source, destination, **kwargs):
            events.append("attachment")
            return real_link(source, destination, **kwargs)

        with patch.object(
            binary_validation_oracle,
            "_fsync_bound_directory",
            side_effect=synchronize,
        ), patch.object(
            binary_validation_oracle,
            "fsync_directory",
            side_effect=lambda _path: events.append("directory") or True,
        ), patch.object(
            binary_validation_oracle.os,
            "link",
            side_effect=publish,
        ), patch.object(
            binary_validation_oracle,
            "oracle_support_manifest_identity",
            return_value="b" * 64,
        ), patch.object(
            binary_validation_oracle,
            "validator_implementation_identity",
            return_value="c" * 64,
        ):
            result = binary_validation_oracle._finalize_validation_result(
                generation,
                manifest,
                {},
                {},
                [],
                None,
            )

        self.assertEqual(events, ["directory", "attachment", "directory"])
        destination = Path(result["validation_result_path"])
        self.assertEqual(destination.parent.resolve(), (generation / "validation").resolve())
        self.assertEqual(
            destination.name,
            f"{result['validation_run_identity']}.json",
        )

    def test_validation_attachment_rejects_preexisting_symlink_directory(self):
        generation = self.root / "symlink-generation"
        external = self.root / "external-validation"
        generation.mkdir()
        external.mkdir()
        try:
            (generation / "validation").symlink_to(
                external, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")
        manifest = {
            "result_generation_identity": "a" * 64,
            "active_snapshot_identities": {},
        }

        with patch.object(
            binary_validation_oracle,
            "oracle_support_manifest_identity",
            return_value="b" * 64,
        ), patch.object(
            binary_validation_oracle,
            "validator_implementation_identity",
            return_value="c" * 64,
        ), self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._finalize_validation_result(
                generation, manifest, {}, {}, [], None
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertEqual(list(external.iterdir()), [])

    def test_validation_attachment_rejects_symlinked_generation(self):
        real_generation = self.root / "real-generation"
        linked_generation = self.root / "linked-generation"
        real_generation.mkdir()
        try:
            linked_generation.symlink_to(
                real_generation, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")

        with self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._write_validation_attachment(
                linked_generation,
                "a" * 64,
                {"value": 1},
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertFalse((real_generation / "validation").exists())

    def test_portable_validation_attachment_rejects_symlink_directory(self):
        generation = self.root / "portable-symlink-generation"
        external = self.root / "portable-external-validation"
        generation.mkdir()
        external.mkdir()
        try:
            (generation / "validation").symlink_to(
                external, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")

        with self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._write_validation_attachment_portable(
                generation,
                "a.json",
                {"value": 1},
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertEqual(list(external.iterdir()), [])

    def test_portable_validation_attachment_collision_never_overwrites(self):
        generation = self.root / "portable-collision-generation"
        validation_dir = generation / "validation"
        validation_dir.mkdir(parents=True)
        destination = validation_dir / "a.json"
        collision_bytes = b'{"concurrent":"different"}\n'
        destination.write_bytes(collision_bytes)

        with self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._write_validation_attachment_portable(
                generation,
                destination.name,
                {"value": 1},
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_IDENTITY_COLLISION",
        )
        self.assertEqual(destination.read_bytes(), collision_bytes)

    @unittest.skipUnless(
        binary_validation_oracle._secure_validation_dirfd_supported(),
        "requires no-follow dirfd filesystem operations",
    )
    def test_validation_attachment_rejects_mkdir_to_open_symlink_race(self):
        generation = self.root / "validation-race-generation"
        external = self.root / "validation-race-external"
        generation.mkdir()
        external.mkdir()
        manifest = {
            "result_generation_identity": "a" * 64,
            "active_snapshot_identities": {},
        }
        real_open = binary_validation_oracle.os.open
        swapped = False

        def swap_before_directory_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "validation" and kwargs.get("dir_fd") is not None:
                swapped = True
                (generation / "validation").rmdir()
                (generation / "validation").symlink_to(
                    external, target_is_directory=True
                )
            return real_open(path, flags, *args, **kwargs)

        with patch.object(
            binary_validation_oracle.os,
            "open",
            side_effect=swap_before_directory_open,
        ), patch.object(
            binary_validation_oracle,
            "oracle_support_manifest_identity",
            return_value="b" * 64,
        ), patch.object(
            binary_validation_oracle,
            "validator_implementation_identity",
            return_value="c" * 64,
        ), self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._finalize_validation_result(
                generation, manifest, {}, {}, [], None
            )

        self.assertTrue(swapped)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertEqual(list(external.iterdir()), [])

    @unittest.skipUnless(
        binary_validation_oracle._secure_validation_dirfd_supported(),
        "requires no-follow dirfd filesystem operations",
    )
    def test_validation_attachment_collision_race_never_overwrites(self):
        generation = self.root / "validation-collision-generation"
        generation.mkdir()
        manifest = {
            "result_generation_identity": "a" * 64,
            "active_snapshot_identities": {},
        }
        collision_bytes = b'{"concurrent":"different"}\n'
        real_link = binary_validation_oracle.os.link
        real_open = binary_validation_oracle.os.open

        def install_collision_then_link(source, destination, **kwargs):
            descriptor = real_open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=kwargs["dst_dir_fd"],
            )
            try:
                os.write(descriptor, collision_bytes)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return real_link(source, destination, **kwargs)

        with patch.object(
            binary_validation_oracle.os,
            "link",
            side_effect=install_collision_then_link,
        ), patch.object(
            binary_validation_oracle,
            "oracle_support_manifest_identity",
            return_value="b" * 64,
        ), patch.object(
            binary_validation_oracle,
            "validator_implementation_identity",
            return_value="c" * 64,
        ), self.assertRaises(
            binary_validation_oracle.BinaryValidationError
        ) as raised:
            binary_validation_oracle._finalize_validation_result(
                generation, manifest, {}, {}, [], None
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_IDENTITY_COLLISION",
        )
        attachments = list((generation / "validation").glob("*.json"))
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0].read_bytes(), collision_bytes)

    def test_phase_progress_write_failure_is_non_authoritative(self):
        timings = binary_pipeline._PhaseTimingRecorder(
            self.root / "unwritable-progress",
            binary_pipeline.time.perf_counter(),
        )
        with patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            return_value=False,
        ):
            timings.append({
                "phase": "static_preflight",
                "elapsed_seconds": 0.1,
            })

        self.assertEqual(len(timings), 1)
        self.assertEqual(timings[0]["phase"], "static_preflight")
        self.assertEqual(timings.write_failure_count, 1)

    def test_failed_phase_is_not_recorded_as_completed(self):
        output = self.root / "failed-progress"
        timings = binary_pipeline._PhaseTimingRecorder(
            output, binary_pipeline.time.perf_counter()
        )
        timings.append({
            "phase": "immutable_generation_write",
            "elapsed_seconds": 1.0,
        })
        timings.start("independent_validation")
        timings.fail({
            "phase": "independent_validation",
            "elapsed_seconds": 2.0,
            "issue_count": 25,
        })

        progress = json.loads(timings.path.read_text(encoding="utf-8"))
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(
            progress["last_completed_phase"], "immutable_generation_write"
        )
        self.assertEqual(progress["current_phase"], "independent_validation")
        self.assertEqual(
            [item["phase"] for item in progress["phases"]],
            ["immutable_generation_write"],
        )
        self.assertEqual(progress["failed_phase_timing"]["issue_count"], 25)

    def test_validation_failure_detail_points_to_all_persisted_issues(self):
        issues = [
            {
                "domain": "direct_edge",
                "reason_code": "ORACLE_DIRECT_EDGE_MISSING",
                "evidence": {"edge": [index]},
            }
            for index in range(20)
        ] + [
            {
                "domain": "direct_edge",
                "reason_code": "ORACLE_DIRECT_EDGE_EXTRA",
                "evidence": {"edge": [index]},
            }
            for index in range(20)
        ]
        detail = binary_pipeline._validation_failure_detail({
            "validation_run_identity": "validation-1",
            "validation_result_path": "/tmp/validation-1.json",
            "issue_count": len(issues),
            "domain_summary": {"direct_edge": {"issues": len(issues)}},
            "issues": issues,
        })

        self.assertEqual(detail["issue_count"], 40)
        self.assertEqual(detail["issues_preview_count"], 20)
        self.assertTrue(detail["issues_truncated"])
        self.assertEqual(detail["reason_code_counts"], {
            "ORACLE_DIRECT_EDGE_EXTRA": 20,
            "ORACLE_DIRECT_EDGE_MISSING": 20,
        })
        self.assertEqual(
            {
                issue["reason_code"] for issue in detail["issues_preview"]
            },
            {"ORACLE_DIRECT_EDGE_MISSING", "ORACLE_DIRECT_EDGE_EXTRA"},
        )
        self.assertEqual(detail["validation_run_identity"], "validation-1")
        self.assertEqual(
            detail["validation_result_path"], "/tmp/validation-1.json"
        )

    def test_validation_binds_generation_to_observed_jdk_identity(self):
        output = self.root / "validation-jdk-toctou"
        generation, manifest = self._resume_generation(output)
        config = {
            "base": {"jdk_home": str(self.root / "base-jdk")},
            "current": {"jdk_home": str(self.root / "current-jdk")},
        }

        def changed_preflight(path):
            identity = (
                "0" * 64
                if Path(path).name == "base-jdk"
                else manifest["policy_identities"][
                    "current_jdk_preflight_identity"
                ]
            )
            return {"jdk_preflight_identity": identity}

        with patch(
            "binary_validation_oracle.preflight_jdk_home",
            side_effect=changed_preflight,
        ):
            validation = validate_generation(config, generation)

        mismatches = [
            issue for issue in validation["issues"]
            if issue["reason_code"]
            == "ORACLE_GENERATION_JDK_PREFLIGHT_IDENTITY_MISMATCH"
        ]
        self.assertEqual(validation["status"], "failed")
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["evidence"]["side"], "base")
        self.assertEqual(
            mismatches[0]["evidence"]["expected_jdk_preflight_identity"],
            manifest["policy_identities"]["base_jdk_preflight_identity"],
        )
        self.assertEqual(
            mismatches[0]["evidence"]["actual_jdk_preflight_identity"],
            "0" * 64,
        )

    def test_validation_rejects_unbound_sqlite_transient_sidecar(self):
        output = self.root / "validation-sqlite-wal"
        generation, manifest = self._resume_generation(output)
        injected = generation / "base_binary_facts.sqlite-wal"
        injected.write_bytes(b"unbound-committed-state")
        config = {
            "base": {"jdk_home": str(self.root / "base-jdk")},
            "current": {"jdk_home": str(self.root / "current-jdk")},
        }

        def matching_preflight(path):
            side = "base" if Path(path).name == "base-jdk" else "current"
            return {
                "jdk_preflight_identity": manifest["policy_identities"][
                    f"{side}_jdk_preflight_identity"
                ]
            }

        with patch(
            "binary_validation_oracle.preflight_jdk_home",
            side_effect=matching_preflight,
        ):
            validation = validate_generation(config, generation)

        self.assertEqual(validation["status"], "failed")
        issues = [
            issue for issue in validation["issues"]
            if issue["reason_code"]
            == "ORACLE_GENERATION_SQLITE_TRANSIENT_SIDECAR_PRESENT"
        ]
        self.assertEqual(len(issues), 1)
        self.assertEqual(
            issues[0]["evidence"]["sidecar"],
            "base_binary_facts.sqlite-wal",
        )

    def test_validation_checkpoint_resumes_without_rebuilding_generation(self):
        output = self.root / "resume-output"
        artifact = self.root / "artifact.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        generation_identity = manifest["result_generation_identity"]
        checkpoint = self._resume_checkpoint(config, manifest)
        checkpoint["phase_timings_before_validation"][0][
            "analysis_context_identity"
        ] = "unbound-spoofed-value"
        binary_pipeline._write_resume_checkpoint(output, checkpoint)
        timings = binary_pipeline._PhaseTimingRecorder(
            output, binary_pipeline.time.perf_counter()
        )
        timings.append({
            "phase": "static_preflight",
            "elapsed_seconds": 0.01,
            "current_resume_attempt": True,
        })
        def validate_generation(_config, _generation):
            return self._resume_validation_result(
                generation, manifest, "passed"
            )
        persist_observability = binary_pipeline._write_non_authoritative_json

        def fail_final_observability(path, payload):
            if Path(path).name in {
                "latest_cache_metrics.json", "latest_phase_timings.json",
            }:
                return False
            return persist_observability(path, payload)

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline,
            "validate_generation",
            side_effect=validate_generation,
        ) as validate, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value=str(output / "active_binary_generation.json"),
        ), patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            side_effect=fail_final_observability,
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=timings,
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        self.assertTrue(result["resumed_from_generation_checkpoint"])
        self.assertEqual(
            result["result_generation_identity"], generation_identity
        )
        self.assertEqual(
            result["schema"],
            "java-upgrade-analyzer.binary-pipeline-result.v1",
        )
        self.assertEqual(result["authority"], "binary_first")
        self.assertEqual(
            result["analysis_context_identity"],
            manifest["analysis_context_identity"],
        )
        self.assertEqual(
            [item["phase"] for item in result["phase_timings"]],
            list(binary_pipeline._PhaseTimingRecorder.ORDER),
        )
        self.assertTrue(all(
            item.get("restored_from_generation_checkpoint")
            for item in result["phase_timings"][:7]
        ))
        self.assertNotIn(
            "current_resume_attempt", result["phase_timings"][0]
        )
        self.assertNotIn(
            "analysis_context_identity", result["phase_timings"][0]
        )
        validate.assert_called_once_with(config, generation.resolve())
        self.assertFalse(binary_pipeline._resume_checkpoint_path(output).exists())
        self.assertFalse(result["cache_metrics_persisted"])
        self.assertFalse(result["phase_timings_persisted"])
        self.assertFalse(Path(result["cache_metrics_path"]).exists())
        self.assertFalse(Path(result["phase_timings_path"]).exists())

    def test_resume_rebinds_only_performance_authority_and_reuses_validation(self):
        output = self.root / "resume-performance-rebind"
        artifact = self.root / "resume-performance-rebind.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        old_binding = self._synthetic_performance_authority_binding("old")
        current_binding = self._synthetic_performance_authority_binding(
            "current"
        )
        generation, manifest = (
            self._bind_resume_generation_publication_authority(
                generation, manifest, old_binding
            )
        )
        validation = self._resume_validation_result(
            generation, manifest, "passed"
        )
        validation_path = Path(validation["validation_result_path"])
        checkpoint = self._resume_checkpoint(
            config,
            manifest,
            status=binary_pipeline._RESUME_VALIDATION_PASSED,
            validation_run_identity=validation["validation_run_identity"],
            validation_result_sha256=hashlib.sha256(
                validation_path.read_bytes()
            ).hexdigest(),
            activation_identity="0" * 64,
            performance_authority_gate_binding=old_binding,
        )
        binary_pipeline._write_resume_checkpoint(output, checkpoint)
        immutable_bytes = {
            path.relative_to(generation).as_posix(): path.read_bytes()
            for path in generation.rglob("*")
            if path.is_file()
        }

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation"
        ) as validate, patch.object(
            binary_pipeline,
            "_verify_performance_authority_gate_binding",
            return_value=dict(current_binding),
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                retain_checkpoint=True,
                generation_implementation_identity="d" * 64,
                performance_authority_gate_binding=current_binding,
            )

        validate.assert_not_called()
        persisted = binary_pipeline._read_resume_checkpoint(output)
        self.assertEqual(
            persisted["performance_authority_gate_binding"], current_binding
        )
        self.assertEqual(
            persisted["checkpoint_content_identity"],
            binary_pipeline._resume_checkpoint_content_identity(persisted),
        )
        self.assertEqual(
            result["performance_authority_gate_binding"], current_binding
        )
        self.assertTrue(
            result["phase_timings"][-2]["reused_validation_attachment"]
        )
        pending = binary_output.read_pending_binary_generation(output)
        self.assertEqual(
            pending["result_generation_identity"],
            manifest["result_generation_identity"],
        )
        self.assertEqual(pending["activation_identity"], "0" * 64)
        self.assertFalse(
            (output / "active_binary_generation.json").exists()
        )
        self.assertEqual(
            {
                path.relative_to(generation).as_posix(): path.read_bytes()
                for path in generation.rglob("*")
                if path.is_file()
            },
            immutable_bytes,
        )

    def test_resume_rebind_is_durable_before_later_validation_crash(self):
        output = self.root / "resume-performance-rebind-crash"
        artifact = self.root / "resume-performance-rebind-crash.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        old_binding = self._synthetic_performance_authority_binding("old")
        current_binding = self._synthetic_performance_authority_binding(
            "current"
        )
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                performance_authority_gate_binding=old_binding,
            ),
        )
        before = binary_pipeline._read_resume_checkpoint(output)

        with patch.object(
            binary_pipeline,
            "_validate_or_reuse_checkpoint_attachment",
            side_effect=RuntimeError("crash after durable rebind"),
        ), self.assertRaisesRegex(RuntimeError, "crash after durable rebind"):
            binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                generation_implementation_identity="d" * 64,
                performance_authority_gate_binding=current_binding,
            )

        persisted = binary_pipeline._read_resume_checkpoint(output)
        expected = {
            **before,
            "performance_authority_gate_binding": current_binding,
        }
        expected["checkpoint_content_identity"] = (
            binary_pipeline._resume_checkpoint_content_identity(expected)
        )
        self.assertEqual(persisted, expected)

    def test_resume_never_rebinds_untrusted_or_incompatible_checkpoint(self):
        artifact = self.root / "resume-no-unsafe-rebind.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        old_binding = self._synthetic_performance_authority_binding("old")
        current_binding = self._synthetic_performance_authority_binding(
            "current"
        )
        cases = (
            (
                "forged-binding",
                "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                "d" * 64,
            ),
            (
                "old-schema",
                "BINARY_RESUME_CHECKPOINT_SCHEMA_MISMATCH",
                "d" * 64,
            ),
            (
                "changed-generation-implementation",
                "BINARY_RESUME_IMPLEMENTATION_CHANGED",
                "0" * 64,
            ),
        )
        for name, expected_reason, generation_implementation in cases:
            with self.subTest(name=name):
                output = self.root / f"resume-no-rebind-{name}"
                _generation, manifest = self._resume_generation(output)
                checkpoint = self._resume_checkpoint(
                    config,
                    manifest,
                    performance_authority_gate_binding=old_binding,
                )
                if name == "forged-binding":
                    checkpoint["performance_authority_gate_binding"] = {
                        **old_binding,
                        "evidence_sha256": "f" * 64,
                    }
                elif name == "old-schema":
                    checkpoint["schema"] = (
                        "java-upgrade-analyzer."
                        "binary-generation-validation-checkpoint.v2"
                    )
                binary_pipeline._write_resume_checkpoint(output, checkpoint)
                checkpoint_path = binary_pipeline._resume_checkpoint_path(
                    output
                )
                original_bytes = checkpoint_path.read_bytes()

                with patch.object(
                    binary_pipeline,
                    "_rebind_resume_checkpoint_performance_authority",
                ) as rebind, patch.object(
                    binary_pipeline, "validate_generation"
                ) as validate:
                    result = binary_pipeline._resume_generation_validation(
                        config,
                        output_root=output,
                        source_inputs={},
                        toolchain_preflight=(
                            self._resume_toolchain_preflight()
                        ),
                        asm_jar=self.asm_jar,
                        phase_timings=(
                            binary_pipeline._PhaseTimingRecorder(
                                output, binary_pipeline.time.perf_counter()
                            )
                        ),
                        pipeline_started=(
                            binary_pipeline.time.perf_counter()
                        ),
                        generation_implementation_identity=(
                            generation_implementation
                        ),
                        performance_authority_gate_binding=current_binding,
                    )

                self.assertIsNone(result)
                rebind.assert_not_called()
                validate.assert_not_called()
                self.assertEqual(checkpoint_path.read_bytes(), original_bytes)
                decision = json.loads((
                    output / "binary_observability"
                    / "latest_resume_decision.json"
                ).read_text(encoding="utf-8"))
                self.assertEqual(decision["reason_code"], expected_reason)

    def test_normal_resume_ignores_diagnostic_implementation_identity(self):
        output = self.root / "resume-normal-implementation-metadata"
        artifact = self.root / "resume-normal-implementation.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        checkpoint = self._resume_checkpoint(config, manifest)
        checkpoint["performance_authority_gate_binding"] = None
        binary_pipeline._write_resume_checkpoint(output, checkpoint)

        with patch.object(
            binary_pipeline,
            "_validate_or_reuse_checkpoint_attachment",
            side_effect=RuntimeError("resume reached validation"),
        ), self.assertRaisesRegex(RuntimeError, "resume reached validation"):
            binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                generation_implementation_identity="0" * 64,
                performance_authority_gate_binding=None,
            )

    def test_resume_reuses_deterministic_failed_validation_attachment(self):
        output = self.root / "resume-failed-validation"
        artifact = self.root / "resume-failed.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        binary_pipeline._write_resume_checkpoint(
            output, self._resume_checkpoint(config, manifest)
        )
        validation = self._resume_validation_result(
            generation, manifest, "failed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation", return_value=validation,
        ) as validate, patch.object(
            binary_pipeline, "activate_binary_generation",
        ) as activate:
            for _attempt in range(2):
                with self.assertRaises(BinaryPipelineError) as error:
                    binary_pipeline._resume_generation_validation(
                        config,
                        output_root=output,
                        source_inputs={},
                        toolchain_preflight=self._resume_toolchain_preflight(),
                        asm_jar=self.asm_jar,
                        phase_timings=binary_pipeline._PhaseTimingRecorder(
                            output, binary_pipeline.time.perf_counter()
                        ),
                        pipeline_started=binary_pipeline.time.perf_counter(),
                    )
                self.assertEqual(
                    error.exception.reason_code,
                    "BINARY_INDEPENDENT_VALIDATION_FAILED",
                )

        checkpoint = binary_pipeline._read_resume_checkpoint(output)
        # The first attempt recovers the atomically written attachment left
        # beside the still-awaiting checkpoint; the second reuses the now
        # advanced deterministic-failure checkpoint.
        self.assertEqual(validate.call_count, 0)
        activate.assert_not_called()
        self.assertEqual(
            checkpoint["status"], binary_pipeline._RESUME_VALIDATION_FAILED
        )
        self.assertEqual(
            checkpoint["validation_run_identity"],
            validation["validation_run_identity"],
        )
        self.assertRegex(checkpoint["validation_result_sha256"], r"^[0-9a-f]{64}$")

    def test_resume_revalidates_timeout_failure_attachment(self):
        output = self.root / "resume-transient-validation"
        artifact = self.root / "resume-transient.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        transient = self._resume_validation_result(
            generation,
            manifest,
            "failed",
            issues=[{
                "domain": "direct_edge",
                "reason_code": "ORACLE_JAVAP_INVENTORY_INCOMPLETE",
                "evidence": {"timed_out": True},
            }],
            issue_count=1,
            domain_summary={"direct_edge": {"issues": 1}},
        )
        transient_path = Path(transient["validation_result_path"])
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                status=binary_pipeline._RESUME_VALIDATION_FAILED,
                validation_run_identity=transient[
                    "validation_run_identity"
                ],
                validation_result_sha256=hashlib.sha256(
                    transient_path.read_bytes()
                ).hexdigest(),
            ),
        )
        recovered = self._resume_validation_result(
            generation, manifest, "passed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation", return_value=recovered,
        ) as validate, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value=str(output / "active_binary_generation.json"),
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        validate.assert_called_once_with(config, generation.resolve())
        self.assertEqual(result["result_generation_identity"], manifest[
            "result_generation_identity"
        ])
        self.assertFalse(binary_pipeline._resume_checkpoint_path(output).exists())

    def test_resume_revalidates_attachment_after_validator_only_change(self):
        output = self.root / "resume-validator-upgrade"
        artifact = self.root / "resume-validator-upgrade.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        stale = self._resume_validation_result(
            generation, manifest, "failed"
        )
        stale_path = Path(stale["validation_result_path"])
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                status=binary_pipeline._RESUME_VALIDATION_FAILED,
                validation_run_identity=stale["validation_run_identity"],
                validation_result_sha256=hashlib.sha256(
                    stale_path.read_bytes()
                ).hexdigest(),
            ),
        )
        recovered = self._resume_validation_result(
            generation, manifest, "passed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline,
            "_current_validator_implementation_identity",
            return_value="0" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation", return_value=recovered,
        ) as validate, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="active",
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        validate.assert_called_once_with(config, generation.resolve())
        self.assertTrue(
            result["phase_timings"][-2][
                "revalidated_stale_validator_attachment"
            ]
        )
        self.assertFalse(binary_pipeline._resume_checkpoint_path(output).exists())

    def test_resume_rebinds_and_revalidates_after_oracle_support_only_change(self):
        output = self.root / "resume-oracle-support-upgrade"
        artifact = self.root / "resume-oracle-support-upgrade.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        old_binding = self._synthetic_performance_authority_binding(
            "old-oracle-support"
        )
        current_binding = self._synthetic_performance_authority_binding(
            "current-oracle-support"
        )
        stale = self._resume_validation_result(
            generation, manifest, "failed"
        )
        stale_path = Path(stale["validation_result_path"])
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                status=binary_pipeline._RESUME_VALIDATION_FAILED,
                validation_run_identity=stale["validation_run_identity"],
                validation_result_sha256=hashlib.sha256(
                    stale_path.read_bytes()
                ).hexdigest(),
                performance_authority_gate_binding=old_binding,
            ),
        )
        recovered = self._resume_validation_result(
            generation, manifest, "passed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline,
            "_current_oracle_support_manifest_identity",
            return_value="0" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation", return_value=recovered,
        ) as validate, patch.object(
            binary_pipeline,
            "_activate_validated_generation_with_authority_binding",
            return_value="active",
        ), patch.object(
            binary_pipeline,
            "_validation_checkpoint_result_receipt",
            return_value={
                "validation_checkpoint_retained": True,
                "validation_checkpoint_path": str(
                    binary_pipeline._resume_checkpoint_path(output)
                ),
            },
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                retain_checkpoint=True,
                performance_authority_gate_binding=current_binding,
            )

        validate.assert_called_once_with(config, generation.resolve())
        self.assertTrue(
            result["phase_timings"][-2][
                "revalidated_stale_validator_attachment"
            ]
        )
        self.assertEqual(
            result["performance_authority_gate_binding"], current_binding
        )
        persisted = binary_pipeline._read_resume_checkpoint(output)
        self.assertEqual(
            persisted["performance_authority_gate_binding"], current_binding
        )
        self.assertEqual(
            persisted["validation_run_identity"],
            recovered["validation_run_identity"],
        )

    def test_resume_recovers_validation_written_before_checkpoint_advance(self):
        output = self.root / "resume-orphan-validation-attachment"
        artifact = self.root / "resume-orphan-validation.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        binary_pipeline._write_resume_checkpoint(
            output, self._resume_checkpoint(config, manifest)
        )
        orphan = self._resume_validation_result(
            generation, manifest, "passed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation"
        ) as validate, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="active",
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        validate.assert_not_called()
        validation_phase = result["phase_timings"][-2]
        self.assertTrue(
            validation_phase["recovered_orphan_validation_attachment"]
        )
        self.assertTrue(validation_phase["reused_validation_attachment"])
        self.assertEqual(
            result["validation_run_identity"],
            orphan["validation_run_identity"],
        )
        self.assertFalse(binary_pipeline._resume_checkpoint_path(output).exists())

    def test_resume_fails_closed_when_implementation_changes_during_validation(self):
        output = self.root / "resume-mid-validation-change"
        artifact = self.root / "resume-mid-validation-change.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        performance_binding = self._resume_performance_authority_binding()
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                performance_authority_gate_binding=performance_binding,
            ),
        )
        def validate_generation(_config, _generation):
            return self._resume_validation_result(
                generation, manifest, "passed"
            )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            side_effect=("d" * 64, "0" * 64),
        ), patch.object(
            binary_pipeline,
            "validate_generation",
            side_effect=validate_generation,
        ) as validate, patch.object(
            binary_pipeline, "activate_binary_generation",
        ) as activate, self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                performance_authority_gate_binding=performance_binding,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
        )
        validate.assert_called_once_with(config, generation.resolve())
        activate.assert_not_called()

    def test_resume_rejects_stale_or_inconsistent_failed_attachment(self):
        artifact = self.root / "resume-stale-validation.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        cases = {
            "old-policy": {
                "validation_policy_version": "binary-independent-validation-v2"
            },
            "wrong-domain-summary": {"domain_summary": {}},
            "duplicate-skipped-domain": {
                "skipped_domains": [
                    {"domain": "base", "reason_code": "NOT_RUN"},
                    {"domain": "base", "reason_code": "NOT_RUN"},
                ]
            },
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                output = self.root / f"resume-stale-{name}"
                generation, manifest = self._resume_generation(output)
                validation = self._resume_validation_result(
                    generation, manifest, "failed", **overrides
                )
                validation_path = Path(validation["validation_result_path"])
                checkpoint = self._resume_checkpoint(
                    config,
                    manifest,
                    status=binary_pipeline._RESUME_VALIDATION_FAILED,
                    validation_run_identity=validation[
                        "validation_run_identity"
                    ],
                    validation_result_sha256=hashlib.sha256(
                        validation_path.read_bytes()
                    ).hexdigest(),
                )
                binary_pipeline._write_resume_checkpoint(output, checkpoint)

                with patch.object(
                    binary_pipeline,
                    "_resume_implementation_identity",
                    return_value="d" * 64,
                ), patch.object(
                    binary_pipeline, "validate_generation"
                ) as validate:
                    with self.assertRaises(BinaryPipelineError) as error:
                        binary_pipeline._resume_generation_validation(
                            config,
                            output_root=output,
                            source_inputs={},
                            toolchain_preflight=(
                                self._resume_toolchain_preflight()
                            ),
                            asm_jar=self.asm_jar,
                            phase_timings=(
                                binary_pipeline._PhaseTimingRecorder(
                                    output,
                                    binary_pipeline.time.perf_counter(),
                                )
                            ),
                            pipeline_started=(
                                binary_pipeline.time.perf_counter()
                            ),
                        )

                validate.assert_not_called()
                self.assertEqual(
                    error.exception.reason_code,
                    "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID",
                )

    def test_resume_rejects_failed_attachment_when_jdk_preflight_changes(self):
        output = self.root / "resume-jdk-changed"
        artifact = self.root / "resume-jdk.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        validation = self._resume_validation_result(
            generation, manifest, "failed"
        )
        validation_path = Path(validation["validation_result_path"])
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config,
                manifest,
                status=binary_pipeline._RESUME_VALIDATION_FAILED,
                validation_run_identity=validation[
                    "validation_run_identity"
                ],
                validation_result_sha256=hashlib.sha256(
                    validation_path.read_bytes()
                ).hexdigest(),
            ),
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(
                    current="0" * 64
                ),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )

    def test_resume_rejects_attachment_when_source_bytes_change(self):
        output = self.root / "resume-source-changed"
        artifact = self.root / "resume-source.jar"
        artifact.write_bytes(b"artifact")
        first_root = self.root / "source-first"
        second_root = self.root / "source-second"
        first_dir = first_root / "src" / "main" / "java"
        second_dir = second_root / "src" / "main" / "java"
        first_dir.mkdir(parents=True)
        second_dir.mkdir(parents=True)
        (first_dir / "Example.java").write_text(
            "class Example { int value() { return 1; } }\n",
            encoding="utf-8",
        )
        (second_dir / "Example.java").write_text(
            "class Example { int value() { return 2; } }\n",
            encoding="utf-8",
        )

        def config_for(root, source_dir):
            return {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": {"artifacts": [{"path": str(artifact)}]},
                "current": {"artifacts": [{"path": str(artifact)}]},
                "source_overlay": {"source_sets": [{
                    "source_root": str(root),
                    "source_dirs": [str(source_dir)],
                    "owner_type": "business",
                    "owner_coord": "app",
                    "module": "app",
                    "snapshot_revision": "1" * 40,
                }]},
            }

        first_config = config_for(first_root, first_dir)
        second_config = config_for(second_root, second_dir)
        self.assertEqual(
            binary_pipeline._resume_config_identity(first_config),
            binary_pipeline._resume_config_identity(second_config),
        )
        self.assertNotEqual(
            binary_pipeline._resume_source_input_identity(first_config),
            binary_pipeline._resume_source_input_identity(second_config),
        )
        generation, manifest = self._resume_generation(output)
        validation = self._resume_validation_result(
            generation, manifest, "failed"
        )
        validation_path = Path(validation["validation_result_path"])
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                first_config,
                manifest,
                status=binary_pipeline._RESUME_VALIDATION_FAILED,
                validation_run_identity=validation[
                    "validation_run_identity"
                ],
                validation_result_sha256=hashlib.sha256(
                    validation_path.read_bytes()
                ).hexdigest(),
            ),
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                second_config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )

    def test_resume_passed_validation_retries_only_activation(self):
        output = self.root / "resume-pending-activation"
        artifact = self.root / "resume-passed.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        binary_pipeline._write_resume_checkpoint(
            output, self._resume_checkpoint(config, manifest)
        )
        def validate_generation(_config, _generation):
            return self._resume_validation_result(
                generation, manifest, "passed"
            )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline,
            "validate_generation",
            side_effect=validate_generation,
        ) as validate, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            side_effect=[RuntimeError("activation failed"), "active"],
        ) as activate:
            with self.assertRaisesRegex(RuntimeError, "activation failed"):
                binary_pipeline._resume_generation_validation(
                    config,
                    output_root=output,
                    source_inputs={},
                    toolchain_preflight=self._resume_toolchain_preflight(),
                    asm_jar=self.asm_jar,
                    phase_timings=binary_pipeline._PhaseTimingRecorder(
                        output, binary_pipeline.time.perf_counter()
                    ),
                    pipeline_started=binary_pipeline.time.perf_counter(),
                )
            checkpoint = binary_pipeline._read_resume_checkpoint(output)
            self.assertEqual(
                checkpoint["status"], binary_pipeline._RESUME_VALIDATION_PASSED
            )
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        self.assertEqual(validate.call_count, 1)
        self.assertEqual(activate.call_count, 2)
        self.assertTrue(result["resumed_from_generation_checkpoint"])
        self.assertTrue(
            result["phase_timings"][-2]["reused_validation_attachment"]
        )
        self.assertFalse(binary_pipeline._resume_checkpoint_path(output).exists())

    def test_orchestrated_resume_retains_checkpoint_until_report_commit(self):
        output = self.root / "resume-retained-for-report"
        artifact = self.root / "resume-retained.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(output)
        binary_pipeline._write_resume_checkpoint(
            output, self._resume_checkpoint(config, manifest)
        )
        validation = self._resume_validation_result(
            generation, manifest, "passed"
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation", return_value=validation,
        ), patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="active",
        ), patch.object(
            binary_pipeline,
            "_validation_checkpoint_result_receipt",
            return_value={
                "validation_checkpoint_retained": True,
                "validation_checkpoint_path": str(
                    binary_pipeline._resume_checkpoint_path(output)
                ),
            },
        ):
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                retain_checkpoint=True,
            )

        checkpoint = binary_pipeline._read_resume_checkpoint(output)
        self.assertEqual(
            checkpoint["status"], binary_pipeline._RESUME_VALIDATION_PASSED
        )
        self.assertEqual(
            checkpoint["result_generation_identity"],
            result["result_generation_identity"],
        )

    def test_resume_rejects_unbound_checkpoint_identity_early(self):
        output = self.root / "resume-unbound-metadata"
        artifact = self.root / "resume-unbound.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        checkpoint = self._resume_checkpoint(
            config,
            manifest,
            analysis_context_identity="0" * 64,
        )
        binary_pipeline._write_resume_checkpoint(output, checkpoint)

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )

    def test_resume_rejects_result_summary_reserved_field_early(self):
        output = self.root / "resume-reserved-summary"
        artifact = self.root / "resume-reserved.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        summary = self._resume_result_summary()
        summary["schema"] = "forged-schema"
        binary_pipeline._write_resume_checkpoint(
            output,
            self._resume_checkpoint(
                config, manifest, result_summary=summary
            ),
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
        )

    def test_resume_rejects_missing_required_field_before_validation(self):
        output = self.root / "resume-missing-required"
        artifact = self.root / "resume-missing-required.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        checkpoint = self._resume_checkpoint(config, manifest)
        checkpoint.pop("runtime_comparison_identity")
        binary_pipeline._write_resume_checkpoint(output, checkpoint)

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation"
        ) as validate, patch.object(
            binary_pipeline, "activate_binary_generation"
        ) as activate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        activate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
        )

    def test_resume_rejects_passed_checkpoint_without_activation_token(self):
        output = self.root / "resume-passed-without-activation-token"
        artifact = self.root / "resume-passed-without-token.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        performance_binding = self._synthetic_performance_authority_binding(
            "passed-without-activation-token"
        )
        checkpoint = self._resume_checkpoint(
            config,
            manifest,
            status=binary_pipeline._RESUME_VALIDATION_PASSED,
            validation_run_identity="4" * 64,
            validation_result_sha256="5" * 64,
            performance_authority_gate_binding=performance_binding,
        )
        binary_pipeline._write_resume_checkpoint(output, checkpoint)
        checkpoint_path = binary_pipeline._resume_checkpoint_path(output)
        original_checkpoint = checkpoint_path.read_bytes()

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(
            binary_pipeline, "validate_generation"
        ) as validate, patch.object(
            binary_pipeline, "activate_binary_generation"
        ) as activate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
                performance_authority_gate_binding=performance_binding,
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        activate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
        )
        self.assertEqual(checkpoint_path.read_bytes(), original_checkpoint)

    def test_resume_rejects_unknown_top_level_checkpoint_field(self):
        output = self.root / "resume-unknown-field"
        artifact = self.root / "resume-unknown-field.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        _generation, manifest = self._resume_generation(output)
        checkpoint = self._resume_checkpoint(config, manifest)
        checkpoint["unexpected_future_authority"] = "forged"
        binary_pipeline._write_resume_checkpoint(output, checkpoint)

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
        )

    def test_resource_metrics_failure_is_non_authoritative(self):
        with patch.object(
            binary_pipeline,
            "_resource_usage_snapshot",
            side_effect=RuntimeError("rss unavailable"),
        ):
            recorder = binary_pipeline._PhaseTimingRecorder(
                self.root / "metrics-unavailable",
                binary_pipeline.time.perf_counter(),
            )
            recorder.append({
                "phase": "static_preflight", "elapsed_seconds": 1,
            })
            peak = binary_pipeline._peak_rss_bytes()

        self.assertEqual(peak, 0)
        self.assertEqual(recorder[0]["peak_rss_bytes"], 0)
        self.assertEqual(recorder[0]["process_tree_cpu_seconds"], 0.0)

    def test_invalid_resume_manifest_is_rejected_without_raising(self):
        output = self.root / "resume-invalid-manifest"
        artifact = self.root / "invalid-manifest-artifact.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation_identity = "b" * 64
        generation = output / "binary_generations" / generation_identity
        generation.mkdir(parents=True)
        (generation / "result_generation.json").write_bytes(b'{"schema":')
        binary_pipeline._write_resume_checkpoint(output, {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "config_identity": binary_pipeline._resume_config_identity(config),
            "implementation_identity": "implementation-1",
            "input_artifact_identity": (
                binary_pipeline._resume_input_artifact_identity(config)
            ),
            "result_generation_identity": generation_identity,
        })
        timings = binary_pipeline._PhaseTimingRecorder(
            output, binary_pipeline.time.perf_counter()
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="implementation-1",
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=timings,
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_GENERATION_MANIFEST_INVALID",
        )

    def test_resume_rejects_generation_missing_required_sidecar_declaration(self):
        output = self.root / "resume-missing-sidecar"
        artifact = self.root / "resume-missing-sidecar.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        generation, manifest = self._resume_generation(
            output, omitted_sidecar="binary_pairings.json"
        )
        binary_pipeline._write_resume_checkpoint(
            output, self._resume_checkpoint(config, manifest)
        )

        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="d" * 64,
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=binary_pipeline._PhaseTimingRecorder(
                    output, binary_pipeline.time.perf_counter()
                ),
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_GENERATION_INTEGRITY_INVALID",
        )
        self.assertFalse(generation.exists())

    def test_validation_checkpoint_is_rejected_when_config_changes(self):
        output = self.root / "resume-rejected"
        output.mkdir()
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "config_identity": "old-config",
            "implementation_identity": "implementation-1",
            "result_generation_identity": "generation-1",
        }
        binary_pipeline._write_resume_checkpoint(output, checkpoint)
        timings = binary_pipeline._PhaseTimingRecorder(
            output, binary_pipeline.time.perf_counter()
        )
        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="implementation-1",
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                {"schema": "changed"},
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=timings,
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(decision["reason_code"], "BINARY_RESUME_CONFIG_CHANGED")

    def test_validation_checkpoint_rejects_invalid_generation_identity(self):
        output = self.root / "resume-invalid-generation"
        artifact = self.root / "resume-artifact.jar"
        artifact.write_bytes(b"artifact")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"artifacts": [{"path": str(artifact)}]},
            "current": {"artifacts": [{"path": str(artifact)}]},
        }
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "config_identity": binary_pipeline._resume_config_identity(config),
            "implementation_identity": "implementation-1",
            "input_artifact_identity": (
                binary_pipeline._resume_input_artifact_identity(config)
            ),
            "result_generation_identity": "../../outside",
        }
        binary_pipeline._write_resume_checkpoint(output, checkpoint)
        timings = binary_pipeline._PhaseTimingRecorder(
            output, binary_pipeline.time.perf_counter()
        )
        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            return_value="implementation-1",
        ), patch.object(binary_pipeline, "validate_generation") as validate:
            result = binary_pipeline._resume_generation_validation(
                config,
                output_root=output,
                source_inputs={},
                toolchain_preflight=self._resume_toolchain_preflight(),
                asm_jar=self.asm_jar,
                phase_timings=timings,
                pipeline_started=binary_pipeline.time.perf_counter(),
            )

        decision = json.loads((
            output / "binary_observability" / "latest_resume_decision.json"
        ).read_text(encoding="utf-8"))
        self.assertIsNone(result)
        validate.assert_not_called()
        self.assertEqual(
            decision["reason_code"],
            "BINARY_RESUME_GENERATION_IDENTITY_INVALID",
        )

    def test_resume_config_identity_ignores_only_regenerated_source_root(self):
        first = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_overlay": {"source_sets": [{
                "source_root": "/tmp/worktree-a/app",
                "source_dirs": ["/tmp/worktree-a/app/src/main/java"],
                "owner_type": "business",
                "owner_coord": "app",
                "module": "app",
                "snapshot_revision": "a" * 40,
            }]},
        }
        second = json.loads(json.dumps(first))
        second["source_overlay"]["source_sets"][0].update({
            "source_root": "/tmp/worktree-b/app",
            "source_dirs": ["/tmp/worktree-b/app/src/main/java"],
        })

        self.assertEqual(
            binary_pipeline._resume_config_identity(first),
            binary_pipeline._resume_config_identity(second),
        )
        second["source_overlay"]["source_sets"][0][
            "snapshot_revision"
        ] = "b" * 40
        self.assertNotEqual(
            binary_pipeline._resume_config_identity(first),
            binary_pipeline._resume_config_identity(second),
        )

    def test_resume_generation_identity_scope_excludes_only_post_generation_code(self):
        baseline = binary_pipeline._resume_implementation_identity(self.asm_jar)
        real_sha256 = binary_pipeline._sha256_file

        def identity_with_changed_source(source_name):
            def changed(path):
                if Path(path).name == source_name:
                    return "0" * 64
                return real_sha256(Path(path))

            with patch.object(
                binary_pipeline, "_sha256_file", side_effect=changed
            ):
                return binary_pipeline._resume_implementation_identity(
                    self.asm_jar
                )

        for post_generation_source in (
            "binary_validation_contract.py",
            "binary_validation_oracle.py",
            "edge_truth.py",
            "final_artifact_edge_oracle.py",
            "gate.py",
            "RuntimeOutcomeOracle.java",
            "binary_report.py",
            "binary_performance_gate.py",
            "performance_gate.json",
            "run_step.py",
            "s6_report.py",
        ):
            with self.subTest(source=post_generation_source):
                self.assertEqual(
                    identity_with_changed_source(post_generation_source),
                    baseline,
                )
        self.assertNotEqual(
            identity_with_changed_source("binary_trace_engine.py"), baseline
        )
        self.assertNotEqual(
            identity_with_changed_source("javap_contract.py"), baseline
        )

        support = json.loads(
            binary_pipeline.SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        oracle_only = json.loads(json.dumps(support))
        oracle_only["oracle_support_manifest"][
            "final_artifact_edge_oracle_procedure_version"
        ] = "oracle-only-change"
        self.assertEqual(
            binary_pipeline._generation_support_manifest_identity(oracle_only),
            binary_pipeline._generation_support_manifest_identity(support),
        )
        performance_only = json.loads(json.dumps(support))
        performance_only["performance_gate"]["sha256"] = "0" * 64
        performance_only["performance_gate"][
            "dataset"
        ] = "new performance evidence metadata"
        self.assertEqual(
            binary_pipeline._generation_support_manifest_identity(
                performance_only
            ),
            binary_pipeline._generation_support_manifest_identity(support),
        )
        production_change = json.loads(json.dumps(support))
        production_change["artifact_diff_support_manifest"][
            "parser_contract"
        ]["visitor_policy_version"] = "production-change"
        self.assertNotEqual(
            binary_pipeline._generation_support_manifest_identity(
                production_change
            ),
            binary_pipeline._generation_support_manifest_identity(support),
        )
        with patch.object(
            binary_pipeline,
            "_generation_support_manifest_identity",
            return_value="0" * 64,
        ):
            self.assertNotEqual(
                binary_pipeline._resume_implementation_identity(self.asm_jar),
                baseline,
            )
        with patch.object(
            binary_pipeline,
            "_generation_runtime_identity",
            return_value="0" * 64,
        ):
            self.assertNotEqual(
                binary_pipeline._resume_implementation_identity(self.asm_jar),
                baseline,
            )

    def test_generation_source_allowlist_and_local_import_closure_are_explicit(self):
        self.assertEqual(
            binary_pipeline._GENERATION_IMPLEMENTATION_SOURCE_PATHS,
            (
                "artifact_safety.py",
                "binary_artifact_diff.py",
                "binary_asm_helper.py",
                "binary_decision_engine.py",
                "binary_definition_verifier.py",
                "binary_entrypoint_discovery.py",
                "binary_fact_store.py",
                "binary_first_contract.py",
                "binary_first_model.py",
                "binary_output.py",
                "binary_pipeline.py",
                "binary_platform_image.py",
                "binary_runtime_reconciler.py",
                "binary_semantic_overlay.py",
                "binary_snapshot_cache.py",
                "binary_source_overlay.py",
                "binary_tool_execution.py",
                "binary_trace_engine.py",
                "compat.py",
                "csv_io.py",
                "enhanced_source_analyzer.py",
                "jdk_preflight.py",
                "javap_contract.py",
                "path_runtime.py",
                "safe_xml.py",
                "signature_utils.py",
                "streaming_json.py",
                "java/BinaryFactExtractor.java",
                "java/ClassDefinitionVerifier.java",
            ),
        )
        binary_pipeline._validate_generation_source_import_closure()
        real_imports = binary_pipeline._local_python_imports

        def imports_with_unclassified_dependency(path):
            imported = real_imports(Path(path))
            if Path(path).name == "binary_trace_engine.py":
                imported.add("s1_dep_diff")
            return imported

        with patch.object(
            binary_pipeline,
            "_local_python_imports",
            side_effect=imports_with_unclassified_dependency,
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._validate_generation_source_import_closure()
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_GENERATION_SOURCE_IMPORT_CLOSURE_INVALID",
        )

    def test_local_import_cache_is_bound_to_exact_source_bytes(self):
        binary_pipeline._local_python_imports_from_exact_bytes.cache_clear()
        with tempfile.TemporaryDirectory() as temp_text:
            source = Path(temp_text) / "fixture.py"
            source.write_text("import json\n", encoding="utf-8")
            with patch.object(
                binary_pipeline.ast,
                "parse",
                wraps=binary_pipeline.ast.parse,
            ) as parse:
                self.assertEqual(
                    binary_pipeline._local_python_imports(source), {"json"}
                )
                self.assertEqual(
                    binary_pipeline._local_python_imports(source), {"json"}
                )
                source.write_text("import sqlite3\n", encoding="utf-8")
                self.assertEqual(
                    binary_pipeline._local_python_imports(source), {"sqlite3"}
                )
        self.assertEqual(parse.call_count, 2)
        binary_pipeline._local_python_imports_from_exact_bytes.cache_clear()

    def test_generation_runtime_identity_is_stable_and_fails_closed(self):
        pins = binary_pipeline._runtime_requirement_pins(
            binary_pipeline.RUNTIME_REQUIREMENTS_PATH.read_bytes()
        )
        first = binary_pipeline._generation_runtime_identity(pins)
        second = binary_pipeline._generation_runtime_identity(pins)
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

        with patch.object(
            binary_pipeline,
            "_stable_runtime_file_record",
            side_effect=OSError("runtime file replaced"),
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._generation_runtime_identity(pins)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
        )

    def test_loaded_generation_code_cannot_be_relabeled_after_disk_change(self):
        binary_pipeline._captured_resume_generation_source_records()
        real_sha256 = binary_pipeline._sha256_file

        for changed_name in ("binary_trace_engine.py",):
            with self.subTest(source=changed_name), patch.object(
                binary_pipeline,
                "_sha256_file",
                side_effect=lambda path, name=changed_name: (
                    "0" * 64
                    if Path(path).name == name
                    else real_sha256(Path(path))
                ),
            ), self.assertRaises(BinaryPipelineError) as raised:
                binary_pipeline._verify_captured_generation_sources()
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
            )
        with patch.object(
            binary_pipeline,
            "_generation_support_manifest_identity",
            return_value="0" * 64,
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._verify_captured_generation_sources()
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_structural_oracle_preserves_array_type_instruction_targets(self):
        parsed = _parse_javap_structural(
            """
public class demo.ArrayCasts {
  java.lang.String[] cast(java.lang.Object);
    descriptor: (Ljava/lang/Object;)[Ljava/lang/String;
    Code:
       0: aload_1
       1: checkcast     #7                  // class \"[Ljava/lang/String;\"
       4: areturn
  java.lang.Class literal();
    descriptor: ()Ljava/lang/Class;
    Code:
       0: ldc           #9                  // class \"[I\"
       2: areturn
}
"""
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "cast", "(Ljava/lang/Object;)[Ljava/lang/String;",
                1, "[Ljava/lang/String;", "checkcast",
            ),
            parsed["type_edges"],
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "method", "cast",
                "(Ljava/lang/Object;)[Ljava/lang/String;", 0,
            ),
            parsed["declared_members"],
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "literal", "()Ljava/lang/Class;",
                0, "[I", "class_literal",
            ),
            parsed["type_edges"],
        )

    def test_runtime_oracle_resolves_object_array_component_and_skips_primitives(self):
        contexts = _oracle_runtime_contexts(
            {
                "java/lang/String": {
                    "status": "definition_ready",
                    "provider_url": "jrt:/java.base/java/lang/String.class",
                    "super_name": "",
                    "interfaces": [],
                },
            },
            ["[I", "[B", "[Ljava/lang/String;", "[[Ljava/lang/String;"],
            ["application-loader"],
            "platform-loader",
        )
        self.assertEqual(
            contexts,
            (("application-loader", "java/lang/String"),),
        )

    def test_runtime_oracle_keeps_provider_selection_separate_from_definition(self):
        self.assertEqual(
            _provider_resource_path(
                "jar:file:/tmp/runtime.jar!/optional/Type.class"
            ),
            Path("/tmp/runtime.jar").resolve(),
        )
        self.assertIsNone(
            _provider_resource_path(
                "jrt:/java.base/java/lang/String.class"
            )
        )

    def test_runtime_oracle_recognizes_only_bound_jdk8_platform_archives(self):
        jdk8 = self.root / "jdk8"
        runtime_lib = jdk8 / "jre" / "lib"
        extension = runtime_lib / "ext" / "provider.jar"
        nested_extension = runtime_lib / "ext" / "nested" / "provider.jar"
        zip_extension = runtime_lib / "ext" / "provider.zip"
        classes = jdk8 / "jre" / "classes" / "vendor" / "Override.class"
        application = self.root / "application.jar"
        for path in (
            runtime_lib / "rt.jar",
            extension,
            nested_extension,
            zip_extension,
            classes,
            application,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")

        self.assertTrue(
            _is_bound_jdk8_platform_path(runtime_lib / "rt.jar", jdk8)
        )
        self.assertTrue(_is_bound_jdk8_platform_path(extension, jdk8))
        self.assertFalse(
            _is_bound_jdk8_platform_path(nested_extension, jdk8)
        )
        self.assertFalse(_is_bound_jdk8_platform_path(zip_extension, jdk8))
        self.assertTrue(_is_bound_jdk8_platform_path(classes, jdk8))
        self.assertFalse(_is_bound_jdk8_platform_path(application, jdk8))

    def test_runtime_oracle_applies_object_fallback_for_interface_methods(self):
        observations = {
            "demo/Api": {
                "status": "definition_ready", "modifiers": 0x0601,
                "members": [], "super_name": "", "interfaces": [],
            },
            "java/lang/Object": {
                "status": "definition_ready", "modifiers": 0x0001,
                "members": [
                    "method|getClass|()Ljava/lang/Class;|273",
                    "method|clone|()Ljava/lang/Object;|260",
                ],
                "super_name": "", "interfaces": [],
            },
        }
        resolved = _resolve_member(
            observations, "demo/Api", "method", "getClass",
            "()Ljava/lang/Class;",
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], "java/lang/Object")
        self.assertIsNone(_resolve_member(
            observations, "demo/Api", "method", "clone",
            "()Ljava/lang/Object;",
        ))

    def test_runtime_oracle_uses_javap_member_when_optional_member_linkage_failed(self):
        observations = {
            "demo/OptionalApi": {
                "status": "definition_failed",
                "failure_phase": "member_linkage",
                "modifiers": 0x0401,
                "super_name": "java/lang/Object",
                "interfaces": [],
                "members": [],
                "javap_declared_members": ["method|available|()V|1"],
            }
        }
        resolved = _resolve_member(
            observations, "demo/OptionalApi", "method", "available", "()V"
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], "demo/OptionalApi")

    def test_runtime_oracle_deduplicates_reflection_and_javap_member_views(self):
        observation = {
            "members": ["method|run|([Ljava/lang/String;)V|129"],
            "javap_declared_members": ["method|run|([Ljava/lang/String;)V|1"],
        }
        self.assertEqual(
            _declared_members(observation),
            [("method", "run", "([Ljava/lang/String;)V", 129)],
        )

    def test_runtime_oracle_uses_code_source_for_non_base_jdk_modules(self):
        self.assertEqual(
            _oracle_provider_location({
                "provider_resource_url": "",
                "provider_url": "jrt:/jdk.jdi",
                "status": "definition_ready",
            }),
            "jrt:/jdk.jdi",
        )
        self.assertEqual(
            _oracle_provider_location({
                "provider_resource_url": "jrt:/java.base/java/lang/String.class",
                "provider_url": "",
            }),
            "jrt:/java.base/java/lang/String.class",
        )

    def test_source_inputs_are_derived_from_actual_source_sets(self):
        self.assertEqual(
            _source_inputs_contract({}),
            {
                "purpose_version": "source-input-purpose-v3",
                "business": {"status": "not_provided", "origin": "not_provided"},
                "dependencies": {"status": "not_provided", "origin": "not_provided"},
            },
        )

    def test_source_input_metadata_cannot_hide_an_available_overlay(self):
        config = {
            "source_inputs": {
                "business": {"status": "not_provided"},
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": ["/not/read"],
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        with self.assertRaises(BinaryPipelineError) as raised:
            _source_inputs_contract(config)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_BUSINESS_SOURCE_STATUS_MISMATCH",
        )

    def test_source_input_contract_rejects_stale_purpose_version(self):
        with self.assertRaises(BinaryPipelineError) as raised:
            _source_inputs_contract({
                "source_inputs": {
                    "purpose_version": "source-input-purpose-v2",
                },
            })

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_SOURCE_INPUT_PURPOSE_VERSION_MISMATCH",
        )

    def _static_preflight_config(self, artifact):
        side = {
            "jdk_home": "/jdk/not-needed-for-static-preflight",
            "artifacts": [{
                "path": str(artifact),
                "logical_location": "lib/app.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 0,
                "lineage": "app",
                "runtime_code_source_origin_identity": "deployment-app",
            }],
        }
        return {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": json.loads(json.dumps(side)),
            "current": json.loads(json.dumps(side)),
        }

    def test_static_config_errors_fail_before_jdk_preflight(self):
        artifact = self.root / "static-preflight.jar"
        artifact.write_bytes(b"not-read-by-static-preflight")
        cases = (
            (
                {"tool_execution_policy": {"unknown": 1}},
                "BINARY_ORACLE_TOOL_POLICY_INVALID",
            ),
            (
                {"max_trace_nodes": "many"},
                "BINARY_PIPELINE_TRACE_LIMIT_INVALID",
            ),
            (
                {"max_paths_per_target": False},
                "BINARY_PIPELINE_TRACE_LIMIT_INVALID",
            ),
            (
                {"artifact_snapshot_workers": 0},
                "BINARY_ARTIFACT_WORKER_COUNT_INVALID",
            ),
            (
                {"artifact_hash_workers": 9},
                "BINARY_ARTIFACT_HASH_WORKER_COUNT_INVALID",
            ),
            (
                {"artifact_safety_limits": {"unknown": 1}},
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            ),
            (
                {"artifact_safety_limits": []},
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            ),
            (
                {"runtime_capability_policy": {"unknown": 1}},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"runtime_capability_policy": []},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"runtime_capability_policy": {
                    "supported_delegation_modes": ["parent_first", "child_first"]
                }},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"runtime_capability_policy": {
                    "supported_transformer_profile_identities": ["unverified-agent"]
                }},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"runtime_capability_policy": {"signed_artifacts_supported": True}},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"runtime_capability_policy": {
                    "policy_version": "caller-self-certified-v999"
                }},
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            ),
            (
                {"source_inputs": []},
                "BINARY_SOURCE_INPUTS_INVALID",
            ),
        )
        for index, (override, reason_code) in enumerate(cases):
            config = self._static_preflight_config(artifact)
            config.update(override)
            with self.subTest(reason_code=reason_code), patch.object(
                binary_pipeline, "preflight_jdk_home"
            ) as jdk_preflight:
                with self.assertRaises(BinaryFirstContractError) as raised:
                    run_pipeline(
                        config,
                        output_root=self.root / f"static-output-{index}",
                    )
                self.assertEqual(raised.exception.reason_code, reason_code)
                jdk_preflight.assert_not_called()

    def test_runtime_capability_policy_can_only_restrict_release_support(self):
        artifact = self.root / "capability-restriction.jar"
        artifact.write_bytes(b"not-read-by-static-preflight")
        config = self._static_preflight_config(artifact)
        config["runtime_capability_policy"] = {
            "supported_delegation_modes": [],
            "closed_world_dispatch": False,
        }

        result = binary_pipeline._static_pipeline_preflight(config)

        capability = result["runtime_capability_policy"]
        self.assertEqual(capability.supported_delegation_modes, ())
        self.assertFalse(capability.closed_world_dispatch)
        self.assertEqual(
            capability.policy_version, "binary-runtime-capability-v2"
        )

    def test_static_preflight_does_not_gate_analysis_on_release_metadata(self):
        artifact = self.root / "authority-switch.jar"
        artifact.write_bytes(b"not-read-by-static-preflight")
        config = self._static_preflight_config(artifact)
        support = json.loads(
            binary_pipeline.SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        support["runtime_loader_support_manifest"][
            "authoritative_runtime_effective_decisions_allowed"
        ] = False
        support["class_definition_support_manifest"][
            "definition_ready_claims_allowed"
        ] = False
        support["oracle_support_manifest"][
            "production_binary_authority_switch_allowed"
        ] = False
        support["performance_gate"] = {"status": "failed"}

        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=support,
        ), patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            side_effect=AssertionError("normal analysis read performance gate"),
        ):
            result = binary_pipeline._static_pipeline_preflight(config)

        self.assertIsNone(result["performance_authority_gate_binding"])

    def test_performance_authority_uses_one_evidence_byte_snapshot(self):
        records, support, evidence_path = self._real_performance_binder_fixture()
        real_read_bytes = Path.read_bytes
        evidence_reads = []

        def observed_read_bytes(path):
            path = Path(path)
            if path == binary_pipeline.PERFORMANCE_GATE_PATH:
                evidence_reads.append(path)
                if len(evidence_reads) > 1:
                    raise AssertionError("performance evidence was read twice")
            return real_read_bytes(path)

        with patch.object(
            binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
        ), patch.object(
            binary_performance_gate,
            "evaluate_recorded_gate",
            return_value={"status": "passed", "issues": []},
        ), patch.object(
            Path, "read_bytes", autospec=True, side_effect=observed_read_bytes
        ):
            binding = binary_pipeline._performance_authority_gate_binding(
                support, generation_source_records=records,
            )

        self.assertEqual(len(evidence_reads), 1)
        self.assertRegex(binding["binding_identity"], r"^[0-9a-f]{64}$")

    def test_performance_authority_change_before_activation_fails_closed(self):
        records, support, evidence_path = self._real_performance_binder_fixture()
        evaluator_patch = patch.object(
            binary_performance_gate,
            "evaluate_recorded_gate",
            return_value={"status": "passed", "issues": []},
        )
        path_patch = patch.object(
            binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
        )
        evaluator_patch.start()
        path_patch.start()
        self.addCleanup(evaluator_patch.stop)
        self.addCleanup(path_patch.stop)
        captured = binary_pipeline._performance_authority_gate_binding(
            support, generation_source_records=records,
        )
        changed_support = json.loads(json.dumps(support))
        changed_support["performance_gate"]["status"] = "failed"

        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=changed_support,
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._verify_performance_authority_gate_binding(
                captured
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
        )

        real_read_bytes = Path.read_bytes

        def changed_evidence_bytes(path):
            content = real_read_bytes(Path(path))
            if Path(path) == binary_pipeline.PERFORMANCE_GATE_PATH:
                return content + b" "
            return content

        with patch.object(
            Path,
            "read_bytes",
            autospec=True,
            side_effect=changed_evidence_bytes,
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._verify_performance_authority_gate_binding(
                captured
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
        )

    def test_activation_helper_defers_live_gate_check_to_output_boundary(self):
        captured = self._synthetic_performance_authority_binding(
            "activation-gate-change"
        )
        gate_error = BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
            "changed",
        )
        with patch.object(
            binary_pipeline,
            "_verify_performance_authority_gate_binding",
            side_effect=gate_error,
        ) as verify, patch.object(
            binary_pipeline,
            "read_binary_generation_publication_authority_binding",
            return_value=dict(captured),
        ), patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="uncommitted-activation",
        ) as activate:
            active_path = binary_pipeline._activate_validated_generation_with_authority_binding(
                self.root,
                {},
                {},
                activation_identity="a" * 64,
                activation_record={},
                defer_publication=False,
                performance_authority_gate_binding=captured,
            )
            self.assertEqual(active_path, "uncommitted-activation")
            # Pipeline only constructs the callback value.  binary_output owns
            # the independent live verification immediately before its
            # descriptor commit, so hashing it here would be duplicate work.
            verify.assert_not_called()
            publication_guard = activate.call_args.kwargs[
                "publication_guard"
            ]
            self.assertEqual(publication_guard(), captured)
            verify.assert_not_called()

    def test_live_authority_verifier_reuses_its_fresh_generation_records(self):
        captured = self._synthetic_performance_authority_binding(
            "live-authority-record-reuse"
        )
        support = {"schema": "fresh-support-snapshot"}
        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=support,
        ), patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            return_value=dict(captured),
        ) as derive:
            self.assertEqual(
                binary_pipeline._verify_performance_authority_gate_binding(
                    captured
                ),
                captured,
            )

        derive.assert_called_once_with(
            support,
            reuse_verified_generation_records_for_runtime=True,
        )

    def test_activation_helper_installs_commit_boundary_authority_guard(self):
        captured = self._synthetic_performance_authority_binding(
            "activation-commit-boundary"
        )
        generation_identity = "b" * 64
        with patch.object(
            binary_pipeline,
            "_verify_performance_authority_gate_binding",
            return_value=dict(captured),
        ) as verify, patch.object(
            binary_pipeline,
            "read_binary_generation_publication_authority_binding",
            return_value=dict(captured),
        ) as read_generation_binding, patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="active.json",
        ) as activate:
            active_path = (
                binary_pipeline
                ._activate_validated_generation_with_authority_binding(
                    self.root,
                    {"result_generation_identity": generation_identity},
                    {},
                    activation_identity="a" * 64,
                    activation_record={},
                    defer_publication=False,
                    performance_authority_gate_binding=captured,
                )
            )
            self.assertEqual(active_path, "active.json")
            verify.assert_not_called()
            publication_guard = activate.call_args.kwargs.get(
                "publication_guard"
            )
            self.assertTrue(callable(publication_guard))
            publication_guard()
            verify.assert_not_called()
            read_generation_binding.assert_called_once_with(
                self.root, generation_identity
            )

    def test_runtime_profile_shape_errors_fail_before_jdk_preflight(self):
        artifact = self.root / "profile-static-preflight.jar"
        artifact.write_bytes(b"not-read-by-static-preflight")
        cases = {
            "profile": [],
            "business_entrypoint_profile": {
                "business_entrypoint_profile": []
            },
            "resolved_configuration_properties": {
                "resolved_configuration_properties": []
            },
            "entrypoint_methods": {
                "business_entrypoint_profile": {"methods": ["not-object"]}
            },
            "loader_realms": {"loader_topology": {"realms": {}}},
            "field_coverage": {"field_coverage": []},
        }
        for field in (
            "activated_frameworks",
            "activated_classes",
            "activated_entity_classes",
            "activated_resource_names",
            "activated_component_scan_packages",
            "coverage_gaps",
        ):
            cases[f"business_{field}"] = {
                "business_entrypoint_profile": {field: "not-a-list"}
            }
        for name, profile in cases.items():
            config = self._static_preflight_config(artifact)
            config["base"]["runtime_profile"] = profile
            with self.subTest(name=name), patch.object(
                binary_pipeline, "preflight_jdk_home"
            ) as jdk_preflight, self.assertRaises(
                BinaryPipelineError
            ) as raised:
                run_pipeline(
                    config,
                    output_root=self.root / f"profile-static-{name}",
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
            )
            jdk_preflight.assert_not_called()

    def test_output_storage_fails_before_jdk_preflight(self):
        output = self.root / "output-is-a-file"
        output.write_bytes(b"occupied")
        with patch.object(
            binary_pipeline, "preflight_jdk_home"
        ) as jdk_preflight, self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=output,
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
        )
        jdk_preflight.assert_not_called()

    def test_output_root_leaf_symlinks_fail_without_touching_external_target(self):
        for dangling in (False, True):
            with self.subTest(dangling=dangling):
                output = self.root / f"linked-output-{dangling}"
                external = self.root / f"external-output-{dangling}"
                sentinel_path = external / "sentinel.txt"
                if not dangling:
                    external.mkdir()
                    sentinel_path.write_text("unchanged", encoding="utf-8")
                try:
                    output.symlink_to(external, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")

                with patch.object(
                    binary_pipeline, "preflight_jdk_home"
                ) as jdk_preflight, self.assertRaises(
                    BinaryPipelineError
                ) as raised:
                    run_pipeline(
                        {
                            "schema": (
                                "java-upgrade-analyzer."
                                "binary-pipeline-input.v1"
                            )
                        },
                        output_root=output,
                    )

                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                )
                jdk_preflight.assert_not_called()
                self.assertTrue(output.is_symlink())
                self.assertFalse((external / ".binary-pipeline-run.lock").exists())
                if dangling:
                    self.assertFalse(external.exists())
                else:
                    self.assertEqual(
                        sentinel_path.read_text(encoding="utf-8"), "unchanged"
                    )
                    self.assertEqual(
                        sorted(path.name for path in external.iterdir()),
                        ["sentinel.txt"],
                    )

    def test_symlinked_observability_directory_fails_before_jdk_preflight_without_escape(self):
        output = self.root / "linked-observability-output"
        output.mkdir()
        outside = self.root / "linked-observability-outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        try:
            (output / "binary_observability").symlink_to(
                outside, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")

        with patch.object(
            binary_pipeline, "preflight_jdk_home"
        ) as jdk_preflight, self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=output,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
        )
        jdk_preflight.assert_not_called()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(
            sorted(path.name for path in outside.iterdir()),
            ["sentinel.txt"],
        )

    def test_cli_failure_diagnostic_never_follows_symlinked_observability(self):
        output = self.root / "cli-linked-observability-output"
        output.mkdir()
        outside = self.root / "cli-linked-observability-outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        try:
            (output / "binary_observability").symlink_to(
                outside, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")
        config = self.root / "cli-linked-observability-config.json"
        config.write_text(json.dumps({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        }), encoding="utf-8")
        result_path = self.root / "cli-linked-observability-result.json"
        stderr = io.StringIO()

        with patch.object(sys, "stderr", stderr):
            exit_code = binary_pipeline.main([
                "--config", str(config),
                "--output-root", str(output),
                "--result-json", str(result_path),
            ])

        failure = json.loads(stderr.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            failure["reason_code"],
            "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
        )
        self.assertEqual(
            json.loads(result_path.read_text(encoding="utf-8")), failure
        )
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(
            sorted(path.name for path in outside.iterdir()),
            ["sentinel.txt"],
        )

    def test_cli_failure_report_never_resolves_unsafe_output_root_leaf(self):
        config_path = self.root / "unsafe-output-config.json"
        config_path.write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1"
            }),
            encoding="utf-8",
        )
        for dangling in (False, True):
            with self.subTest(dangling=dangling):
                output = self.root / f"cli-linked-output-{dangling}"
                external = self.root / f"cli-external-output-{dangling}"
                sentinel_path = external / "sentinel.txt"
                if not dangling:
                    external.mkdir()
                    sentinel_path.write_text("unchanged", encoding="utf-8")
                try:
                    output.symlink_to(external, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")
                result_path = self.root / f"cli-unsafe-result-{dangling}.json"

                exit_code = binary_pipeline.main([
                    "--config", str(config_path),
                    "--output-root", str(output),
                    "--result-json", str(result_path),
                ])

                failure = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertEqual(exit_code, 1)
                self.assertEqual(
                    failure["reason_code"],
                    "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                )
                self.assertEqual(failure["last_progress"], {})
                self.assertTrue(output.is_symlink())
                if dangling:
                    self.assertFalse(external.exists())
                else:
                    self.assertEqual(
                        sentinel_path.read_text(encoding="utf-8"), "unchanged"
                    )
                    self.assertEqual(
                        sorted(path.name for path in external.iterdir()),
                        ["sentinel.txt"],
                    )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO files are unavailable")
    def test_special_output_root_fails_as_storage_before_jdk_preflight(self):
        output = self.root / "output-is-a-fifo"
        os.mkfifo(output)
        with patch.object(
            binary_pipeline, "preflight_jdk_home"
        ) as jdk_preflight, self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=output,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
        )
        jdk_preflight.assert_not_called()

    def test_output_root_allows_symlinked_ancestor_but_not_leaf(self):
        physical_parent = self.root / "physical-output-parent"
        physical_parent.mkdir()
        linked_parent = self.root / "linked-output-parent"
        try:
            linked_parent.symlink_to(
                physical_parent, target_is_directory=True
            )
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")
        output = linked_parent / "physical-output-leaf"
        expected = physical_parent.resolve() / "physical-output-leaf"

        with patch.object(
            binary_pipeline,
            "_run_pipeline_under_lock",
            return_value={"status": "entered"},
        ) as body:
            result = run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=output,
            )

        self.assertEqual(result, {"status": "entered"})
        self.assertTrue(expected.is_dir())
        self.assertFalse(expected.is_symlink())
        body.assert_called_once_with(
            {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
            output_root=expected,
            retain_validation_checkpoint=False,
        )

    def test_output_probe_cleanup_failure_fails_before_jdk_preflight(self):
        output = self.root / "probe-cleanup-failure"
        real_unlink = binary_pipeline._unlink_missing_ok

        def reject_probe_unlink(path):
            path = Path(path)
            if path.name.startswith(".binary-output-probe."):
                raise OSError("probe cannot be removed")
            return real_unlink(path)

        with patch.object(
            binary_pipeline,
            "_unlink_missing_ok",
            side_effect=reject_probe_unlink,
        ), patch.object(
            binary_pipeline, "preflight_jdk_home"
        ) as jdk_preflight, self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=output,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
        )
        self.assertIn("probe cannot be removed", str(raised.exception))
        jdk_preflight.assert_not_called()

    def test_output_probe_cleanup_does_not_mask_primary_storage_failure(self):
        output = self.root / "probe-primary-failure"
        write_failure = OSError("probe write failed")
        with patch.object(
            binary_pipeline,
            "_write_text_atomic_durable",
            side_effect=write_failure,
        ), patch.object(
            binary_pipeline,
            "_unlink_missing_ok",
            side_effect=OSError("probe cleanup failed"),
        ), self.assertRaises(BinaryPipelineError) as raised:
            binary_pipeline._preflight_output_root(output)

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
        )
        self.assertIs(raised.exception.__cause__, write_failure)
        self.assertTrue(any(
            "probe cleanup failed" in note
            for note in getattr(raised.exception, "__notes__", ())
        ))

    def test_jvm_argument_contract_fails_before_asm_and_platform_image(self):
        artifact = self.root / "malformed-jvm-arguments.jar"
        artifact.write_bytes(b"not-read-before-jvm-contract")
        config = self._static_preflight_config(artifact)
        config["base"]["runtime_profile"] = {
            "runtime_jvm_arguments": "-Dunterminated='value",
        }
        observed = {
            "jdk_preflight_identity": "a" * 64,
            "java_major": 21,
        }
        with patch.object(
            binary_pipeline, "preflight_jdk_home", return_value=observed
        ) as jdk_preflight, patch.object(
            binary_pipeline, "resolve_asm_jar"
        ) as resolve_asm, patch.object(
            binary_pipeline, "JdkPlatformImage"
        ) as platform:
            with self.assertRaises(BinaryPipelineError) as raised:
                run_pipeline(config, output_root=self.root / "jvm-args-output")
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_JVM_ARGUMENTS_INVALID",
        )
        jdk_preflight.assert_not_called()
        resolve_asm.assert_not_called()
        platform.assert_not_called()

    def test_static_preflight_failure_overwrites_stale_phase_progress(self):
        artifact = self.root / "preflight-progress.jar"
        artifact.write_bytes(b"not-read-before-jdk-preflight")
        config = self._static_preflight_config(artifact)
        output = self.root / "preflight-progress-output"
        progress = output / "binary_observability" / "latest_in_progress.json"
        progress.parent.mkdir(parents=True)
        progress.write_text(json.dumps({
            "schema": "java-upgrade-analyzer.binary-progress.v1",
            "status": "completed",
            "current_phase": "validated_generation_activation",
        }), encoding="utf-8")
        with patch.object(
            binary_pipeline,
            "preflight_jdk_home",
            side_effect=BinaryPipelineError("SENTINEL_PREFLIGHT_FAILURE", ""),
        ), self.assertRaises(BinaryPipelineError):
            run_pipeline(config, output_root=output)
        recorded = json.loads(progress.read_text(encoding="utf-8"))
        self.assertEqual(recorded["status"], "running")
        self.assertEqual(recorded["current_phase"], "static_preflight")
        self.assertEqual(recorded["last_completed_phase"], "")

    def _jar(
        self, side, value, *, service_provider=None, manifest=None,
        uses_system_out=False,
    ):
        source = self.root / side / "src" / "demo" / "Api.java"
        source.parent.mkdir(parents=True)
        statement = 'System.out.print(""); ' if uses_system_out else ""
        source.write_text(
            f"package demo; public class Api {{ public int value(){{ {statement}return {value}; }} }}",
            encoding="utf-8",
        )
        classes = self.root / side / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar = self.root / side / "api.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.write(classes / "demo" / "Api.class", "demo/Api.class")
            if manifest is not None:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
            if service_provider:
                archive.writestr(
                    "META-INF/services/demo.Service", f"{service_provider}\n"
                )
        return jar

    def _compile_sources_jar(self, label, sources, *, classpath=()):
        source_root = self.root / label / "src"
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / label / "classes"
        classes.mkdir(parents=True)
        command = ["javac", "-g"]
        if classpath:
            command.extend(["-cp", os.pathsep.join(map(str, classpath))])
        command.extend(["-d", str(classes), *map(str, paths)])
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar = self.root / label / f"{label}.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        return jar

    def _pre_java8_mr_jar(self, label, base_value, ignored_value):
        base = self._jar(f"{label}-base", base_value)
        ignored = self._jar(f"{label}-ignored", ignored_value)
        artifact = self.root / label / f"{label}.jar"
        artifact.parent.mkdir(parents=True)
        with zipfile.ZipFile(base) as base_archive, zipfile.ZipFile(
            ignored
        ) as ignored_archive, zipfile.ZipFile(artifact, "w") as output:
            output.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
            )
            output.writestr(
                "demo/Api.class", base_archive.read("demo/Api.class")
            )
            output.writestr(
                "META-INF/versions/7/demo/Api.class",
                ignored_archive.read("demo/Api.class"),
            )
            output.writestr(
                "META-INF/versions/07/demo/Api.class",
                ignored_archive.read("demo/Api.class"),
            )
            output.writestr(
                "META-INF/versions/9/demo//Api.class",
                ignored_archive.read("demo/Api.class"),
            )
        return artifact

    def _side(self, jar, version="1"):
        return {
            "jdk_home": str(self.home),
            "artifacts": [{
                "path": str(jar),
                "logical_location": "lib/api.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 0,
                "coord": f"com.acme:api:{version}",
                "lineage": "com.acme:api",
                "runtime_code_source_origin_identity": "deployment-api",
            }],
            "runtime_profile": {
                "container_and_launcher_kind": "java-classpath",
                "loader_topology": {
                    "coverage_status": "complete",
                    "entrypoint_realms": ["application-loader"],
                    "realms": [
                        {
                            "identity": "platform-loader",
                            "kind": "platform",
                            "delegation": "parent_first",
                            "module_mode": "named-platform",
                        },
                        {
                            "identity": "application-loader",
                            "kind": "application",
                            "parent": "platform-loader",
                            "delegation": "parent_first",
                            "module_mode": "unnamed",
                        },
                    ],
                },
                "runtime_security_and_package_sealing_policy_identity": (
                    "standard-unsealed-unsigned-v1"
                ),
                "active_profile_identities": ["default"],
                "external_config_snapshot_identities": [],
                "agent_transformer_plugin_profile_identities": [],
                "business_entrypoint_profile": {
                    "coverage_status": "complete",
                    "methods": [{
                        "initiating_loader_realm_identity": "application-loader",
                        "class_name": "demo/Api",
                        "member_name": "value",
                        "descriptor": "()I",
                    }],
                },
                "runtime_class_closure_coverage_status": "complete",
                "resource_selection_coverage_status": "complete",
            },
        }

    def test_unsupported_outer_security_completes_as_non_authoritative(self):
        base = self._jar("unsupported-security-base", 1)
        current = self._jar("unsupported-security-current", 2)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
        }
        for side in (config["base"], config["current"]):
            profile = side["runtime_profile"]
            profile[
                "runtime_security_and_package_sealing_policy_identity"
            ] = "unsupported-outer-signed-or-sealed-v1"
            profile["runtime_configuration_coverage_status"] = "partial"
            profile["runtime_configuration_coverage_gaps"] = [
                "outer_runtime_security_unsupported:signature_entry:META-INF/APP.RSA"
            ]
            profile["resource_selection_coverage_status"] = "partial"

        result = run_pipeline(
            config,
            output_root=self.root / "unsupported-security-output",
        )
        verification = json.loads(
            (
                Path(result["generation_directory"])
                / "binary_definition_verification.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(result["validation_status"], "passed")
        for side in ("base", "current"):
            summary = verification[side]
            self.assertGreater(
                summary["definition_status_counts"].get("security_failed", 0),
                0,
            )
            self.assertTrue(any(
                item["reason"] == "runtime_security_policy_unsupported"
                for item in summary["failure_samples"]
            ))

    def test_identical_sides_share_indexes_and_reuse_semantic_preflight(self):
        artifact = self._jar("identical-shared-runtime", 1)
        side = self._side(artifact, "1")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side,
            "current": json.loads(json.dumps(side)),
        }
        real_engine = binary_pipeline.BinaryDecisionEngine
        real_preflight = (
            binary_pipeline.semantic_overlay_requires_runtime_selection
        )
        observed = {}

        def capture_engine(**kwargs):
            engine = real_engine(**kwargs)
            observed["shared_runtime_evidence"] = kwargs.get(
                "shared_runtime_evidence"
            )
            observed["compact_indexes_shared"] = all((
                engine._base_providers is engine._current_providers,
                engine._base_definitions is engine._current_definitions,
                engine._base_resources is engine._current_resources,
            ))
            return engine

        with patch.object(
            binary_pipeline,
            "BinaryDecisionEngine",
            side_effect=capture_engine,
        ), patch.object(
            binary_pipeline,
            "semantic_overlay_requires_runtime_selection",
            wraps=real_preflight,
        ) as preflight, patch.object(
            binary_semantic_overlay,
            "semantic_overlay_requires_runtime_selection",
            side_effect=AssertionError("semantic preflight recomputed"),
        ):
            result = run_pipeline(
                config,
                output_root=self.root / "identical-shared-runtime-output",
            )

        self.assertEqual(result["validation_status"], "passed")
        self.assertIs(observed["shared_runtime_evidence"], True)
        self.assertTrue(observed["compact_indexes_shared"])
        self.assertEqual(preflight.call_count, 1)

    def test_semantic_overlay_preflight_override_preserves_default_contract(self):
        store = Mock()
        profile = Mock(identity="runtime-profile")
        reconciliation = Mock(identity="runtime-reconciliation")
        with patch.object(
            binary_semantic_overlay,
            "semantic_overlay_requires_runtime_selection",
            return_value=False,
        ) as preflight:
            overlay = binary_semantic_overlay.build_binary_semantic_overlay(
                store, profile, reconciliation
            )

        preflight.assert_called_once_with(store, None)
        self.assertEqual(overlay.rows, ())
        self.assertEqual(overlay.coverage_status, "complete")

        with self.assertRaises(BinaryFirstContractError) as raised:
            binary_semantic_overlay.build_binary_semantic_overlay(
                store,
                profile,
                reconciliation,
                runtime_selection_required=1,
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_SEMANTIC_RUNTIME_SELECTION_PRECHECK_INVALID",
        )

    def test_spring_data_hierarchy_fast_path_matches_forced_full_builder(self):
        executed_sql = []
        empty_cursor = Mock()
        empty_cursor.fetchone.return_value = None
        store = Mock()
        store.runtime_trigger_summary.return_value = {
            "has_runtime_annotations": False,
            "hierarchy_types": frozenset({
                "org/springframework/data/jpa/repository/JpaRepository",
            }),
            "has_main_method": False,
        }
        store.connection.execute.side_effect = (
            lambda sql: executed_sql.append(sql) or empty_cursor
        )
        profile = Mock(identity="runtime-profile")
        reconciliation = Mock(identity="runtime-reconciliation")
        expected = Mock()

        with patch.object(
            binary_semantic_overlay,
            "hydrate_runtime_reconciliation",
            return_value=reconciliation,
        ), patch.object(binary_semantic_overlay, "_Builder") as builder:
            builder.return_value.build.return_value = expected
            default_result = (
                binary_semantic_overlay.build_binary_semantic_overlay(
                    store, profile, reconciliation
                )
            )
            forced_result = (
                binary_semantic_overlay.build_binary_semantic_overlay(
                    store,
                    profile,
                    reconciliation,
                    runtime_selection_required=True,
                )
            )

        self.assertIs(default_result, expected)
        self.assertIs(forced_result, expected)
        self.assertEqual(builder.call_count, 2)
        direct_edge_query = next(
            sql for sql in executed_sql if "FROM direct_edges" in sql
        )
        self.assertIn("symbolic_owner GLOB 'org/springframework/*'", direct_edge_query)
        self.assertNotIn("symbolic_owner LIKE", direct_edge_query)

    def test_second_fact_store_open_failure_closes_first_store(self):
        artifact = self._jar("second-store-open-failure", 1)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(artifact),
            "current": self._side(artifact),
        }
        base_store = Mock()
        with patch.object(
            binary_pipeline,
            "BinaryFactStore",
            side_effect=[base_store, RuntimeError("current store open failed")],
        ), self.assertRaisesRegex(RuntimeError, "current store open failed"):
            run_pipeline(
                config,
                output_root=self.root / "second-store-open-failure-output",
            )

        base_store.close.assert_called_once_with()

    def test_second_store_open_failure_is_not_masked_by_close_failure(self):
        artifact = self._jar("second-store-primary-preservation", 1)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(artifact),
            "current": self._side(artifact),
        }
        primary = RuntimeError("current store open primary")
        base_store = Mock()
        base_store.close.side_effect = OSError("base store cleanup")
        with patch.object(
            binary_pipeline,
            "BinaryFactStore",
            side_effect=[base_store, primary],
        ):
            with self.assertRaises(RuntimeError) as caught:
                run_pipeline(
                    config,
                    output_root=self.root / "store-primary-preservation-output",
                )

        self.assertIs(caught.exception, primary)
        base_store.close.assert_called_once_with()
        self.assertTrue(any(
            "base store cleanup" in note
            for note in getattr(primary, "__notes__", ())
        ))

    def test_cleanup_attempts_every_resource_and_raises_first_without_primary(self):
        first = Mock(side_effect=OSError("first close"))
        second = Mock(side_effect=OSError("second close"))
        with self.assertRaisesRegex(OSError, "first close") as caught:
            binary_pipeline._attempt_cleanups(
                (("first resource", first), ("second resource", second)),
                primary=None,
            )

        first.assert_called_once_with()
        second.assert_called_once_with()
        self.assertTrue(any(
            "second close" in note
            for note in getattr(caught.exception, "__notes__", ())
        ))

    def test_normal_generation_does_not_hash_implementation_sources(self):
        base = self._jar("mid-run-implementation-base", 1)
        current = self._jar("mid-run-implementation-current", 2)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        output = self.root / "mid-run-implementation-output"
        with patch.object(
            binary_pipeline,
            "_resume_implementation_identity",
            side_effect=AssertionError("implementation hash must not run"),
        ), patch.object(
            binary_pipeline,
            "_resume_generation_source_records",
            side_effect=AssertionError("source snapshot must not run"),
        ):
            result = run_pipeline(config, output_root=output)

        self.assertEqual(
            result["validation_status"],
            "passed",
        )
        self.assertTrue((output / "active_binary_generation.json").is_file())

    def test_direct_config_multi_release_switches_fail_closed(self):
        platform = type("Platform", (), {
            "identity": "platform-identity",
            "java_major": 21,
            "release": {
                "IMPLEMENTOR": "fixture",
                "JAVA_VERSION": "21",
                "OS_NAME": "fixture-os",
                "OS_ARCH": "fixture-arch",
            },
        })()

        rejected = (
            (
                {
                    "jvm_system_properties": {
                        "jdk.util.jar.enableMultiRelease": "false"
                    },
                    "runtime_profile": {},
                },
                "BINARY_PIPELINE_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
            ),
            (
                {
                    "runtime_profile": {
                        "known_jvm_arguments": [
                            "-Djdk.util.jar.version=17"
                        ]
                    }
                },
                "BINARY_PIPELINE_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
            ),
            (
                {
                    "jvm_arguments": "-Xmx256m 'unterminated",
                    "runtime_profile": {},
                },
                "BINARY_PIPELINE_JVM_ARGUMENTS_INVALID",
            ),
            (
                {
                    "runtime_profile": {
                        "loader_topology": {
                            "multi_release_jar_runtime_policy": {
                                "policy_identity": (
                                    "openjdk-jarfile-default-properties-v1"
                                ),
                                "target_runtime_feature": 21,
                                "jdk.util.jar.enableMultiRelease": "force",
                                "jdk.util.jar.version": (
                                    "target-runtime-feature"
                                ),
                                "non_default_behavior": "fail_closed",
                            }
                        }
                    }
                },
                "BINARY_PIPELINE_MULTI_RELEASE_POLICY_UNSUPPORTED",
            ),
        )
        for side_config, reason_code in rejected:
            with self.subTest(reason_code=reason_code):
                with self.assertRaises(BinaryPipelineError) as raised:
                    binary_pipeline._runtime_profile(
                        side_config, platform, []
                    )
                self.assertEqual(raised.exception.reason_code, reason_code)

        jar = self._jar("direct-default-mr-policy", 1)
        side = self._side(jar)
        side["jvm_system_properties"] = {
            "jdk.util.jar.enableMultiRelease": " true "
        }
        side["runtime_profile"]["loader_topology"][
            "multi_release_jar_runtime_policy"
        ] = {
            "policy_identity": "openjdk-jarfile-default-properties-v1",
            "target_runtime_feature": 21,
            "jdk.util.jar.enableMultiRelease": "true",
            "jdk.util.jar.version": "target-runtime-feature",
            "non_default_behavior": "fail_closed",
        }
        profile = binary_pipeline._runtime_profile(side, platform, [])
        self.assertEqual(
            profile.payload["loader_topology"]
            ["multi_release_jar_runtime_policy"]["policy_identity"],
            "openjdk-jarfile-default-properties-v1",
        )

    def test_direct_edge_failure_skips_expensive_runtime_validation(self):
        base = self._jar("fail-fast-base", 1)
        current = self._jar("fail-fast-current", 2)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(
            config, output_root=self.root / "fail-fast-report"
        )
        generation = Path(result["generation_directory"])
        database = generation / "current_binary_facts.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "DELETE FROM direct_edges WHERE rowid = "
                "(SELECT rowid FROM direct_edges LIMIT 1)"
            )
            connection.commit()
        finally:
            connection.close()
        manifest_path = generation / "result_generation.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sidecar_content_identities"][database.name] = hashlib.sha256(
            database.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with patch(
            "binary_validation_oracle._observe_classes",
            side_effect=AssertionError("runtime Oracle must be skipped"),
        ), patch(
            "binary_validation_oracle._expected_result_generation_identity",
            return_value=manifest["result_generation_identity"],
        ):
            validation = validate_generation(config, generation)

        self.assertEqual(validation["status"], "failed")
        self.assertIn(
            "ORACLE_DIRECT_EDGE_MISSING",
            {item["reason_code"] for item in validation["issues"]},
        )
        self.assertIn(
            {
                "domain": "entrypoint_discovery",
                "reason_code": "FOUNDATIONAL_VALIDATION_FAILED",
            },
            validation["skipped_domains"],
        )

    def test_changed_api_with_complete_empty_entrypoints_uses_empty_closed_world(self):
        base = self._jar("empty-roots-base", 1)
        current = self._jar("empty-roots-current", 2)
        base_side = self._side(base, "1")
        current_side = self._side(current, "2")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config, output_root=self.root / "empty-roots-report"
        )
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        coverage = json.loads(
            (generation / "binary_coverage.json").read_text(encoding="utf-8")
        )

        self.assertTrue(formal["results"])
        self.assertEqual(
            {item["reachability_status"] for item in formal["results"]},
            {"not_found_in_static_analysis"},
        )
        self.assertTrue(all(not item["paths"] for item in formal["results"]))
        self.assertEqual(
            coverage["batch_graph_stats"]["graph_materialization_status"],
            "not_required_empty_root_set",
        )
        self.assertEqual(result["validation_status"], "passed")

    def test_two_dependency_pairings_with_same_resource_delta_remain_distinct(self):
        def resource_jar(label, content):
            path = self.root / label / f"{label}.jar"
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META-INF/LICENSE", content)
            return path

        base_jar = resource_jar("shared-resource-base", b"old-license")
        current_jar = resource_jar("shared-resource-current", b"new-license")

        def side(path, version):
            result = self._side(path, version)
            result["artifacts"] = [
                {
                    "path": str(path),
                    "logical_location": f"lib/dependency-{suffix}.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "classpath",
                    "slot": index,
                    "coord": f"com.acme:dependency-{suffix}:{version}",
                    "lineage": f"com.acme:dependency-{suffix}",
                    "runtime_code_source_origin_identity": (
                        f"deployment-dependency-{suffix}"
                    ),
                }
                for index, suffix in enumerate(("a", "b"))
            ]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [],
            }
            return result

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_jar, "1"),
            "current": side(current_jar, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "same-resource-two-pairings-report")

        decisions = json.loads(
            (Path(result["generation_directory"]) / "binary_decisions.json")
            .read_text(encoding="utf-8")
        )
        raw_resource_decisions = [
            row for row in decisions["excluded_decisions"]
            if row["reason_code"]
            == "ARTIFACT_RESOURCE_OBSERVATION_RECONCILED_BY_SELECTION_VIEW"
        ]
        self.assertEqual(len(raw_resource_decisions), 2)
        self.assertEqual(len({
            row["disposition_obligation_identity"]
            for row in raw_resource_decisions
        }), 2)
        self.assertEqual({
            artifact["logical_dependency_lineage"]
            for row in raw_resource_decisions
            for artifact in row["dependency_artifacts"]
        }, {"com.acme:dependency-a", "com.acme:dependency-b"})
        self.assertEqual(result["validation_status"], "passed")

    def test_trace_preserves_independent_entrypoint_paths_for_one_changed_api(self):
        def target(label, value):
            return self._compile_sources_jar(label, {
                "lib/Api.java": (
                    "package lib; public class Api { public int changed() { "
                    f"return {value}; }} }}"
                ),
            })

        base_target = target("multi-path-base", 1)
        current_target = target("multi-path-current", 2)
        business = self._compile_sources_jar("multi-path-business", {
            "biz/Shared.java": (
                "package biz; public class Shared { public int call() { "
                "return new lib.Api().changed(); } }"
            ),
            "biz/First.java": (
                "package biz; public class First { public int run() { "
                "return new Shared().call(); } }"
            ),
            "biz/Second.java": (
                "package biz; public class Second { public int run() { "
                "return new Shared().call(); } }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business),
                "logical_location": "app/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes",
                "slot": 0,
                "coord": "com.acme:application:1",
                "lineage": "com.acme:application",
                "runtime_code_source_origin_identity": "multi-path-business",
            }, {
                "path": str(target_jar),
                "logical_location": "lib/target.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 1,
                "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "multi-path-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": class_name,
                    "member_name": "run",
                    "descriptor": "()I",
                } for class_name in ("biz/First", "biz/Second")],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "multi-path-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal
            if item["display_owner"] == "lib/Api"
            and item["display_member"] == "changed"
        )
        self.assertTrue(changed["path_set_complete"])
        self.assertEqual(len(changed["paths"]), 2)
        self.assertEqual(
            {
                path["path_text"].split(" → ", 1)[0]
                for path in changed["paths"]
            },
            {"biz.First.run()", "biz.Second.run()"},
        )

    def test_path_budget_does_not_hide_exact_or_downgrade_unrelated_result(self):
        def target(label, changed_value, unused_value):
            return self._compile_sources_jar(label, {
                "lib/Api.java": (
                    "package lib; public class Api { "
                    f"public int changed() {{ return {changed_value}; }} "
                    f"public int unused() {{ return {unused_value}; }} }}"
                ),
            })

        base_target = target("path-budget-base", 1, 10)
        current_target = target("path-budget-current", 2, 20)
        method_names = [f"run{index:02d}" for index in range(21)]
        business = self._compile_sources_jar("path-budget-business", {
            "biz/Entrypoints.java": (
                "package biz; public class Entrypoints { "
                + " ".join(
                    f"public int {name}() {{ return new lib.Api().changed(); }}"
                    for name in method_names
                )
                + " }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business),
                "logical_location": "app/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes",
                "slot": 0,
                "coord": "com.acme:application:1",
                "lineage": "com.acme:application",
                "runtime_code_source_origin_identity": "path-budget-business",
            }, {
                "path": str(target_jar),
                "logical_location": "lib/target.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 1,
                "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "path-budget-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entrypoints",
                    "member_name": name,
                    "descriptor": "()I",
                } for name in method_names],
            }
            return result

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "path-budget-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal if item["display_member"] == "changed"
        )
        unused = next(
            item for item in formal if item["display_member"] == "unused"
        )
        self.assertEqual(changed["reachability_status"], "reachable")
        self.assertTrue(changed["exact_path_exists"])
        self.assertFalse(changed["path_set_complete"])
        self.assertEqual(len(changed["paths"]), 20)
        self.assertEqual(
            unused["reachability_status"], "not_found_in_static_analysis"
        )
        self.assertTrue(unused["path_set_complete"])

    def _automatic_scheduled_entry_fixture(self, *, include_activation_resource=True):
        def compile_core(label, value):
            source = self.root / label / "src" / "api" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                f"package api; public class Api {{ public int value() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "core.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "api" / "Api.class", "api/Api.class")
            return jar

        base_core = compile_core("scheduled-core-base", 1)
        current_core = compile_core("scheduled-core-current", 2)
        scheduler_root = self.root / "scheduler-entry"
        scheduler_sources = scheduler_root / "src"
        source_files = {
            "org/springframework/scheduling/annotation/Scheduled.java": """
                package org.springframework.scheduling.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface Scheduled { long fixedDelay() default 0; }
            """,
            "org/springframework/boot/autoconfigure/AutoConfiguration.java": """
                package org.springframework.boot.autoconfigure;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface AutoConfiguration {}
            """,
            "org/springframework/boot/SpringApplication.java": """
                package org.springframework.boot;
                public final class SpringApplication {
                    private SpringApplication() {}
                    public static Object run(Class<?> type, String[] args) {
                        return null;
                    }
                }
            """,
            "vendor/ScheduledConfig.java": """
                package vendor;
                import api.Api;
                import org.springframework.boot.autoconfigure.AutoConfiguration;
                import org.springframework.scheduling.annotation.Scheduled;
                @AutoConfiguration
                public class ScheduledConfig {
                    @Scheduled(fixedDelay = 1000)
                    public int tick() { return new Api().value(); }
                }
            """,
        }
        scheduler_paths = []
        for relative, content in source_files.items():
            source = scheduler_sources / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(content, encoding="utf-8")
            scheduler_paths.append(source)
        scheduler_classes = scheduler_root / "classes"
        scheduler_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(base_core), "-d", str(scheduler_classes),
                *map(str, scheduler_paths),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        scheduler_jar = scheduler_root / "scheduler.jar"
        with zipfile.ZipFile(scheduler_jar, "w") as archive:
            for class_file in sorted(scheduler_classes.rglob("*.class")):
                archive.write(
                    class_file,
                    class_file.relative_to(scheduler_classes).as_posix(),
                )
            if include_activation_resource:
                archive.writestr(
                    "META-INF/spring/"
                    "org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                    "vendor.ScheduledConfig\n",
                )
        app_source = self.root / "scheduled-app" / "src" / "biz" / "Application.java"
        app_source.parent.mkdir(parents=True)
        app_source.write_text(
            "package biz; import org.springframework.boot.SpringApplication; "
            "public class Application { public static void main(String[] args) { "
            "SpringApplication.run(Application.class, args); } }",
            encoding="utf-8",
        )
        app_classes = self.root / "scheduled-app" / "classes"
        app_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(scheduler_jar),
                "-d", str(app_classes), str(app_source),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        app_jar = self.root / "scheduled-app" / "app.jar"
        with zipfile.ZipFile(app_jar, "w") as archive:
            archive.write(
                app_classes / "biz" / "Application.class",
                "biz/Application.class",
            )
        return base_core, current_core, scheduler_jar, app_jar

    def _automatic_entry_side(self, core, scheduler, app, version):
        side = self._side(core, version)
        side["artifacts"] = [
            {
                "path": str(app), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "deployment-business",
            },
            {
                "path": str(scheduler), "logical_location": "lib/scheduler.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": "com.acme:scheduler:1.0",
                "lineage": "com.acme:scheduler",
                "runtime_code_source_origin_identity": "deployment-scheduler",
            },
            {
                "path": str(core), "logical_location": "lib/core.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 2, "coord": f"com.acme:core:{version}",
                "lineage": "com.acme:core",
                "runtime_code_source_origin_identity": "deployment-core",
            },
        ]
        side["runtime_profile"]["business_entrypoint_profile"] = {
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "main_class": "biz.Application",
            "methods": [],
        }
        return side

    def test_dependency_scheduled_auto_configuration_is_reachable_without_manual_entrypoint(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture()
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._automatic_entry_side(base_core, scheduler, app, "1.0"),
            "current": self._automatic_entry_side(current_core, scheduler, app, "2.0"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "scheduled-report")
        generation = Path(result["generation_directory"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        self.assertTrue(formal["by_api"], formal)
        matching_targets = [
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        ]
        self.assertEqual(
            len(matching_targets), 1,
            [
                (item.get("display_owner"), item.get("display_member"))
                for item in formal["by_api"]
            ],
        )
        target = matching_targets[0]
        entrypoint_path = generation / "binary_entrypoints.json"
        entrypoints = json.loads(entrypoint_path.read_text())

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(target["paths"][0]["entry_kinds"], ["spring_scheduled"])
        self.assertEqual(
            target["paths"][0]["entry_kind_labels"], ["Spring 定时任务"]
        )
        self.assertEqual(
            target["paths"][0]["entrypoint_dependency_coords"],
            ["com.acme:scheduler:1.0"],
        )
        scheduled = next(
            item for item in entrypoints["records"]
            if item["entry_kind"] == "spring_scheduled"
        )
        self.assertEqual(scheduled["class_name"], "vendor/ScheduledConfig")
        self.assertEqual(scheduled["member_name"], "tick")
        self.assertEqual(scheduled["path_certainty"], "exact")
        self.assertEqual(
            scheduled["activation_reason"],
            "spring_boot_auto_configuration_import",
        )
        entrypoint_path.write_text(
            json.dumps({**entrypoints, "records": []}), encoding="utf-8"
        )
        manifest_path = generation / "result_generation.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sidecar_content_identities"][entrypoint_path.name] = (
            hashlib.sha256(entrypoint_path.read_bytes()).hexdigest()
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with patch(
            "binary_validation_oracle._expected_result_generation_identity",
            return_value=manifest["result_generation_identity"],
        ):
            independent_validation = validate_generation(config, generation)
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_ENTRYPOINT_SET_MISMATCH"
            for item in independent_validation["issues"]
        ), independent_validation["issues"])

    def test_dependency_scheduled_method_without_activation_proof_is_not_exact(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture(
            include_activation_resource=False
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._automatic_entry_side(base_core, scheduler, app, "1.0"),
            "current": self._automatic_entry_side(current_core, scheduler, app, "2.0"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "unactivated-report")
        generation = Path(result["generation_directory"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )
        entrypoints = json.loads((generation / "binary_entrypoints.json").read_text())
        scheduled = next(
            item for item in entrypoints["records"]
            if item["entry_kind"] == "spring_scheduled"
        )

        self.assertEqual(target["reachability_status"], "uncertain")
        self.assertEqual(scheduled["path_certainty"], "possible")
        self.assertEqual(
            scheduled["activation_reason"],
            "dependency_framework_activation_unproven",
        )

    def test_spring_xml_scheduled_entry_is_rebuilt_by_independent_oracle(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture(
            include_activation_resource=False
        )
        with zipfile.ZipFile(scheduler, "a") as archive:
            archive.writestr(
                "config/scheduler.xml",
                "<beans xmlns:task='urn:test'>"
                "<bean id='job' class='vendor.ScheduledConfig' init-method='tick'/>"
                "<task:scheduled-tasks>"
                "<task:scheduled target='job.tick'/>"
                "</task:scheduled-tasks></beans>",
            )
        base_side = self._automatic_entry_side(base_core, scheduler, app, "1.0")
        current_side = self._automatic_entry_side(current_core, scheduler, app, "2.0")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"][
                "activated_resource_names"
            ] = ["classpath:config/scheduler.xml"]
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "scheduled-xml-report")
        generation = Path(result["generation_directory"])
        entries = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )["records"]
        xml_entry = next(
            item for item in entries if item["entry_kind"] == "spring_xml_scheduled"
        )
        init_entry = next(
            item for item in entries
            if item["entry_kind"] == "spring_xml_init_method"
        )
        validation = validate_generation(config, generation)

        self.assertEqual(xml_entry["path_certainty"], "exact")
        self.assertEqual(xml_entry["dependency_coord"], "com.acme:scheduler:1.0")
        self.assertEqual(init_entry["path_certainty"], "exact")
        self.assertEqual(init_entry["member_name"], "tick")
        self.assertEqual(validation["status"], "passed", validation["issues"])

    def test_persistence_unit_registration_proves_dependency_jpa_callback(self):
        def entity_jar(label, value):
            jar = self._compile_sources_jar(label, {
                "jakarta/persistence/Entity.java": (
                    "package jakarta.persistence; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface Entity {}"
                ),
                "jakarta/persistence/PostLoad.java": (
                    "package jakarta.persistence; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                    "public @interface PostLoad {}"
                ),
                "lib/EntityRecord.java": (
                    "package lib; @jakarta.persistence.Entity public class EntityRecord { "
                    "@jakarta.persistence.PostLoad public void afterLoad() { "
                    f"System.out.print({value}); }} }}"
                ),
            })
            with zipfile.ZipFile(jar, "a") as archive:
                archive.writestr(
                    "META-INF/persistence.xml",
                    "<?xml version=\"1.0\"?><persistence><persistence-unit name=\"app\">"
                    "<class>lib.EntityRecord</class></persistence-unit></persistence>",
                )
            return jar

        base = entity_jar("jpa-persistence-base", 1)
        current = entity_jar("jpa-persistence-current", 2)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "jpa-persistence-report")
        generation = Path(result["generation_directory"])
        entries = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )["records"]
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        callback_entry = next(
            item for item in entries
            if item["class_name"] == "lib/EntityRecord"
            and item["member_name"] == "afterLoad"
        )
        callback = next(
            item for item in formal
            if item["display_owner"] == "lib/EntityRecord"
            and str(item["display_member"]).startswith("afterLoad")
        )

        self.assertEqual(callback_entry["path_certainty"], "exact")
        self.assertEqual(
            callback_entry["activation_reason"], "jpa_entity_registration_proved"
        )
        self.assertEqual(callback["reachability_status"], "reachable")

    def test_exact_reflection_literals_create_typed_runtime_semantic_path(self):
        def target_jar(label, value):
            source = self.root / label / "src" / "lib" / "Target.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package lib; public class Target { public Target() {} "
                f"public int changed() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "target.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "lib" / "Target.class", "lib/Target.class")
            return jar

        base_target = target_jar("reflection-base", 1)
        current_target = target_jar("reflection-current", 2)
        source = self.root / "reflection-business" / "src" / "biz" / "Entry.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            "package biz; public class Entry { public int run() throws Exception { "
            "Class<?> type = Class.forName(\"lib.Target\"); "
            "java.lang.reflect.Method method = type.getDeclaredMethod(\"changed\"); "
            "Object target = type.getDeclaredConstructor().newInstance(); "
            "return ((Integer) method.invoke(target)).intValue(); } }",
            encoding="utf-8",
        )
        classes = self.root / "reflection-business" / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business = self.root / "reflection-business" / "business.jar"
        with zipfile.ZipFile(business, "w") as archive:
            archive.write(classes / "biz" / "Entry.class", "biz/Entry.class")

        def side(target, version):
            result = self._side(target, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "reflection-business",
            }, {
                "path": str(target), "logical_location": "lib/target.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "reflection-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry",
                    "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "reflection-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "lib/Target"
            and str(item["display_member"]).startswith("changed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "reflection_method_invocation"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))
        overlay["rows"] = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] != "reflection_method_invocation"
        ]
        overlay_path = generation / "binary_runtime_semantic_overlay.json"
        overlay_path.write_text(
            json.dumps(overlay, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path = generation / "result_generation.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sidecar_content_identities"][overlay_path.name] = hashlib.sha256(
            overlay_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with patch(
            "binary_validation_oracle._expected_result_generation_identity",
            return_value=manifest["result_generation_identity"],
        ):
            tampered = validate_generation(config, generation)
        self.assertTrue(any(
            issue["reason_code"] == "ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH"
            for issue in tampered["issues"]
        ), tampered["issues"])

    def test_exact_method_handle_lookup_reaches_dependency_change(self):
        def target(label, value):
            return self._compile_sources_jar(label, {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    f"public int changed() {{ return {value}; }} }}"
                ),
            })

        base_target = target("method-handle-base", 1)
        current_target = target("method-handle-current", 2)
        business = self._compile_sources_jar("method-handle-business", {
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() throws Throwable { "
                "java.lang.invoke.MethodHandle handle = java.lang.invoke.MethodHandles.lookup()"
                ".findVirtual(lib.Target.class, \"changed\", "
                "java.lang.invoke.MethodType.methodType(int.class)); "
                "return (int) handle.invokeExact(new lib.Target()); } }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "method-handle-business",
            }, {
                "path": str(target_jar), "logical_location": "lib/target.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "method-handle-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "method-handle-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal
            if item["display_owner"] == "lib/Target"
            and str(item["display_member"]).startswith("changed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(changed["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "method_handle_invocation"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_invoked_registered_dynamic_proxy_handler_reaches_dependency_change(self):
        def api_jar(label, value):
            source = self.root / label / "src" / "api" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                f"package api; public class Api {{ public int value() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "api.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "api" / "Api.class", "api/Api.class")
            return jar

        base_api = api_jar("proxy-base", 1)
        current_api = api_jar("proxy-current", 2)
        source_root = self.root / "proxy-business" / "src"
        sources = {
            "biz/Action.java": "package biz; public interface Action { int run(); }",
            "biz/Handler.java": (
                "package biz; public class Handler implements java.lang.reflect.InvocationHandler { "
                "public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { "
                "return Integer.valueOf(new api.Api().value()); } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { "
                "Action action = (Action) java.lang.reflect.Proxy.newProxyInstance("
                "Action.class.getClassLoader(), new Class<?>[]{Action.class}, new Handler()); "
                "return action.run(); } }"
            ),
        }
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / "proxy-business" / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-cp", str(current_api), "-d", str(classes), *map(str, paths)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business = self.root / "proxy-business" / "business.jar"
        with zipfile.ZipFile(business, "w") as archive:
            for class_file in classes.rglob("*.class"):
                archive.write(class_file, class_file.relative_to(classes).as_posix())

        def side(api, version):
            result = self._side(api, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "proxy-business",
            }, {
                "path": str(api), "logical_location": "lib/api.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:api:{version}", "lineage": "com.acme:api",
                "runtime_code_source_origin_identity": "proxy-api",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_api, "1"), "current": side(current_api, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "proxy-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "dynamic_proxy_callback"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_mybatis_mapper_proxy_dispatch_reaches_packaged_runtime_chain(self):
        def runtime(label, value):
            return self._compile_sources_jar(label, {
                "org/apache/ibatis/annotations/Mapper.java": (
                    "package org.apache.ibatis.annotations; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface Mapper {}"
                ),
                "org/apache/ibatis/session/SqlSession.java": (
                    "package org.apache.ibatis.session; public interface SqlSession {}"
                ),
                "org/apache/ibatis/binding/MapperProxy.java": (
                    "package org.apache.ibatis.binding; public class MapperProxy { "
                    "public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { "
                    f"return Integer.valueOf({value}); }} }}"
                ),
                "org/apache/ibatis/binding/MapperMethod.java": (
                    "package org.apache.ibatis.binding; public class MapperMethod { "
                    "public Object execute(org.apache.ibatis.session.SqlSession session, Object[] args) { "
                    "return null; } }"
                ),
            })

        base_runtime = runtime("mybatis-base", 1)
        current_runtime = runtime("mybatis-current", 2)
        business = self._compile_sources_jar("mybatis-business", {
            "biz/DemoMapper.java": (
                "package biz; @org.apache.ibatis.annotations.Mapper "
                "public interface DemoMapper { int findOne(); }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(DemoMapper mapper) { "
                "return mapper.findOne(); } }"
            ),
        }, classpath=(current_runtime,))

        def side(runtime_jar, version):
            result = self._side(runtime_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "mybatis-business",
            }, {
                "path": str(runtime_jar), "logical_location": "lib/mybatis.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"org.mybatis:mybatis:{version}",
                "lineage": "org.mybatis:mybatis",
                "runtime_code_source_origin_identity": "mybatis-runtime",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/DemoMapper;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_runtime, "1"), "current": side(current_runtime, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "mybatis-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "org/apache/ibatis/binding/MapperProxy"
            and str(item["display_member"]).startswith("invoke")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "mybatis_mapper_proxy_dispatch"
            and row["target_dependency_coord"] == "org.mybatis:mybatis:2"
            for row in overlay["rows"]
        ))

    def test_transactional_business_method_reaches_packaged_interceptor_chain(self):
        def runtime(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/transaction/annotation/Transactional.java": (
                    "package org.springframework.transaction.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Transactional {}"
                ),
                "org/aopalliance/intercept/MethodInvocation.java": (
                    "package org.aopalliance.intercept; public interface MethodInvocation {}"
                ),
                "org/springframework/transaction/interceptor/TransactionInterceptor.java": (
                    "package org.springframework.transaction.interceptor; public class TransactionInterceptor { "
                    "public Object invoke(org.aopalliance.intercept.MethodInvocation invocation) { "
                    f"return Integer.valueOf({value}); }} }}"
                ),
                "org/springframework/transaction/interceptor/TransactionAspectSupport.java": (
                    "package org.springframework.transaction.interceptor; public class TransactionAspectSupport { "
                    "public interface InvocationCallback {} "
                    "public Object invokeWithinTransaction(java.lang.reflect.Method method, Class<?> type, "
                    "InvocationCallback callback) { return null; } }"
                ),
                "org/springframework/aop/framework/ReflectiveMethodInvocation.java": (
                    "package org.springframework.aop.framework; public class ReflectiveMethodInvocation { "
                    "public Object proceed() { return null; } }"
                ),
            })

        base_runtime = runtime("transaction-base", 1)
        current_runtime = runtime("transaction-current", 2)
        business = self._compile_sources_jar("transaction-business", {
            "biz/Service.java": (
                "package biz; public class Service { "
                "@org.springframework.transaction.annotation.Transactional "
                "public int work() { return 7; } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { return new Service().work(); } }"
            ),
        }, classpath=(current_runtime,))

        def side(runtime_jar, version):
            result = self._side(runtime_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "transaction-business",
            }, {
                "path": str(runtime_jar), "logical_location": "lib/spring-runtime.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"org.springframework:spring-tx:{version}",
                "lineage": "org.springframework:spring-tx",
                "runtime_code_source_origin_identity": "transaction-runtime",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_runtime, "1"), "current": side(current_runtime, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "transaction-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"].endswith("TransactionInterceptor")
            and str(item["display_member"]).startswith("invoke")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(
            target["current_dependency_coords"],
            ["org.springframework:spring-tx:2"],
        )
        self.assertTrue(any(
            row["semantic_edge_kind"] == "spring_transaction_proxy_dispatch"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_component_wiring_and_spring_data_proxy_use_runtime_activation(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/stereotype/Component.java": (
                    "package org.springframework.stereotype; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Component {}"
                ),
                "org/springframework/context/annotation/ComponentScan.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface ComponentScan { String[] value() default {}; }"
                ),
                "org/springframework/context/annotation/Profile.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Profile { String[] value(); }"
                ),
                "org/springframework/context/annotation/Primary.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Primary {}"
                ),
                "org/springframework/data/repository/Repository.java": (
                    "package org.springframework.data.repository; public interface Repository<T,ID> {}"
                ),
                "org/springframework/data/jpa/repository/JpaRepository.java": (
                    "package org.springframework.data.jpa.repository; public interface JpaRepository<T,ID> "
                    "extends org.springframework.data.repository.Repository<T,ID> { java.util.List<T> findAll(); }"
                ),
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository.java": (
                    "package org.springframework.data.jpa.repository.support; public class SimpleJpaRepository<T,ID> { "
                    f"public java.util.List<T> findAll() {{ return {value} == 1 "
                    "? new java.util.ArrayList<T>() : java.util.Collections.emptyList(); } }"
                ),
                "lib/Service.java": "package lib; public interface Service { int ping(); }",
                "lib/LibService.java": (
                    "package lib; @org.springframework.stereotype.Component "
                    "@org.springframework.context.annotation.Primary "
                    "@org.springframework.context.annotation.Profile(\"prod\") "
                    f"public class LibService implements Service {{ public int ping() {{ return {value}; }} }}"
                ),
                "lib/BackupService.java": (
                    "package lib; @org.springframework.stereotype.Component "
                    "@org.springframework.context.annotation.Profile(\"prod\") "
                    f"public class BackupService implements Service {{ public int ping() {{ return {value + 10}; }} }}"
                ),
            })

        base_framework = framework("wiring-base", 1)
        current_framework = framework("wiring-current", 2)
        business = self._compile_sources_jar("wiring-business", {
            "biz/DemoRepository.java": (
                "package biz; public interface DemoRepository extends "
                "org.springframework.data.jpa.repository.JpaRepository<Object,Long> {}"
            ),
            "biz/Config.java": (
                "package biz; @org.springframework.context.annotation.ComponentScan(\"lib\") "
                "public class Config {}"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(lib.Service service, DemoRepository repo) { "
                "return service.ping() + repo.findAll().size(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "wiring-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:framework:{version}",
                "lineage": "com.acme:framework",
                "runtime_code_source_origin_identity": "wiring-framework",
            }]
            profile = result["runtime_profile"]
            profile["container_and_launcher_kind"] = "spring-boot-executable-jar"
            profile["active_profile_identities"] = ["prod"]
            profile["business_entrypoint_profile"] = {
                "coverage_status": "complete", "main_class": "biz.Application",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Llib/Service;Lbiz/DemoRepository;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "wiring-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        ping = next(
            item for item in formal if item["display_owner"] == "lib/LibService"
            and str(item["display_member"]).startswith("ping")
        )
        backup_ping = next(
            item for item in formal if item["display_owner"] == "lib/BackupService"
            and str(item["display_member"]).startswith("ping")
        )
        find_all = next(
            item for item in formal if item["display_owner"].endswith("SimpleJpaRepository")
            and str(item["display_member"]).startswith("findAll")
        )

        self.assertEqual(ping["reachability_status"], "reachable")
        self.assertEqual(
            backup_ping["reachability_status"], "uncertain"
        )
        self.assertEqual(find_all["reachability_status"], "reachable")
        self.assertIn("spring_bean_wiring_dispatch", {
            row["semantic_edge_kind"] for row in overlay["rows"]
        })
        wiring_edges = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
        ]
        self.assertEqual(
            {
                (row["target_class_name"], row["path_certainty"])
                for row in wiring_edges
                if row["target_member_name"] == "ping"
            },
            {("lib/LibService", "exact")},
        )
        self.assertIn("spring_data_repository_proxy_dispatch", {
            row["semantic_edge_kind"] for row in overlay["rows"]
        })

    def test_custom_spring_data_factory_does_not_claim_simple_repository_dispatch(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/data/repository/Repository.java": (
                    "package org.springframework.data.repository; "
                    "public interface Repository<T,ID> {}"
                ),
                "org/springframework/data/jpa/repository/JpaRepository.java": (
                    "package org.springframework.data.jpa.repository; "
                    "public interface JpaRepository<T,ID> extends "
                    "org.springframework.data.repository.Repository<T,ID> { "
                    "java.util.List<T> findAll(); }"
                ),
                "org/springframework/data/jpa/repository/config/EnableJpaRepositories.java": (
                    "package org.springframework.data.jpa.repository.config; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface EnableJpaRepositories { "
                    "Class<?> repositoryFactoryBeanClass(); }"
                ),
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository.java": (
                    "package org.springframework.data.jpa.repository.support; "
                    "public class SimpleJpaRepository<T,ID> { "
                    f"public java.util.List<T> findAll() {{ return {value} == 1 "
                    "? new java.util.ArrayList<T>() : java.util.Collections.emptyList(); } }"
                ),
            })

        base_framework = framework("custom-repository-base", 1)
        current_framework = framework("custom-repository-current", 2)
        business = self._compile_sources_jar("custom-repository-business", {
            "biz/DemoRepository.java": (
                "package biz; public interface DemoRepository extends "
                "org.springframework.data.jpa.repository.JpaRepository<Object,Long> {}"
            ),
            "biz/CustomFactory.java": (
                "package biz; public class CustomFactory {}"
            ),
            "biz/Config.java": (
                "package biz; "
                "@org.springframework.data.jpa.repository.config.EnableJpaRepositories("
                "repositoryFactoryBeanClass=biz.CustomFactory.class) "
                "public class Config {}"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { "
                "public int run(DemoRepository repository) { "
                "return repository.findAll().size(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            payload = self._side(framework_jar, version)
            payload["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "custom-repository-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:data:{version}",
                "lineage": "com.acme:data",
                "runtime_code_source_origin_identity": "custom-repository-framework",
            }]
            payload["runtime_profile"]["container_and_launcher_kind"] = (
                "spring-boot-executable-jar"
            )
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "activated_frameworks": ["spring_boot"],
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/DemoRepository;)I",
                }],
            }
            return payload

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"),
            "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "custom-repository-report")
        generation = Path(result["generation_directory"])
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            "spring_data_custom_repository_factory", overlay["coverage_gaps"]
        )
        self.assertFalse(any(
            row["semantic_edge_kind"] == "spring_data_repository_proxy_dispatch"
            for row in overlay["rows"]
        ))

    def test_spring_aop_and_security_filter_callbacks_remain_reachable(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/aspectj/lang/annotation/Aspect.java": (
                    "package org.aspectj.lang.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Aspect {}"
                ),
                "org/aspectj/lang/annotation/Around.java": (
                    "package org.aspectj.lang.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                    "public @interface Around { String value(); }"
                ),
                "io/micrometer/observation/annotation/Observed.java": (
                    "package io.micrometer.observation.annotation; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) "
                    "@Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Observed {}"
                ),
                "io/micrometer/observation/aop/ObservedAspect.java": (
                    "package io.micrometer.observation.aop; "
                    "@org.aspectj.lang.annotation.Aspect "
                    "public class ObservedAspect { "
                    "@org.aspectj.lang.annotation.Around(\"@within("
                    "io.micrometer.observation.annotation.Observed) && "
                    "!@annotation(io.micrometer.observation.annotation.Observed) && "
                    "execution(* *.*(..))\") public void observeClass() {} }"
                ),
                "org/springframework/context/annotation/Bean.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Bean {}"
                ),
                "jakarta/servlet/Filter.java": (
                    "package jakarta.servlet; public interface Filter { void doFilter(); }"
                ),
                "org/springframework/security/web/SecurityFilterChain.java": (
                    "package org.springframework.security.web; public interface SecurityFilterChain {}"
                ),
                "org/springframework/security/config/annotation/web/builders/HttpSecurity.java": (
                    "package org.springframework.security.config.annotation.web.builders; "
                    "public class HttpSecurity { public HttpSecurity addFilter(jakarta.servlet.Filter filter) { return this; } "
                    "public org.springframework.security.web.SecurityFilterChain build() { return null; } }"
                ),
                "lib/Api.java": (
                    f"package lib; public class Api {{ public int changed() {{ return {value}; }} }}"
                ),
                "lib/LibFilter.java": (
                    "package lib; public class LibFilter implements jakarta.servlet.Filter { "
                    f"public void doFilter() {{ System.out.print({value}); }} }}"
                ),
            })

        base_framework = framework("aop-security-base", 1)
        current_framework = framework("aop-security-current", 2)
        business = self._compile_sources_jar("aop-security-business", {
            "biz/Service.java": "package biz; public class Service { public int work() { return 1; } }",
            "biz/ObservedService.java": (
                "package biz; "
                "@io.micrometer.observation.annotation.Observed "
                "public class ObservedService { public void observed() {} "
                "@io.micrometer.observation.annotation.Observed "
                "public void suppressed() {} }"
            ),
            "biz/TracingAspect.java": (
                "package biz; @org.aspectj.lang.annotation.Aspect public class TracingAspect { "
                "@org.aspectj.lang.annotation.Around(\"execution(* biz.Service.work(..))\") "
                "public int around() { return new lib.Api().changed(); } }"
            ),
            "biz/SecurityConfig.java": (
                "package biz; public class SecurityConfig { @org.springframework.context.annotation.Bean "
                "public org.springframework.security.web.SecurityFilterChain chain("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http) { "
                "return http.addFilter(new lib.LibFilter()).build(); } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { return new Service().work(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "aop-security-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:framework:{version}",
                "lineage": "com.acme:framework",
                "runtime_code_source_origin_identity": "aop-security-framework",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "aop-security-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        api = next(item for item in formal if item["display_owner"] == "lib/Api")
        callback = next(
            item for item in formal if item["display_owner"] == "lib/LibFilter"
            and str(item["display_member"]).startswith("doFilter")
        )

        self.assertEqual(api["reachability_status"], "reachable")
        self.assertEqual(callback["reachability_status"], "reachable")
        kinds = {row["semantic_edge_kind"] for row in overlay["rows"]}
        self.assertIn("spring_aop_dispatch", kinds)
        self.assertIn("spring_security_filter_dispatch", kinds)
        observed_edges = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] == "spring_aop_dispatch"
            and row["target_class_name"]
            == "io/micrometer/observation/aop/ObservedAspect"
        ]
        self.assertEqual(
            {(row["caller_class_name"], row["caller_member_name"], row["path_certainty"])
             for row in observed_edges},
            {("biz/ObservedService", "observed", "possible")},
        )

    def test_declarative_client_and_dubbo_spi_dispatch_are_preserved(self):
        def framework(label, value):
            jar = self._compile_sources_jar(label, {
                "org/springframework/cloud/openfeign/FeignClient.java": (
                    "package org.springframework.cloud.openfeign; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface FeignClient { String value(); }"
                ),
                "feign/SynchronousMethodHandler.java": (
                    "package feign; public class SynchronousMethodHandler { "
                    f"public Object invoke(Object[] args) {{ return Integer.valueOf({value}); }} }}"
                ),
                "org/apache/dubbo/common/extension/ExtensionLoader.java": (
                    "package org.apache.dubbo.common.extension; public class ExtensionLoader { "
                    "public Object getExtension(String name) { return null; } }"
                ),
                "demo/DubboService.java": (
                    "package demo; public interface DubboService { int execute(); }"
                ),
                "demo/Provider.java": (
                    f"package demo; public class Provider implements DubboService {{ "
                    f"public int execute() {{ return {value}; }} }}"
                ),
            })
            with zipfile.ZipFile(jar, "a") as archive:
                archive.writestr(
                    "META-INF/dubbo/demo.DubboService",
                    "fast=demo.Provider\n",
                )
            return jar

        base_framework = framework("dispatch-base", 1)
        current_framework = framework("dispatch-current", 2)
        business = self._compile_sources_jar("dispatch-business", {
            "biz/RemoteClient.java": (
                "package biz; @org.springframework.cloud.openfeign.FeignClient(\"remote\") "
                "public interface RemoteClient { int call(); }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(RemoteClient client) { "
                "org.apache.dubbo.common.extension.ExtensionLoader loader = "
                "new org.apache.dubbo.common.extension.ExtensionLoader(); "
                "demo.DubboService service = (demo.DubboService) loader.getExtension(\"fast\"); "
                "return client.call() + service.execute(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "dispatch-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:dispatch:{version}",
                "lineage": "com.acme:dispatch",
                "runtime_code_source_origin_identity": "dispatch-framework",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/RemoteClient;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "dispatch-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        feign = next(
            item for item in formal if item["display_owner"] == "feign/SynchronousMethodHandler"
        )
        provider = next(
            item for item in formal if item["display_owner"] == "demo/Provider"
            and str(item["display_member"]).startswith("execute")
        )

        self.assertEqual(feign["reachability_status"], "reachable")
        self.assertEqual(provider["reachability_status"], "reachable")
        kinds = {row["semantic_edge_kind"] for row in overlay["rows"]}
        self.assertIn("declarative_http_client_dispatch", kinds)
        self.assertIn("dubbo_spi_dispatch", kinds)

    def test_web_binding_keeps_removed_dependency_field_reachable_as_data_contract(self):
        base_dto = self._compile_sources_jar("dto-base", {
            "lib/Dto.java": (
                "package lib; public class Dto { "
                "public String removed; public String retained; }"
            ),
        })
        current_dto = self._compile_sources_jar("dto-current", {
            "lib/Dto.java": (
                "package lib; public class Dto { public String retained; }"
            ),
        })
        business = self._compile_sources_jar("dto-business", {
            "org/springframework/web/bind/annotation/GetMapping.java": (
                "package org.springframework.web.bind.annotation; "
                "import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) "
                "@Target(ElementType.METHOD) public @interface GetMapping {}"
            ),
            "biz/Controller.java": (
                "package biz; public class Controller { "
                "@org.springframework.web.bind.annotation.GetMapping "
                "public lib.Dto endpoint(lib.Dto request) { return request; } }"
            ),
        }, classpath=(current_dto,))

        def side(dto, version):
            result = self._side(dto, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "dto-business",
            }, {
                "path": str(dto), "logical_location": "lib/dto.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:dto:{version}",
                "lineage": "com.acme:dto",
                "runtime_code_source_origin_identity": "dto-dependency",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Controller", "member_name": "endpoint",
                    "descriptor": "(Llib/Dto;)Llib/Dto;",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_dto, "1"), "current": side(current_dto, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "data-contract-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        removed = next(
            item for item in formal
            if item["display_owner"] == "lib/Dto"
            and str(item["display_member"]).startswith("removed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(removed["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "implicit_data_contract_dispatch"
            and row["target_class_name"] == "lib/Dto"
            and row["target_member_name"] == "removed"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_step1_runtime_materialization_runs_without_handwritten_binary_config(self):
        base_core, current_core, scheduler, app = (
            self._automatic_scheduled_entry_fixture()
        )
        report = self.root / "auto-materialized-report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)

        def digest(path):
            return hashlib.sha256(Path(path).read_bytes()).hexdigest()

        manifest = {
            "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
            "items": [],
            "business_artifacts": [],
            "runtime_closure": {},
        }
        provenance = {
            "schema": "java-upgrade-analyzer.build-provenance.v2",
            "sides": [],
        }
        for side, core, version in (
            ("base", base_core, "1.0"),
            ("current", current_core, "2.0"),
        ):
            outer = self.root / f"auto-materialized-{side}.jar"
            with zipfile.ZipFile(app) as business_archive, zipfile.ZipFile(
                outer, "w"
            ) as deployed_archive:
                for info in business_archive.infolist():
                    if not info.is_dir():
                        deployed_archive.writestr(
                            f"BOOT-INF/classes/{info.filename}",
                            business_archive.read(info),
                        )
                deployed_archive.writestr(
                    f"BOOT-INF/lib/{scheduler.name}", scheduler.read_bytes()
                )
                deployed_archive.writestr(
                    f"BOOT-INF/lib/{core.name}", core.read_bytes()
                )
                deployed_archive.writestr(
                    "META-INF/BOOT.SF", "Signature-Version: 1.0\r\n\r\n"
                )
            outer_digest = digest(outer)
            manifest["business_artifacts"].append({
                "side": side,
                "retained_path": str(app),
                "sha256": digest(app),
                "outer_artifact_path": str(outer),
                "outer_artifact_sha256": outer_digest,
                "container_and_launcher_kind": "spring-boot-executable-jar",
            })
            for index, (jar, coord, dependency_version) in enumerate((
                (scheduler, "com.acme:scheduler", "1.0"),
                (core, "com.acme:core", version),
            )):
                manifest["items"].append({
                    "side": side,
                    "coord": coord,
                    "version": dependency_version,
                    "lib_entry": f"BOOT-INF/lib/{Path(jar).name}",
                    "retained_path": str(jar),
                    "nested_jar_sha256": digest(jar),
                    "outer_artifact_sha256": outer_digest,
                    "runtime_classpath_index": index,
                    "purposes": ["binary_runtime"],
                })
            manifest["runtime_closure"][side] = {
                "coverage_status": "complete",
                "coverage_gaps": [],
                "expected_dependency_count": 2,
                "retained_dependency_count": 2,
                "business_artifact_count": 1,
            }
            provenance["sides"].append({
                "side": side,
                "target_module": "app",
                "jdk_home": str(self.home),
                "artifact_path": str(outer),
                "artifact_sha256": outer_digest,
            })
        (dependencies / "dependency_jars.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (dependencies / "build_provenance.json").write_text(
            json.dumps(provenance), encoding="utf-8"
        )

        config = materialize_binary_pipeline_config(report)
        for side in ("base", "current"):
            self.assertEqual(
                config[side]["runtime_profile"][
                    "runtime_security_and_package_sealing_policy_identity"
                ],
                "standard-unsealed-unsigned-v1",
            )
        config["asm_jar"] = str(self.asm_jar)
        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        formal = json.loads(
            (Path(result["generation_directory"]) / "binary_formal_results.json")
            .read_text(encoding="utf-8")
        )
        entrypoints = json.loads(
            (Path(result["generation_directory"]) / "binary_entrypoints.json")
            .read_text(encoding="utf-8")
        )
        coverage = json.loads(
            (Path(result["generation_directory"]) / "binary_coverage.json")
            .read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(
            target["paths"][0]["entrypoint_dependency_coords"],
            ["com.acme:scheduler:1.0"],
        )
        self.assertEqual(entrypoints["coverage_status"], "partial")
        self.assertIn(
            "packaged_main_class_manifest_missing",
            entrypoints["coverage_gaps"],
        )
        self.assertIn(
            "packaged_main_class_manifest_missing",
            coverage["trace_coverage_gaps"],
        )

    def test_end_to_end_generation_is_content_bound_and_immutable(self):
        base = self._jar("base", 1, service_provider="demo.OldProvider")
        current = self._jar("current", 2, service_provider="demo.NewProvider")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        report = self.root / "report"
        output = report / ".runtime" / "binary_authority"
        first = run_pipeline(config, output_root=output)
        second = run_pipeline(config, output_root=output)

        self.assertEqual(
            first["result_generation_identity"], second["result_generation_identity"]
        )
        self.assertGreater(first["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["artifact_snapshot_misses"], 0)
        self.assertEqual(first["authoritative_change_fact_count"], 2)
        self.assertGreater(first["total_elapsed_seconds"], 0)
        self.assertTrue(first["phase_timings"])
        self.assertTrue(all(
            item["elapsed_seconds"] >= 0 for item in first["phase_timings"]
        ))
        self.assertTrue(all(
            item["process_tree_cpu_seconds"] >= 0
            and item["average_cpu_cores"] >= 0
            for item in first["phase_timings"]
        ))
        timings = json.loads(Path(first["phase_timings_path"]).read_text())
        self.assertTrue(timings["non_authoritative_observability"])
        self.assertGreater(timings["peak_rss_bytes"], 0)
        self.assertEqual(timings["peak_rss_scope"], "current_process")
        self.assertEqual(second["peak_rss_bytes"], timings["peak_rss_bytes"])
        self.assertEqual(
            timings["result_generation_identity"],
            first["result_generation_identity"],
        )
        progress = json.loads(
            (
                output / "binary_observability" / "latest_in_progress.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(
            progress["last_completed_phase"], "validated_generation_activation"
        )
        generation = Path(first["generation_directory"])
        summary = json.loads((generation / "binary_summary.json").read_text())
        self.assertEqual(summary["formal_projection_count"], 1)
        self.assertEqual(summary["reachable_total"], 1)
        self.assertTrue((generation / "base_binary_facts.sqlite").is_file())
        active = json.loads((output / "active_binary_generation.json").read_text())
        self.assertEqual(
            active["result_generation_identity"], first["result_generation_identity"]
        )
        api_dir = report / "evidence" / "api_changes"
        call_dir = report / "evidence" / "call_chain"
        findings = report / ".runtime" / "findings" / "s6_findings.json"
        final_report = report / "deliverables" / "report.md"
        self._write_step6_upstream_contract(report, "com.acme:api")
        step4_result = publish_step4(report, api_dir)
        with self.assertRaises(BinaryReportError) as unmatched_selection:
            publish_step5(
                report,
                call_dir,
                selected_coords=("com.acme:not-present",),
            )
        self.assertEqual(
            unmatched_selection.exception.reason_code,
            "BINARY_STEP5_SELECTION_UNMATCHED",
        )
        self.assertFalse(call_dir.exists())
        publish_step5(report, call_dir)
        committed_step5_bytes = (
            (call_dir / "summary.json").read_bytes(),
            (
                report / "evidence" / "binary_analysis"
                / "system-reachability.md"
            ).read_bytes(),
            (
                report / ".runtime" / "indexes" / "s5_query_index.json"
            ).read_bytes(),
        )
        with patch(
            "binary_report.derive_coverage_report",
            side_effect=OSError("injected private Step5 render failure"),
        ):
            with self.assertRaisesRegex(OSError, "private Step5 render"):
                publish_step5(report, call_dir)
        self.assertEqual(
            (
                (call_dir / "summary.json").read_bytes(),
                (
                    report / "evidence" / "binary_analysis"
                    / "system-reachability.md"
                ).read_bytes(),
                (
                    report / ".runtime" / "indexes"
                    / "s5_query_index.json"
                ).read_bytes(),
            ),
            committed_step5_bytes,
        )
        step5_destinations = (
            call_dir.resolve(),
            (report / "evidence" / "binary_analysis").resolve(),
            (report / ".runtime" / "indexes").resolve(),
        )
        with binary_report._report_publication_prepare_capability(
            report, "step5"
        ):
            pending_step5 = prepare_step5_publication_candidate(
                report, call_dir
            )["publication_transaction"]
        self.assertEqual(pending_step5["state"], "pending_gate")
        self.assertEqual(
            (
                (call_dir / "summary.json").read_bytes(),
                (
                    report / "evidence" / "binary_analysis"
                    / "system-reachability.md"
                ).read_bytes(),
                (
                    report / ".runtime" / "indexes"
                    / "s5_query_index.json"
                ).read_bytes(),
            ),
            committed_step5_bytes,
        )
        with tempfile.TemporaryDirectory() as candidate_tmp:
            candidate_snapshot = materialize_report_publication_gate_candidate(
                step5_destinations,
                Path(candidate_tmp).resolve(),
                expected_transaction_id=pending_step5["transaction_id"],
                expected_binding=pending_step5["binding"],
                expected_published_content_identity=pending_step5[
                    "published_content_identity"
                ],
            )
            candidate_paths = [
                Path(item)
                for item in candidate_snapshot["candidate_destinations"]
            ]
            with patch.object(gate, "ok"):
                gate.gate_binary_report(
                    report,
                    candidate_call_chain_dir=candidate_paths[0],
                    candidate_binary_analysis_dir=candidate_paths[1],
                    candidate_index_dir=candidate_paths[2],
                    candidate_publication_binding=pending_step5["binding"],
                )
        mark_report_publication_gate_passed(
            step5_destinations,
            expected_transaction_id=pending_step5["transaction_id"],
            expected_binding=pending_step5["binding"],
            gate_name="binary_report",
            strict_risk_gate=False,
        )
        publish_report_publication(
            step5_destinations,
            expected_transaction_id=pending_step5["transaction_id"],
            expected_binding=pending_step5["binding"],
        )
        self.assertTrue(commit_report_publication(
            step5_destinations,
            expected_transaction_id=pending_step5["transaction_id"],
            expected_binding=pending_step5["binding"],
        ))
        self.assertEqual(
            reconcile_current_release(report)["step5"]["status"],
            "current",
        )
        step6_result = publish_step6(report, findings, final_report)
        committed_step6_bytes = (
            final_report.read_bytes(),
            findings.read_bytes(),
            (api_dir / "all_changed_apis.csv").read_bytes(),
        )
        with patch(
            "binary_report.s6_report.write_primary_report_artifacts",
            side_effect=OSError("injected private Step6 render failure"),
        ):
            with self.assertRaisesRegex(OSError, "private Step6 render"):
                publish_step6(report, findings, final_report)
        self.assertEqual(
            (
                final_report.read_bytes(),
                findings.read_bytes(),
                (api_dir / "all_changed_apis.csv").read_bytes(),
            ),
            committed_step6_bytes,
        )
        dependencies_dir = report / "evidence" / "dependencies"
        context_dir = report / "evidence" / "context"
        static_dir = report / "evidence" / "static_scan"
        dependencies_dir.mkdir(parents=True, exist_ok=True)
        context_dir.mkdir(parents=True, exist_ok=True)
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "s3_dependency_compat.csv").write_text(
            "坐标,版本,依赖范围,风险类型,证据,最终制品内路径\n",
            encoding="utf-8",
        )
        (static_dir / "s3_dependency_classfile.csv").write_text(
            "依赖坐标,版本,依赖范围,最终制品内路径,是否为多版本JAR,"
            "基础区最高Class版本,多版本区最高Class版本,"
            "基础区所需Java版本,多版本区所需Java版本,"
            "最高所需Java版本,目标JDK版本,扫描结论\n",
            encoding="utf-8",
        )
        (dependencies_dir / "dep_changes.csv").write_text(
            "coord,old_version,new_version,change_type,risk,scope,"
            "resolution_status,base_lib_entry,current_lib_entry\n"
            "com.acme:api,1.0,2.0,升级,P1,compile,resolved,"
            "lib/api-1.0.jar,lib/api-2.0.jar\n",
            encoding="utf-8",
        )
        (dependencies_dir / "build_provenance.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v2",
                "both_builds_succeeded": True,
                "sides": [
                    {
                        "side": "base",
                        "artifact_sha256": "a" * 64,
                    },
                    {
                        "side": "current",
                        "artifact_sha256": "b" * 64,
                    },
                ],
            }),
            encoding="utf-8",
        )
        context_path = context_dir / "context.json"
        context_path.write_text(
            json.dumps({
                "base_branch": "base",
                "current_branch": "current",
                "jdk_base": "17",
                "jdk_current": "17",
                "build_tool": "maven",
                "jdk_upgraded": False,
                "springboot_major_upgrade": False,
                "tech_flags": {},
            }),
            encoding="utf-8",
        )
        valid_dependency_changes = (
            dependencies_dir / "dep_changes.csv"
        ).read_bytes()
        (dependencies_dir / "dep_changes.csv").write_text(
            "coord,change_type\ncom.acme:api,升级\n",
            encoding="utf-8",
        )
        with binary_report._report_publication_prepare_capability(
            report, "step6"
        ), self.assertRaises(BinaryReportError) as invalid_step1:
            prepare_step6_publication_candidate(
                report, findings, final_report
            )
        self.assertEqual(
            invalid_step1.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(invalid_step1.exception.owner_step, "step1")
        self.assertEqual(
            (
                final_report.read_bytes(),
                findings.read_bytes(),
                (api_dir / "all_changed_apis.csv").read_bytes(),
            ),
            committed_step6_bytes,
        )
        (dependencies_dir / "dep_changes.csv").write_bytes(
            valid_dependency_changes
        )
        with binary_report._report_publication_prepare_capability(
            report, "step6"
        ):
            pending_step6_result = prepare_step6_publication_candidate(
                report, findings, final_report
            )
        pending_step6 = pending_step6_result["publication_transaction"]
        self.assertEqual(pending_step6["state"], "pending_gate")
        self.assertEqual(
            (
                final_report.read_bytes(),
                findings.read_bytes(),
                (api_dir / "all_changed_apis.csv").read_bytes(),
            ),
            committed_step6_bytes,
        )
        with tempfile.TemporaryDirectory() as candidate_tmp:
            candidate = materialize_report_publication_gate_candidate(
                (final_report.parent.resolve(), findings.parent.resolve()),
                Path(candidate_tmp).resolve(),
                expected_transaction_id=pending_step6["transaction_id"],
                expected_binding=pending_step6["binding"],
                expected_published_content_identity=pending_step6[
                    "published_content_identity"
                ],
            )
            candidate_paths = tuple(
                Path(item)
                for item in candidate["candidate_destinations"]
            )
            with patch.object(gate, "ok"):
                gate.gate_binary_final_report(
                    report,
                    candidate_deliverables_dir=candidate_paths[0],
                    candidate_findings_dir=candidate_paths[1],
                    candidate_publication_binding=pending_step6["binding"],
                )
        completion = complete_downstream_report_publication_after_gate(
            report,
            "step6",
            expected_transaction_id=pending_step6["transaction_id"],
            expected_binding=pending_step6["binding"],
            gate_name="binary_final_report",
            strict_risk_gate=False,
        )
        self.assertEqual(
            completion["global_release"]["step6"]["status"], "current"
        )
        original_context = context_path.read_bytes()
        context_path.write_text('{"changed":true}\n', encoding="utf-8")
        self.assertEqual(
            reconcile_current_release(report)["step6"]["status"], "stale"
        )
        context_path.write_bytes(original_context)
        self.assertEqual(
            reconcile_current_release(report)["step6"]["status"], "current"
        )
        self.assertFalse((api_dir / "binary_decisions.json").exists())
        self.assertEqual(step4_result["change_fact_count"], 1)
        step4_summary = json.loads(
            (api_dir / "summary.json").read_text()
        )
        self.assertEqual(
            step4_summary["source_inputs"]["business"]["status"], "not_provided"
        )
        self.assertEqual(step4_summary["authoritative_change_fact_count"], 2)
        self.assertEqual(step4_summary["published_api_change_count"], 1)
        self.assertEqual(step4_summary["confirmed_unprojectable_fact_count"], 1)
        self.assertIn(
            "业务源码：未提供；依赖源码：未提供",
            (report / "evidence" / "source_analysis" / "review.md").read_text(
                encoding="utf-8"
            ),
        )
        with (report / "evidence" / "source_analysis" / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(list(csv.DictReader(handle)), [])
        self.assertTrue(
            (api_dir / "all_changed_apis.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        api_csv = (api_dir / "all_changed_apis.csv").read_text()
        self.assertNotIn("META-INF/services/demo.Service", api_csv)
        with (api_dir / "all_changed_apis.csv").open(encoding="utf-8-sig", newline="") as handle:
            api_rows = list(csv.DictReader(handle))
        self.assertEqual(api_rows[0]["coord"], "com.acme:api")
        self.assertEqual(api_rows[0]["old_version"], "1")
        self.assertEqual(api_rows[0]["new_version"], "2")
        self.assertEqual(api_rows[0]["api_signature"], "()")
        dependency_review = (api_dir / "changed_dependencies.md").read_text()
        self.assertIn("com.acme:api", dependency_review)
        self.assertIn("[review.md](review.md)", dependency_review)
        per_dependency_review = next((api_dir / "s4_per_dependency").glob("*/summary.md"))
        self.assertIn(
            "[查看完整裁决](../../review.md)",
            per_dependency_review.read_text(),
        )
        complete_review = (api_dir / "review.md").read_text()
        self.assertIn("业务源码：未提供；依赖源码：未提供", complete_review)
        self.assertIn("## com.acme:api\n", complete_review)
        self.assertNotIn("## com.acme:api:1、com.acme:api:2", complete_review)
        self.assertIn("META-INF/services/demo.Service", complete_review)
        self.assertFalse(any(api_dir.glob("*.sqlite")))
        self.assertFalse(any(api_dir.glob("all_changed_apis_part_*.csv")))
        self.assertTrue(any(
            (report / "deliverables" / "changed-api-parts").glob(
                "all_changed_apis_part_*.csv"
            )
        ))
        published_summary = json.loads((call_dir / "summary.json").read_text())
        self.assertEqual(
            published_summary["schema"],
            "java-upgrade-analyzer.binary-step5-summary.v1",
        )
        step5_review = (call_dir / "summary.md").read_text(encoding="utf-8")
        self.assertIn("# 系统触达证据", step5_review)
        self.assertIn("com.acme:api", step5_review)
        self.assertIn("不是已确认无影响", step5_review)
        self.assertEqual(published_summary["reachable"], 1)
        self.assertNotIn("confirmed_impact", published_summary["quality_gate"])
        self.assertNotIn("confirmed_no_impact", published_summary["quality_gate"])
        # The established Step5 report contract retains the explicit
        # not-impacted bucket even though binary-first never fabricates a
        # confirmed-no-impact result.  The bucket must therefore remain empty.
        self.assertEqual(published_summary["not_impacted"], 0)
        self.assertEqual(published_summary["not_impacted_apis"], [])
        self.assertTrue(
            (call_dir / "alerts.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        with (call_dir / "alerts.csv").open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            alert_rows = list(reader)
            self.assertEqual(tuple(reader.fieldnames or ()), LEGACY_ALERT_FIELDS)
        self.assertEqual(alert_rows[0]["target_coord"], "com.acme:api")
        self.assertEqual(alert_rows[0]["api_signature"], "()")
        self.assertTrue(alert_rows[0]["path_text"].endswith("demo.Api.value()"))
        query = query_scope_call_chain_result(report, "com.acme:api", "coord")
        self.assertEqual(query["matched_coords"], ["com.acme:api"])
        self.assertTrue(query["chains"], query)
        self.assertTrue(
            (generation / "binary_formal_results.csv").read_bytes().startswith(
                b"\xef\xbb\xbf"
            )
        )
        self.assertIn("业务源码：未提供；依赖源码：未提供", final_report.read_text())
        published_findings = json.loads(findings.read_text(encoding="utf-8"))
        self.assertEqual(
            sum(
                published_findings["binary_dimensions"][
                    "reachability_status"
                ].values()
            ),
            len(
                json.loads(
                    (generation / "binary_formal_results.json").read_text(
                        encoding="utf-8"
                    )
                )["by_api"]
            ),
        )
        self.assertEqual(
            step6_result["step5_publication_receipt_identity"],
            published_findings["step5_publication_receipt_identity"],
        )
        rendered_report = final_report.read_text()
        self.assertIn("# Java 依赖升级影响报告", rendered_report)
        self.assertIn("## 一、依赖层面结论", rendered_report)
        self.assertIn("## 二、API 及调用关系", rendered_report)
        self.assertIn("## 三、用户可见文件说明", rendered_report)
        self.assertIn("确认有影响", rendered_report)
        self.assertIn("不表示运行时故障已经发生", rendered_report)
        self.assertNotIn("五态语义", rendered_report)
        for internal_status in (
            "reachable",
            "uncertain",
            "not_found_in_static_analysis",
            "not_analyzed",
        ):
            self.assertNotIn(internal_status, rendered_report)
        self.assertNotIn("未确认影响（存在候选关系）", rendered_report)
        self.assertNotIn("Analysis context：", rendered_report)
        self.assertFalse((api_dir / "source_overlay.md").exists())
        self.assertTrue(
            (report / "evidence" / "source_analysis" / "review.md").is_file()
        )
        self.assertTrue((final_report.parent / "all-affected-dependencies.md").is_file())
        self.assertTrue((final_report.parent / "all-affected-dependencies.csv").is_file())
        self.assertTrue((final_report.parent / "all-impact-details.md").is_file())
        self.assertTrue((final_report.parent / "all-impact-details.csv").is_file())
        self.assertTrue((final_report.parent / "analysis-scope.md").is_file())
        with (final_report.parent / "all-affected-dependencies.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(
                csv.DictReader(handle).fieldnames,
                ["依赖", "版本变化", "API 分析（已完成/总数）", "当前系统调用关系", "分析结果", "结果说明"],
            )
        with (final_report.parent / "all-impact-details.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(
                csv.DictReader(handle).fieldnames,
                ["依赖", "API", "新版本中的变化", "当前系统调用关系", "分析结果", "结果说明"],
            )
        scope_report = (final_report.parent / "analysis-scope.md").read_text()
        self.assertIn("## 源码辅助分析", scope_report)
        self.assertIn("业务源码：未提供；依赖源码：未提供", scope_report)
        impact_detail = (final_report.parent / "all-impact-details.md").read_text()
        self.assertIn("当前系统调用关系", impact_detail)
        self.assertIn("demo.Api.value()", impact_detail)
        release_path = (
            report / ".runtime" / "releases" / "current_release.json"
        )
        committed_release_bytes = release_path.read_bytes()
        tampered_release = json.loads(committed_release_bytes)
        tampered_release["release_identity"] = "0" * 64
        release_path.write_text(
            json.dumps(tampered_release), encoding="utf-8"
        )
        with self.assertRaises(BinaryReportError) as invalid_release:
            reconcile_current_release(report)
        self.assertEqual(
            invalid_release.exception.reason_code,
            "BINARY_GLOBAL_RELEASE_INVALID",
        )
        release_path.write_bytes(committed_release_bytes)
        release_path.unlink()
        rebuilt_release = reconcile_current_release(report)
        self.assertEqual(
            tuple(
                rebuilt_release[stage]["status"]
                for stage in ("step4", "step5", "step6")
            ),
            ("current", "current", "current"),
        )
        with binary_report._report_publication_prepare_capability(
            report, "step5"
        ):
            crash_window_step5 = prepare_step5_publication_candidate(
                report, call_dir
            )["publication_transaction"]
        mark_report_publication_gate_passed(
            step5_destinations,
            expected_transaction_id=crash_window_step5["transaction_id"],
            expected_binding=crash_window_step5["binding"],
            gate_name="binary_report",
            strict_risk_gate=False,
        )
        publish_report_publication(
            step5_destinations,
            expected_transaction_id=crash_window_step5["transaction_id"],
            expected_binding=crash_window_step5["binding"],
        )
        self.assertTrue(commit_report_publication(
            step5_destinations,
            expected_transaction_id=crash_window_step5["transaction_id"],
            expected_binding=crash_window_step5["binding"],
        ))
        crash_recovered_release = reconcile_current_release(report)
        self.assertEqual(
            crash_recovered_release["step5"]["status"], "current"
        )
        self.assertEqual(
            crash_recovered_release["step6"]["status"], "stale"
        )
        prior_step6_bytes = (final_report.read_bytes(), findings.read_bytes())
        republished_step4 = publish_step4(report, api_dir)
        self.assertEqual(
            republished_step4["global_release"]["step4"]["status"],
            "current",
        )
        self.assertEqual(
            republished_step4["global_release"]["step5"]["status"],
            "stale",
        )
        self.assertEqual(
            republished_step4["global_release"]["step6"]["status"],
            "stale",
        )
        with self.assertRaises(BinaryReportError) as stale_step6:
            publish_step6(report, findings, final_report)
        self.assertEqual(
            stale_step6.exception.reason_code,
            "BINARY_GLOBAL_RELEASE_STAGE_STALE",
        )
        with self.assertRaises(BinaryReportError) as stale_query:
            query_scope_call_chain_result(report, "com.acme:api", "coord")
        self.assertEqual(
            stale_query.exception.reason_code,
            "BINARY_GLOBAL_RELEASE_STAGE_STALE",
        )
        self.assertEqual(
            (final_report.read_bytes(), findings.read_bytes()),
            prior_step6_bytes,
        )
        with binary_report._report_publication_prepare_capability(
            report, "step5"
        ):
            abandoned_step5 = prepare_step5_publication_candidate(
                report, call_dir
            )["publication_transaction"]
        recovery = recover_downstream_report_publications(report)
        self.assertIn(
            {
                "stage": "step5",
                "prior_state": "pending_gate",
                "disposition": "rolled_back_uncommitted",
                "recovered": True,
            },
            recovery["actions"],
        )
        self.assertEqual(abandoned_step5["state"], "pending_gate")
        self.assertEqual(
            load_validated_generation(report)["manifest"]["result_generation_identity"],
            first["result_generation_identity"],
        )
        validation = validate_generation(config, generation)
        self.assertEqual(validation["status"], "passed", validation["issues"])
        self.assertNotEqual(
            validation["validation_run_identity"], first["analysis_context_identity"]
        )
        formal_path = generation / "binary_formal_results.json"
        manifest_path = generation / "result_generation.json"
        original_formal = formal_path.read_bytes()
        original_manifest = manifest_path.read_bytes()
        manipulated = json.loads(original_formal)
        manipulated["by_api"][0]["reachability_status"] = (
            "not_found_in_static_analysis"
        )
        manipulated["by_api"][0]["impact_conclusion"] = "inconclusive"
        formal_path.write_text(
            json.dumps(
                manipulated, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ) + "\n",
            encoding="utf-8",
        )
        manifest = json.loads(original_manifest)
        manifest["sidecar_content_identities"][formal_path.name] = hashlib.sha256(
            formal_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with patch(
            "binary_validation_oracle._expected_result_generation_identity",
            return_value=manifest["result_generation_identity"],
        ):
            conclusion_tampered = validate_generation(config, generation)
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_API_AGGREGATION_MISMATCH"
            for item in conclusion_tampered["issues"]
        ), conclusion_tampered["issues"])
        formal_path.write_bytes(original_formal)
        manifest_path.write_bytes(original_manifest)
        summary_path = generation / "binary_summary.json"
        summary_path.write_text("{}\n", encoding="utf-8")
        tampered = validate_generation(config, generation)
        self.assertEqual(tampered["status"], "failed")
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_GENERATION_SIDECAR_TAMPERED"
            for item in tampered["issues"]
        ))
        with self.assertRaises(BinaryReportError):
            load_validated_generation(report)

    def test_inherited_resolution_and_service_activation_are_human_visible(self):
        def compile_dependency(side, parent, provider, value):
            source_root = self.root / side / "dependency-src"
            sources = {
                "demo/hierarchy/ParentA.java": (
                    "package demo.hierarchy; public class ParentA { "
                    "public int value(){ return 1; } }"
                ),
                "demo/hierarchy/ParentB.java": (
                    "package demo.hierarchy; public class ParentB { "
                    f"public int value(){{ return {value}; }} }}"
                ),
                "demo/hierarchy/Child.java": (
                    "package demo.hierarchy; public class Child extends "
                    f"{parent} {{ public int call() {{ return value(); }} }}"
                ),
                "demo/spi/Service.java": (
                    "package demo.spi; public interface Service { String run(); }"
                ),
                f"demo/spi/{provider}.java": (
                    "package demo.spi; public class "
                    f"{provider} implements Service {{ public String run(){{ "
                    f"return \"{provider}\"; }} }}"
                ),
            }
            source_paths = []
            for relative, content in sources.items():
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                source_paths.append(path)
            classes = self.root / side / "dependency-classes"
            classes.mkdir(parents=True)
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), *map(str, source_paths)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / side / "dependency.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                for path in sorted(classes.rglob("*.class")):
                    archive.write(path, path.relative_to(classes).as_posix())
                archive.writestr(
                    "META-INF/services/demo.spi.Service",
                    f"demo.spi.{provider}\n",
                )
            return jar

        base_dependency = compile_dependency("semantic-base", "ParentA", "OldProvider", 2)
        current_dependency = compile_dependency("semantic-current", "ParentB", "NewProvider", 2)
        business_source = self.root / "semantic-business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; import java.util.ServiceLoader; "
            "public class Main { public String entry(){ return "
            "new demo.hierarchy.Child().call() + \":\" + "
            "ServiceLoader.load(demo.spi.Service.class).findFirst()"
            ".orElseThrow().run(); } }",
            encoding="utf-8",
        )
        business_classes = self.root / "semantic-business-classes"
        business_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(base_dependency),
                "-d", str(business_classes), str(business_source),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business_jar = self.root / "semantic-business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")

        def side(dependency, version):
            return {
                "jdk_home": str(self.home),
                "artifacts": [{
                    "path": str(business_jar),
                    "logical_location": "app/business.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "business_classes",
                    "slot": 0,
                    "coord": "com.acme:application:1",
                    "lineage": "com.acme:application",
                    "runtime_code_source_origin_identity": "semantic:application",
                }, {
                    "path": str(dependency),
                    "logical_location": "lib/semantic.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "classpath",
                    "slot": 1,
                    "coord": f"com.acme:semantic:{version}",
                    "lineage": "com.acme:semantic",
                    "runtime_code_source_origin_identity": (
                        f"semantic:dependency:{version}"
                    ),
                }],
                "runtime_profile": {
                    "container_and_launcher_kind": "java-classpath",
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
                    "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
                    "active_profile_identities": ["default"],
                    "external_config_snapshot_identities": [],
                    "agent_transformer_plugin_profile_identities": [],
                    "business_entrypoint_profile": {
                        "coverage_status": "complete",
                        "methods": [{
                            "initiating_loader_realm_identity": "application-loader",
                            "class_name": "biz/Main", "member_name": "entry",
                            "descriptor": "()Ljava/lang/String;",
                        }],
                    },
                    "runtime_class_closure_coverage_status": "complete",
                    "resource_selection_coverage_status": "complete",
                },
            }

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_dependency, "1"),
            "current": side(current_dependency, "2"),
            "runtime_comparison": {
                "comparison_intent": "release_snapshot",
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
                "changed_or_unknown_profile_fields": [
                    "runtime_code_source_origin_mapping_identity"
                ],
            },
        }
        report = self.root / "semantic-report"
        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        generation = Path(result["generation_directory"])
        decisions = json.loads((generation / "binary_decisions.json").read_text())
        resolution = [
            item for item in decisions["authoritative_change_facts"]
            if item.get("reason_code") == "RUNTIME_MEMBER_RESOLUTION_CHANGED"
        ]
        self.assertEqual(len(resolution), 1)
        self.assertEqual(
            resolution[0]["evidence"]["base_resolution"]["resolved_owner"],
            "demo/hierarchy/ParentA",
        )
        self.assertEqual(
            resolution[0]["evidence"]["current_resolution"]["resolved_owner"],
            "demo/hierarchy/ParentB",
        )
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        resolution_result = next(
            item for item in formal["results"]
            if item.get("change_fact_identity") == resolution[0]["change_fact_identity"]
        )
        self.assertEqual(resolution_result["reachability_status"], "reachable")
        resource_result = formal["resource_activation_results"]
        self.assertEqual(len(resource_result), 1)
        self.assertEqual(resource_result[0]["activation_status"], "reachable")

        self._write_step6_upstream_contract(report, "com.acme:semantic")
        publish_step4(report, report / "evidence" / "api_changes")
        publish_step5(report, report / "evidence" / "call_chain")
        publish_step6(
            report,
            report / ".runtime" / "findings" / "s6_findings.json",
            report / "deliverables" / "report.md",
        )
        with (report / "evidence" / "api_changes" / "all_changed_apis.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            rows = list(csv.DictReader(handle))
        resolution_row = next(
            item for item in rows
            if item["change_type"] == "MEMBER_RESOLUTION_CHANGED"
        )
        self.assertEqual(resolution_row["old_value"], "demo/hierarchy/ParentA")
        self.assertEqual(resolution_row["new_value"], "demo/hierarchy/ParentB")
        report_text = (report / "deliverables" / "report.md").read_text()
        self.assertIn("demo.hierarchy.ParentA → demo.hierarchy.ParentB", report_text)
        self.assertIn("META-INF/services/demo.spi.Service", report_text)
        self.assertIn("已确认当前系统激活", report_text)
        dependencies_text = (
            report / "deliverables" / "all-affected-dependencies.md"
        ).read_text()
        semantic_row = next(
            line for line in dependencies_text.splitlines()
            if "`com.acme:semantic`" in line
        )
        self.assertIn("确认有影响", semantic_row)
        self.assertIn("运行时资源", semantic_row)

    def test_manifest_semantics_match_independent_validation(self):
        manifest = (
            "Manifest-Version: 1.0\r\n"
            "Created-By: comparison fixture\r\n"
            "Long-Value: first-\r\n"
            " continuation\r\n"
            "\r\n"
        )
        base = self._jar("base", 1, manifest=manifest, uses_system_out=True)
        current = self._jar("current", 2, manifest=manifest, uses_system_out=True)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base),
            "current": self._side(current),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config,
            output_root=self.root / "report" / ".runtime" / "binary_authority",
        )

        self.assertEqual(result["validation_status"], "passed")

    def test_one_sided_platform_reference_is_not_a_provider_change(self):
        def signature_jar(side, parameter_type):
            source = self.root / side / "src" / "demo" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class Api { "
                "public int value(){ return 1; } "
                f"public int signature({parameter_type} value){{ return value.length(); }} "
                "}",
                encoding="utf-8",
            )
            classes = self.root / side / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / side / "api.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "demo" / "Api.class", "demo/Api.class")
            return jar

        base = signature_jar("platform-ref-base", "String")
        current = signature_jar("platform-ref-current", "CharSequence")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config,
            output_root=self.root / "platform-reference-output",
        )
        decisions = json.loads(
            (Path(result["generation_directory"]) / "binary_decisions.json").read_text()
        )
        all_decisions = [
            *decisions["authoritative_change_facts"],
            *decisions["diagnostic_candidate_facts"],
        ]

        self.assertFalse(any(
            item.get("fact_kind") == "provider_topology"
            and (item.get("fact_scope") or {}).get("class_name")
            == "java/lang/CharSequence"
            for item in all_decisions
        ))

    def test_dependency_source_set_is_published_with_dependency_dimension(self):
        base = self._compile_sources_jar("source-base", {
            "demo/Api.java": (
                "package demo; public class Api { "
                "public int value(){ return helper(); } "
                "private int helper(){ return 1; } }"
            ),
        })
        current = self._compile_sources_jar("source-current", {
            "demo/Api.java": (
                "package demo; public class Api { "
                "public int value(){ System.out.print(\"\"); return helper(); } "
                "private int helper(){ return 2; } }"
            ),
        })
        current_source = self.root / "source-current" / "src"
        kotlin_source = current_source / "demo" / "KotlinConsumer.kt"
        kotlin_source.write_text(
            "package demo\nclass KotlinConsumer { fun value() = Api().value() }\n",
            encoding="utf-8",
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "dependency",
                    "owner_coord": "com.acme:api:2",
                    "module": "api",
                }],
            },
        }
        report = self.root / "dependency-source-report"

        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        self.assertEqual(
            result["source_inputs"]["dependencies"]["status"], "available"
        )
        attestation = json.loads(
            (
                Path(result["generation_directory"])
                / "binary_source_attestation.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(attestation["coverage_status"], "partial")
        self.assertEqual(attestation["source_sets"][0]["owner_type"], "dependency")
        self.assertEqual(attestation["source_sets"][0]["owner_coord"], "com.acme:api:2")
        self.assertEqual(attestation["file_count"], 2)
        self.assertEqual(
            attestation["language_file_counts"], {"java": 1, "kotlin": 1}
        )
        self.assertEqual(
            attestation["coverage_gaps"][0]["reason_code"],
            "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
        )
        self.assertGreaterEqual(attestation["mapped_binary_member_count"], 1)
        self.assertEqual(len(attestation["files"][0]["sha256"]), 64)
        api_dir = report / "evidence" / "api_changes"
        publish_step4(report, api_dir)
        source_dir = report / "evidence" / "source_analysis"
        with (source_dir / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            rows = list(csv.DictReader(handle))

        mapped = next(row for row in rows if row["二进制方法"] == "demo.Api.value()")
        self.assertEqual(mapped["源码归属"], "com.acme:api:2")
        self.assertEqual(mapped["二进制制品"], "com.acme:api:2")
        self.assertEqual(mapped["源码位置"], "demo/Api.java:1")
        self.assertTrue(mapped["源码声明"])
        source_review = (source_dir / "review.md").read_text(encoding="utf-8")
        self.assertIn("kotlin 1 个", source_review)
        self.assertIn("coverage_gaps.csv", source_review)
        with (source_dir / "coverage_gaps.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            gap_rows = list(csv.DictReader(handle))
        self.assertEqual(gap_rows[0]["源码文件"], "demo/KotlinConsumer.kt")
        self.assertTrue((source_dir / "source_snapshot.json").is_file())
        with (source_dir / "candidate_relationships.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            candidate_rows = list(csv.DictReader(handle))
        self.assertTrue(candidate_rows)
        self.assertTrue(any(
            row["候选目标"] == "demo.Api.helper()"
            and row["置信度"] == "high"
            for row in candidate_rows
        ))
        self.assertFalse(any(
            row["候选目标"].endswith(".print")
            or row["置信度"] == "low"
            for row in candidate_rows
        ))
        self.assertTrue(all(
            row["源码归属"] == "com.acme:api:2"
            and row["权威边界"] == "源码候选关系，不是可执行调用边"
            for row in candidate_rows
        ))

    def _constant_side(self, side, constant):
        root = self.root / side
        vendor_source = root / "vendor-src" / "vendor" / "Constants.java"
        vendor_source.parent.mkdir(parents=True)
        vendor_source.write_text(
            f"package vendor; public class Constants {{ public static final int VALUE = {constant}; }}",
            encoding="utf-8",
        )
        vendor_classes = root / "vendor-classes"
        vendor_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(vendor_classes), str(vendor_source)],
            check=True,
            capture_output=True,
        )
        vendor_jar = root / "vendor.jar"
        with zipfile.ZipFile(vendor_jar, "w") as archive:
            archive.write(
                vendor_classes / "vendor" / "Constants.class",
                "vendor/Constants.class",
            )
        business_source = root / "business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; public class Main { public int entry(){ return vendor.Constants.VALUE; } }",
            encoding="utf-8",
        )
        business_classes = root / "business-classes"
        business_classes.mkdir()
        subprocess.run(
            [
                "javac", "-g", "-cp", str(vendor_jar), "-d", str(business_classes),
                str(business_source),
            ],
            check=True,
            capture_output=True,
        )
        business_jar = root / "business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")
        return business_source.parent.parent, business_jar, vendor_jar

    def _constant_config_side(self, source_root, business, vendor):
        side = self._side(vendor)
        side["artifacts"] = [
            {
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "deployment-business",
            },
            {
                "path": str(vendor), "logical_location": "lib/vendor.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": "vendor", "lineage": "vendor",
                "runtime_code_source_origin_identity": "deployment-vendor",
            },
        ]
        side["runtime_profile"]["business_entrypoint_profile"] = {
            "coverage_status": "complete",
            "methods": [{
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "biz/Main", "member_name": "entry", "descriptor": "()I",
            }],
        }
        return side

    def test_source_overlay_proves_javac_constant_inline_without_literal_guessing(self):
        _base_source, base_business, base_vendor = self._constant_side("inline-base", 11)
        current_source, current_business, current_vendor = self._constant_side("inline-current", 29)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._constant_config_side(_base_source, base_business, base_vendor),
            "current": self._constant_config_side(current_source, current_business, current_vendor),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        inline_report = self.root / "inline-report"
        result = run_pipeline(
            config,
            output_root=inline_report / ".runtime" / "binary_authority",
        )
        generation = Path(result["generation_directory"])
        inline = json.loads((generation / "binary_inline_overlay.json").read_text())
        self.assertEqual(inline["proven_count"], 1, inline)
        proven = next(row for row in inline["rows"] if row["binding_certainty"] == "proven")
        self.assertTrue(proven["bytecode_constant_transition_proven"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        field_results = [
            item for item in formal["results"]
            if item["target_nodes"] == [proven["changed_field_member_identity"]]
        ]
        self.assertEqual(len(field_results), 1)
        self.assertEqual(field_results[0]["reachability_status"], "reachable")
        source_report_dir = inline_report / "evidence" / "api_changes"
        publish_step4(inline_report, source_report_dir)
        source_analysis_dir = inline_report / "evidence" / "source_analysis"
        source_report = (source_analysis_dir / "review.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("`business`", source_report)
        self.assertIn("biz.Main.entry()", source_report)
        with (source_analysis_dir / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            source_rows = list(csv.DictReader(handle))
        self.assertTrue(any(row["源码归属"] == "business" for row in source_rows))

    def test_retained_base_constant_consumer_never_becomes_exact_inline_edge(self):
        base_source, base_business, base_vendor = self._constant_side("retained-base", 7)
        current_source, _rebuilt_business, current_vendor = self._constant_side(
            "retained-current", 31
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._constant_config_side(base_source, base_business, base_vendor),
            # Deliberately retain the old consumer bytes while updating the
            # dependency and source snapshot.
            "current": self._constant_config_side(
                current_source, base_business, current_vendor
            ),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        result = run_pipeline(
            config,
            output_root=self.root / "retained-output",
        )
        inline = json.loads(
            (Path(result["generation_directory"]) / "binary_inline_overlay.json").read_text()
        )
        self.assertEqual(inline["proven_count"], 0)
        self.assertEqual(inline["retained_or_unchanged_count"], 1)
        row = next(
            item for item in inline["rows"]
            if item["consumption_state"] == "retained_base_or_unchanged"
        )
        self.assertEqual(row["binding_certainty"], "none")

    def _dispatch_jar(self, side, value):
        source_root = self.root / side / "src"
        sources = {
            "demo/Api.java": "package demo; public interface Api { int value(); }",
            "demo/Impl.java": (
                f"package demo; public class Impl implements Api {{ public int value(){{ return {value}; }} }}"
            ),
            "demo/Main.java": (
                "package demo; public class Main { "
                "public int entry(){ Api api = new Impl(); return api.value(); } "
                "public java.util.function.IntSupplier supplier(Api api){ return api::value; } "
                "}"
            ),
        }
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / side / "classes"
        classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(classes), *map(str, paths)],
            check=True,
            capture_output=True,
        )
        jar = self.root / side / "app.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        return jar

    def _same_name_edge_jar(self, side, marker):
        calls = " ".join(
            f"value = encryptor.{'enCrypt' if index % 2 == 0 else 'deCrypt'}(value);"
            for index in range(16)
        )
        return self._compile_sources_jar(side, {
            "com/csii/pe/security/EnDecrypt.java": (
                "package com.csii.pe.security; "
                "public interface EnDecrypt { "
                "String enCrypt(String value); String deCrypt(String value); }"
            ),
            "a.java": (
                "import com.csii.pe.security.EnDecrypt; "
                "public class a { "
                "static Class<?> class$0; "
                "public a() {} "
                "public String a(EnDecrypt encryptor, String value) { "
                f"{calls} "
                "Class<?> first = class$0; class$0 = String.class; "
                "Class<?> second = class$0; class$0 = Object.class; "
                "return first == second ? value : value; "
                "} "
                f"public int marker() {{ return {marker}; }} "
                "}"
            ),
        })

    def _major48_same_name_edge_jar(self, side, marker):
        from tests.test_final_artifact_edge_oracle import (
            SAME_NAME_METHOD_CLASS,
            _minimal_static_edge_class,
        )

        jar = self._compile_sources_jar(side, {
            "com/csii/pe/security/EnDecrypt.java": (
                "package com.csii.pe.security; "
                "public interface EnDecrypt { "
                "String enCrypt(String value); String deCrypt(String value); }"
            ),
            "fixture/Marker.java": (
                "package fixture; public class Marker { "
                f"public int marker() {{ return {marker}; }} }}"
            ),
        })
        self.assertEqual(int.from_bytes(SAME_NAME_METHOD_CLASS[6:8], "big"), 48)
        entry = zipfile.ZipInfo(
            "a.class", date_time=(2020, 1, 1, 0, 0, 0)
        )
        entry.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(jar, "a") as archive:
            archive.writestr(entry, SAME_NAME_METHOD_CLASS)
            archive.writestr(
                "SurrogatePipelineFixture.class",
                _minimal_static_edge_class(
                    "SurrogatePipelineFixture", json.loads('"\\ud800"')
                ),
            )
        return jar

    def test_independent_oracle_validates_interface_dispatch_targets(self):
        base = self._dispatch_jar("dispatch-base", 1)
        current = self._dispatch_jar("dispatch-current", 2)
        base_side = self._side(base)
        current_side = self._side(current)
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "demo/Main", "member_name": "entry", "descriptor": "()I",
                }],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(
            config,
            output_root=self.root / "dispatch-output",
        )
        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)

    def test_same_name_method_edges_reach_validated_generation_activation(self):
        base = self._same_name_edge_jar("same-name-base", 1)
        current = self._same_name_edge_jar("same-name-current", 2)
        base_side = self._side(base, "1")
        current_side = self._side(current, "2")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "a",
                    "member_name": "marker",
                    "descriptor": "()I",
                }],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        output = self.root / "same-name-output"
        result = run_pipeline(config, output_root=output)

        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)
        progress = json.loads(
            (output / "binary_observability" / "latest_in_progress.json").read_text()
        )
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(
            progress["last_completed_phase"], "validated_generation_activation"
        )

        connection = sqlite3.connect(
            Path(result["generation_directory"]) / "current_binary_facts.sqlite"
        )
        try:
            rows = connection.execute(
                "SELECT edge_kind, opcode, symbolic_owner, symbolic_name "
                "FROM direct_edges JOIN members "
                "ON members.member_identity = direct_edges.caller_member_identity "
                "WHERE class_name = 'a' AND member_name = 'a' "
                "AND edge_kind IN ('method', 'field') "
                "ORDER BY bytecode_offset"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 20)
        self.assertEqual(sum(row[0] == "method" and row[1] == 185 for row in rows), 16)
        self.assertEqual(sum(row[0] == "field" and row[1] == 178 for row in rows), 2)
        self.assertEqual(sum(row[0] == "field" and row[1] == 179 for row in rows), 2)
        self.assertEqual(
            {row[3] for row in rows if row[0] == "method"},
            {"enCrypt", "deCrypt"},
        )

    def test_major48_same_name_edges_reach_validated_generation_activation(self):
        base = self._major48_same_name_edge_jar("major48-base", 1)
        current = self._major48_same_name_edge_jar("major48-current", 2)
        base_side = self._side(base, "1")
        current_side = self._side(current, "2")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "fixture/Marker",
                    "member_name": "marker",
                    "descriptor": "()I",
                }],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        output = self.root / "major48-same-name-output"
        result = run_pipeline(config, output_root=output)

        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)
        progress = json.loads(
            (output / "binary_observability" / "latest_in_progress.json").read_text()
        )
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(
            progress["last_completed_phase"],
            "validated_generation_activation",
        )

        connection = sqlite3.connect(
            Path(result["generation_directory"])
            / "current_binary_facts.sqlite"
        )
        try:
            rows = connection.execute(
                "SELECT edge_kind, opcode, symbolic_owner, symbolic_name, "
                "edge_json FROM direct_edges JOIN members "
                "ON members.member_identity = direct_edges.caller_member_identity "
                "WHERE class_name = 'a' AND member_name = 'a' "
                "AND edge_kind IN ('method', 'field') "
                "ORDER BY bytecode_offset"
            ).fetchall()
            surrogate_members = connection.execute(
                "SELECT member_name FROM members "
                "WHERE class_name = 'SurrogatePipelineFixture' "
                "AND member_kind = 'method'"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 20)
        self.assertEqual(
            sum(row[0] == "method" and row[1] == 185 for row in rows), 16
        )
        self.assertEqual(
            sum(row[0] == "field" and row[1] == 178 for row in rows), 2
        )
        self.assertEqual(
            sum(row[0] == "field" and row[1] == 179 for row in rows), 2
        )
        self.assertTrue(all(
            json.loads(row[4]).get("interface") is True
            for row in rows
            if row[0] == "method"
        ))
        self.assertIn(
            (transport_jvm_text(json.loads('"\\ud800"')),),
            surrogate_members,
        )

    def test_pre_java8_mr_entry_is_ignored_through_validated_activation(self):
        base = self._pre_java8_mr_jar("mr-floor-base", 1, 71)
        current = self._pre_java8_mr_jar("mr-floor-current", 2, 72)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        output = self.root / "mr-floor-output"
        result = run_pipeline(config, output_root=output)

        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)
        connection = sqlite3.connect(
            Path(result["generation_directory"]) / "current_binary_facts.sqlite"
        )
        try:
            class_entries = [
                row[0] for row in connection.execute(
                    "SELECT physical_entry_label FROM classes ORDER BY physical_entry_label"
                )
            ]
        finally:
            connection.close()
        self.assertEqual(class_entries, ["demo/Api.class#occurrence=0"])
        progress = json.loads(
            (output / "binary_observability" / "latest_in_progress.json")
            .read_text()
        )
        self.assertEqual(
            progress["last_completed_phase"],
            "validated_generation_activation",
        )

    def test_step1_materialized_mr_resources_reach_validated_activation(self):
        report = self.root / "step1-mr-resource-report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)
        dummy = self.root / "empty-runtime-dependency.jar"
        with zipfile.ZipFile(dummy, "w"):
            pass
        manifest_bytes = (
            b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
        )
        side_meta = {}
        side_entries = {}
        expected_selected_xml = {}
        for side, base_value, versioned_value, version in (
            ("base", 1, 91, "1"),
            ("current", 2, 92, "2"),
        ):
            base_class_jar = self._jar(
                f"step1-{side}-base-class", base_value
            )
            versioned_class_jar = self._jar(
                f"step1-{side}-versioned-class", versioned_value
            )
            v8_only_class_jar = self._compile_sources_jar(
                f"step1-{side}-v8-only-class",
                {
                    "demo/EightOnly.java": (
                        "package demo; public class EightOnly { "
                        "public int value(){ return 8; } }"
                    )
                },
            )
            selected_xml = (
                f"<beans><bean id='{side}-version9'/></beans>".encode()
            )
            expected_selected_xml[side] = hashlib.sha256(
                selected_xml
            ).hexdigest()
            outer = self.root / f"step1-{side}-mr.jar"
            with zipfile.ZipFile(base_class_jar) as base_archive, zipfile.ZipFile(
                versioned_class_jar
            ) as versioned_archive, zipfile.ZipFile(
                v8_only_class_jar
            ) as v8_only_archive, zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", manifest_bytes)
                archive.writestr(
                    "demo/Api.class", base_archive.read("demo/Api.class")
                )
                archive.writestr(
                    "META-INF/versions/9/demo/Api.class",
                    versioned_archive.read("demo/Api.class"),
                )
                # OpenJDK selects versions/8 for runtime views 9+ even though
                # JEP 238 describes version directories as n > 8.  These
                # no-base entries prove that all Step4 stages follow runtime
                # lookup truth instead of silently treating them as base-only.
                archive.writestr(
                    "META-INF/versions/8/demo/EightOnly.class",
                    v8_only_archive.read("demo/EightOnly.class"),
                )
                archive.writestr(
                    "config/runtime.xml",
                    f"<beans><bean id='{side}-base'/></beans>",
                )
                archive.writestr(
                    "META-INF/versions/9/config/runtime.xml", selected_xml
                )
                archive.writestr(
                    "META-INF/versions/8/config/eight-only.xml",
                    b"<beans><bean id='must-not-be-selected'/></beans>",
                )
                archive.writestr(
                    "META-INF/services/demo.Api", "demo.Api\n"
                )
                archive.writestr(
                    "META-INF/versions/9/META-INF/services/demo.Api",
                    "demo.DoesNotExist\n",
                )
                archive.writestr("lib/empty.jar", dummy.read_bytes())
            side_meta[side] = {
                "artifact_path": str(outer),
                "artifact_sha256": hashlib.sha256(
                    outer.read_bytes()
                ).hexdigest(),
            }
            side_entries[side] = [{
                "coord": "com.acme:empty",
                "version": version,
                "scope": "runtime",
                "lib_entry": "lib/empty.jar",
                "resolution_status": "resolved",
            }]

        manifest_path, _ = s1_dep_diff.materialize_changed_dependency_jars(
            [],
            side_meta,
            dependencies,
            base_entries=side_entries["base"],
            current_entries=side_entries["current"],
        )
        step1_manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        for business in step1_manifest["business_artifacts"]:
            with zipfile.ZipFile(business["retained_path"]) as archive:
                self.assertEqual(
                    archive.read("META-INF/MANIFEST.MF"), manifest_bytes
                )
                self.assertIn(
                    "META-INF/versions/9/config/runtime.xml",
                    archive.namelist(),
                )
                self.assertIn(
                    "META-INF/versions/8/config/eight-only.xml",
                    archive.namelist(),
                )
                self.assertIn(
                    "META-INF/versions/8/demo/EightOnly.class",
                    archive.namelist(),
                )
        (dependencies / "build_provenance.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v2",
                "sides": [{
                    "side": side,
                    "target_module": "app",
                    "jdk_home": str(self.home),
                    "artifact_path": row["artifact_path"],
                    "artifact_sha256": row["artifact_sha256"],
                } for side, row in sorted(side_meta.items())],
            }),
            encoding="utf-8",
        )
        config = materialize_binary_pipeline_config(report)
        config["asm_jar"] = str(self.asm_jar)
        config["source_usage"] = {
            "decision": "skip_source",
            "decision_source": "explicit_config",
        }
        for side in (config["base"], config["current"]):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "demo/Api",
                    "member_name": "value",
                    "descriptor": "()I",
                }],
            }
            side["runtime_profile"]["entrypoint_discovery_coverage_gaps"] = []

        output = report / ".runtime" / "binary-authority"
        result = run_pipeline(config, output_root=output)

        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(
            Path(result["validation_result_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(validation["issue_count"], 0)
        connection = sqlite3.connect(
            Path(result["generation_directory"])
            / "current_binary_facts.sqlite"
        )
        try:
            resources = {
                name: (digest, physical_name)
                for name, digest, physical_name in connection.execute(
                    "SELECT resources.resource_name,resources.content_sha256,"
                    "archive_entries.name FROM resources JOIN archive_entries "
                    "USING(physical_entry_identity)"
                )
            }
            classes = [
                row[0] for row in connection.execute(
                    "SELECT physical_entry_label FROM classes"
                )
            ]
            v8_physical_evidence = {
                name: json.loads(entry_json)["runtime_effective"]
                for name, entry_json in connection.execute(
                    "SELECT name,entry_json FROM archive_entries "
                    "WHERE name LIKE 'META-INF/versions/8/%'"
                )
            }
        finally:
            connection.close()
        self.assertEqual(
            resources["config/runtime.xml"],
            (
                expected_selected_xml["current"],
                "META-INF/versions/9/config/runtime.xml",
            ),
        )
        self.assertEqual(
            resources["META-INF/services/demo.Api"][1],
            "META-INF/services/demo.Api",
        )
        self.assertNotIn(
            "META-INF/versions/9/config/runtime.xml", resources
        )
        self.assertEqual(
            resources["config/eight-only.xml"][1],
            "META-INF/versions/8/config/eight-only.xml",
        )
        self.assertEqual(
            sorted(classes),
            [
                "META-INF/versions/8/demo/EightOnly.class#occurrence=0",
                "META-INF/versions/9/demo/Api.class#occurrence=0",
            ],
        )
        self.assertEqual(
            v8_physical_evidence,
            {
                "META-INF/versions/8/config/eight-only.xml": True,
                "META-INF/versions/8/demo/EightOnly.class": True,
            },
        )
        progress = json.loads(
            (output / "binary_observability" / "latest_in_progress.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            progress["last_completed_phase"],
            "validated_generation_activation",
        )


if __name__ == "__main__":
    unittest.main()
