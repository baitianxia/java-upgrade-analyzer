import contextlib
import errno
import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
import warnings
from pathlib import Path, PureWindowsPath
from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock, patch
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_validation_oracle as oracle  # noqa: E402
from binary_tool_execution import BinaryToolFailure, BinaryToolResult  # noqa: E402


class BinaryValidationOracleBoundaryTest(unittest.TestCase):
    def test_execution_shape_and_artifact_identity_boundary_matrix(self):
        gib = 1024 * 1024 * 1024
        memory_cases = (
            (None, 4_000, 2),
            (gib, 500, 1),
            (3 * gib, 1_000, 1),
            (6 * gib, 4_000, 1),
            (12 * gib, 8_000, 2),
            (20 * gib, 12_000, 3),
        )
        for available, expected_limit, expected_workers in memory_cases:
            effect = RuntimeError("memory unavailable") if available is None else available
            with (
                patch.object(
                    oracle, "system_available_memory_bytes", side_effect=effect
                    if isinstance(effect, Exception) else None,
                    return_value=None if isinstance(effect, Exception) else effect,
                ),
                patch.object(oracle.os, "cpu_count", return_value=16),
                patch.object(
                    oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 20_000,
                ),
            ):
                batch, workers, observed = oracle._runtime_oracle_execution_shape(
                    oracle.MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE * 20,
                )
            self.assertEqual(batch, expected_limit)
            self.assertEqual(workers, expected_workers)
            self.assertEqual(observed, available)

        with (
            patch.object(oracle, "system_available_memory_bytes", return_value=20 * gib),
            patch.object(oracle.os, "cpu_count", return_value=None),
            patch.object(oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 1_000),
        ):
            self.assertEqual(oracle._runtime_oracle_execution_shape(-3)[:2], (1_000, 1))
            self.assertEqual(
                oracle._runtime_oracle_execution_shape(
                    oracle.MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE
                )[:2],
                (1_000, 1),
            )

        worker_cases = (
            (None, 4), (gib, 1), (3 * gib, 2), (6 * gib, 4), (20 * gib, 8),
        )
        for available, maximum in worker_cases:
            effect = RuntimeError("memory unavailable") if available is None else available
            with (
                patch.object(
                    oracle, "system_available_memory_bytes", side_effect=effect
                    if isinstance(effect, Exception) else None,
                    return_value=None if isinstance(effect, Exception) else effect,
                ),
                patch.object(oracle.os, "cpu_count", return_value=None),
            ):
                count, observed = oracle._artifact_scan_worker_count(99)
            self.assertEqual(count, 1)
            self.assertEqual(observed, available)
            self.assertGreaterEqual(maximum, count)
        with (
            patch.object(oracle, "system_available_memory_bytes", return_value=20 * gib),
            patch.object(oracle.os, "cpu_count", return_value=64),
        ):
            self.assertEqual(oracle._artifact_scan_worker_count(-1)[0], 0)
            self.assertEqual(oracle._artifact_scan_worker_count(3)[0], 3)

        rows = [["text", None, True, 3, 1.25]]
        native = oracle._artifact_truth_identity("boundary", rows)
        with patch.object(oracle, "_NATIVE_ARTIFACT_IDENTITY_MAX_ROWS", 0):
            streaming = oracle._artifact_truth_identity("boundary", rows)
        self.assertEqual(native, streaming)
        self.assertRegex(native, r"^[0-9a-f]{64}$")
        for non_native in (
            ["not-a-row"],
            [[{"nested": "value"}]],
        ):
            self.assertRegex(
                oracle._artifact_truth_identity("boundary", non_native),
                r"^[0-9a-f]{64}$",
            )
        with patch.object(
            oracle, "_NATIVE_ARTIFACT_IDENTITY_MAX_ESTIMATED_BYTES", 1,
        ):
            self.assertRegex(
                oracle._artifact_truth_identity("boundary", [["large"]]),
                r"^[0-9a-f]{64}$",
            )

    def test_generation_identity_safe_names_and_json_equality_matrix(self):
        valid = {
            "schema": "java-upgrade-analyzer.binary-result-generation.v1",
            "authority": "binary_first",
            "active_snapshot_identities": {
                layer: "snapshot-" + layer
                for layer in oracle._RESULT_GENERATION_SNAPSHOT_LAYERS
            },
            "sidecar_content_identities": {
                name: "sidecar-" + name
                for name in oracle._REQUIRED_PIPELINE_GENERATION_SIDECARS
            },
            "policy_identities": {},
            "analysis_context_identity": "context",
            "trace_result_set_digest": "trace",
        }
        self.assertRegex(
            oracle._expected_result_generation_identity(valid), r"^[0-9a-f]{64}$",
        )
        mutations = (
            ("schema", "wrong"),
            ("authority", "legacy"),
            ("active_snapshot_identities", []),
            ("active_snapshot_identities", {}),
            ("sidecar_content_identities", []),
            ("sidecar_content_identities", {}),
            ("policy_identities", []),
            ("analysis_context_identity", 1),
            ("analysis_context_identity", ""),
            ("trace_result_set_digest", 1),
            ("trace_result_set_digest", ""),
        )
        for field, value in mutations:
            candidate = dict(valid)
            candidate[field] = value
            self.assertIsNone(
                oracle._expected_result_generation_identity(candidate), field,
            )
        candidate = json.loads(json.dumps(valid))
        first_layer = next(iter(candidate["active_snapshot_identities"]))
        candidate["active_snapshot_identities"][first_layer] = ""
        self.assertIsNone(oracle._expected_result_generation_identity(candidate))
        candidate = json.loads(json.dumps(valid))
        candidate["active_snapshot_identities"][first_layer] = 1
        self.assertIsNone(oracle._expected_result_generation_identity(candidate))

        for value in (None, 3, "", ".", "..", "a/b", "a\\b", "a\x00b"):
            self.assertFalse(oracle._safe_generation_sidecar_name(value), value)
        self.assertTrue(oracle._safe_generation_sidecar_name("facts.json"))

        equal_pairs = (
            ({}, {}),
            ({"a": [1, {"b": "x"}]}, {"a": (1, {"b": "x"})}),
            ([1, 2], (1, 2)),
            (True, True),
        )
        for left, right in equal_pairs:
            self.assertTrue(oracle._same_json_value(left, right))
        unequal_pairs = (
            ({"a": 1}, {"b": 1}),
            ({"a": 1}, {"a": 2}),
            ([1], [1, 2]),
            ([1, 2], [1, 3]),
            (True, 1),
            (1, 1.0),
            ("a", "b"),
        )
        for left, right in unequal_pairs:
            self.assertFalse(oracle._same_json_value(left, right))
        for left, right in (
            ({}, []), ([], {}), ({}, {"a": 1}),
            ({"a": 1}, {"a": 2}), ([1], (2,)),
        ):
            self.assertFalse(oracle._same_json_value(left, right), (left, right))
        self.assertTrue(oracle._same_json_value([], ()))

    def test_storage_manifest_and_foundational_helper_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            valid_json = root / "valid.json"
            valid_json.write_text('{"value": 1}', encoding="utf-8")
            self.assertEqual(oracle._load_json(valid_json), {"value": 1})
            for name, payload in (("array.json", "[]"), ("bad.json", "{")):
                path = root / name
                path.write_text(payload, encoding="utf-8")
                with self.assertRaises(oracle.BinaryValidationError):
                    oracle._load_json(path)
            with self.assertRaises(oracle.BinaryValidationError):
                oracle._load_json(root / "missing.json")

            ordinary_100 = root / "ordinary-100.bin"
            ordinary_100.write_bytes(b"x" * 100)
            self.assertEqual(
                oracle._sqlite_logical_content_sha256(ordinary_100),
                hashlib.sha256(ordinary_100.read_bytes()).hexdigest(),
            )

            jdk = root / "jdk"
            jdk.mkdir()
            (jdk / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\nINVALID\nOS_NAME="Test"\n',
                encoding="utf-8",
            )
            self.assertEqual(oracle._release_values(jdk)["OS_NAME"], "Test")
            self.assertEqual(oracle._release_major(jdk), 8)
            with patch.object(
                oracle,
                "resolve_jdk_release",
                return_value={
                    "values": {"JAVA_VERSION": "17.0.12", "OS_NAME": "Probe"},
                    "identity": "b" * 64,
                    "source": "java-properties-probe",
                },
            ):
                self.assertEqual(oracle._release_major(jdk), 17)
                self.assertEqual(oracle._release_values(jdk)["OS_NAME"], "Probe")
            (jdk / "release").write_text(
                'JAVA_VERSION="unknown"\n', encoding="utf-8",
            )
            with self.assertRaises(oracle.BinaryValidationError):
                oracle._release_major(jdk)
            with self.assertRaises(oracle.BinaryValidationError):
                oracle._release_values(root / "missing-jdk")
            with patch.object(
                oracle, "resolve_jdk_release", side_effect=OSError("unreadable")
            ), self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._release_values(jdk)
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_JDK_RELEASE_MISSING",
            )

            def manifest_result(label, entries):
                archive_path = root / f"{label}.jar"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    for name, value in entries:
                        archive.writestr(name, value)
                with zipfile.ZipFile(archive_path) as archive:
                    return oracle._manifest_multi_release(archive)

            self.assertFalse(manifest_result("empty", []))
            self.assertTrue(manifest_result("canonical", [(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nMulti-Release: true",
            )]))
            self.assertFalse(manifest_result("orphan-continuation", [(
                "META-INF/MANIFEST.MF", " orphan\nInvalid\n",
            )]))
            self.assertFalse(manifest_result("false-value", [(
                "META-INF/MANIFEST.MF", "Multi-Release: false\n",
            )]))
            self.assertFalse(manifest_result("spaced-key", [(
                "META-INF/MANIFEST.MF", " Multi-Release: true\n",
            )]))
            self.assertFalse(manifest_result("directory-only", [(
                "META-INF/MANIFEST.MF/", b"",
            )]))
            self.assertFalse(manifest_result("continued", [(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nMulti-Release: tr\n ue\n",
            )]))
            self.assertFalse(manifest_result("duplicate", [
                ("META-INF/MANIFEST.MF", "Multi-Release: true\n"),
                ("meta-inf/manifest.mf", "Multi-Release: true\n"),
            ]))

            required = {
                name: "a" * 64
                for name in oracle._REQUIRED_PIPELINE_GENERATION_SIDECARS
            }
            self.assertTrue(oracle._generation_sidecar_declaration_issues(
                {}, root, {},
            ))
            self.assertEqual(
                oracle._generation_sidecar_declaration_issues({}, root, required),
                [],
            )
            declared_optional = {
                **required,
                **{
                    name: "b" * 64
                    for name in oracle._RESERVED_OPTIONAL_GENERATION_SIDECARS
                },
            }
            self.assertTrue(oracle._generation_sidecar_declaration_issues(
                {}, root, declared_optional,
            ))
            self.assertTrue(oracle._generation_sidecar_declaration_issues(
                {"source_overlay": {"source_sets": []}}, root, required,
            ))
            self.assertEqual(
                oracle._generation_sidecar_declaration_issues(
                    {"source_overlay": {"source_sets": []}},
                    root,
                    declared_optional,
                ),
                [],
            )
            reserved = root / next(iter(
                oracle._RESERVED_OPTIONAL_GENERATION_SIDECARS
            ))
            reserved.write_text("{}", encoding="utf-8")
            self.assertTrue(oracle._generation_sidecar_declaration_issues(
                {}, root, required,
            ))
            transient = root / "base_binary_facts.sqlite-journal"
            transient.write_bytes(b"journal")
            self.assertTrue(oracle._generation_sidecar_declaration_issues(
                {}, root, required,
            ))
            with patch.object(Path, "is_symlink", return_value=True):
                self.assertTrue(oracle._generation_sidecar_declaration_issues(
                    {}, root, required,
                ))

            formatted = root / "formatted.json"
            formatted.write_text(
                '{\n  "rows": [{"id": 1}]\n}', encoding="utf-8",
            )
            with patch.object(
                oracle, "iter_canonical_json_object_array",
                side_effect=oracle.StreamingJsonReadError("noncanonical"),
            ):
                self.assertEqual(list(oracle._iter_sidecar_object_rows(
                    root, formatted.name, "rows",
                )), [{"id": 1}])
                for payload in ('{"rows": [1]}', '{"rows": {}}'):
                    formatted.write_text(payload, encoding="utf-8")
                    with self.assertRaises(oracle.BinaryValidationError):
                        list(oracle._iter_sidecar_object_rows(
                            root, formatted.name, "rows",
                        ))
                with self.assertRaises(oracle.BinaryValidationError):
                    list(oracle._iter_sidecar_object_rows(
                        root, "missing-sidecar.json", "rows",
                    ))

            progress = []
            indexed = root / "binary_decisions.json"
            indexed.write_text("{}", encoding="utf-8")
            with patch.object(oracle, "prime_canonical_json_fields") as prime:
                oracle._prime_large_sidecar_fields(root)
                oracle._prime_large_sidecar_fields(
                    root, lambda *args: progress.append(args),
                )
            self.assertEqual(prime.call_count, 2)
            self.assertTrue(progress)
            empty = root / "empty-generation"
            empty.mkdir()
            oracle._prime_large_sidecar_fields(empty)

            short_left = root / "short-left.bin"
            short_right = root / "short-right.bin"
            short_left.write_bytes(b"same")
            short_right.write_bytes(b"same")
            self.assertTrue(oracle._sqlite_logical_contents_equal(
                short_left, short_right,
            ))
            short_right.write_bytes(b"different-size")
            self.assertFalse(oracle._sqlite_logical_contents_equal(
                short_left, short_right,
            ))
            bad_left = root / "bad-left.sqlite"
            bad_right = root / "bad-right.sqlite"
            bad_left.write_bytes(b"x" * 100)
            bad_right.write_bytes(b"x" * 100)
            self.assertTrue(oracle._sqlite_logical_contents_equal(
                bad_left, bad_right,
            ))
            valid_header = bytearray(100)
            valid_header[:16] = b"SQLite format 3\x00"
            bad_left.write_bytes(valid_header)
            self.assertFalse(oracle._sqlite_logical_contents_equal(
                bad_left, bad_right,
            ))

            class TruncatedDuringRead:
                def __init__(self, content):
                    self.content = content

                def stat(self):
                    return SimpleNamespace(st_size=100)

                def open(self, _mode):
                    return io.BytesIO(self.content)

            self.assertFalse(oracle._sqlite_logical_contents_equal(
                TruncatedDuringRead(bytes(valid_header)),
                TruncatedDuringRead(b"x" * 99),
            ))
            valid_right = bytearray(valid_header)
            valid_right[30] = 1
            bad_right.write_bytes(valid_right)
            self.assertFalse(oracle._sqlite_logical_contents_equal(
                bad_left, bad_right,
            ))

            good = root / "good.jar"
            good.write_bytes(b"stable")
            digest = hashlib.sha256(b"stable").hexdigest()
            issues, truth = oracle._final_artifact_stability((
                ("base", [{"path": good, "sha256": digest, "slot": 0}]),
                ("current", [{
                    "path": root / "absent.jar", "sha256": digest,
                    "loader_realm": "app", "slot": 1,
                }]),
            ))
            self.assertEqual(len(issues), 1)
            self.assertEqual(truth[0]["loader_realm"], "")

        provider_cases = (
            ({
                "provider_resource_url": "file:/resource.jar",
                "provider_url": "file:/code.jar",
            }, "file:/resource.jar"),
            ({
                "provider_resource_url": "<resource-error:x>",
                "provider_url": "file:/code.jar",
            }, "file:/code.jar"),
            ({
                "provider_resource_url": "",
                "provider_url": "<code-error:x>",
            }, ""),
            ({}, ""),
        )
        for observation, expected in provider_cases:
            self.assertEqual(
                oracle._oracle_provider_location(observation), expected,
            )
        self.assertIsNone(oracle._provider_resource_path(None))
        self.assertEqual(
            oracle._provider_resource_path(
                "jar:file:/tmp/provider.jar!/demo/Api.class"
            ),
            Path("/tmp/provider.jar").resolve(),
        )
        self.assertEqual(
            oracle._provider_resource_path("file:/tmp/provider.jar"),
            Path("/tmp/provider.jar").resolve(),
        )
        for value in (
            "file:/C:/workspace/provider.jar",
            "file:///C:/workspace/provider.jar",
            "file://C:/workspace/provider.jar",
            "jar:file:/C:/workspace/provider.jar!/demo/Api.class",
        ):
            resource = value[4:].split("!/", 1)[0] if value.startswith("jar:") else value
            decoded = oracle._decoded_file_url_path(
                oracle.urlparse(resource), windows=True
            )
            self.assertEqual(
                PureWindowsPath(decoded),
                PureWindowsPath("C:/workspace/provider.jar"),
            )
            self.assertNotIn("C:\\C:", decoded)
        self.assertEqual(
            PureWindowsPath(oracle._decoded_file_url_path(
                oracle.urlparse("file://server/share/provider.jar"),
                windows=True,
            )),
            PureWindowsPath("//server/share/provider.jar"),
        )

        class CapturingPath:
            def __init__(self, value):
                self.value = str(value)

            def resolve(self):
                return self.value

        oracle._file_url_path.cache_clear()
        try:
            with patch.object(oracle.os, "name", "nt"), patch.object(
                oracle, "Path", CapturingPath,
            ):
                self.assertEqual(
                    oracle._provider_resource_path(
                        "jar:file:/C:/workspace/provider.jar!/demo/Api.class"
                    ),
                    r"C:\workspace\provider.jar",
                )
        finally:
            oracle._file_url_path.cache_clear()

        self.assertEqual(
            oracle._descriptor_return_class("()Ldemo/Type;"), "demo/Type",
        )
        self.assertEqual(oracle._descriptor_return_class("()Lbroken"), "")
        self.assertEqual(oracle._oracle_type_provider_owner("[Lbroken"), "")
        self.assertEqual(
            oracle._independent_resource_category(
                "META-INF/spring/not-imports"
            ),
            "unknown",
        )

        subtype_observations = {
            "cycle/A": {"super_name": "cycle/B", "interfaces": []},
            "cycle/B": {"super_name": "cycle/A", "interfaces": []},
        }
        self.assertFalse(oracle._is_subtype(
            subtype_observations, "cycle/A", "missing/Type",
        ))
        self.assertFalse(
            oracle._is_subtype({}, "missing/Child", "missing/Parent")
        )

        contexts = oracle._oracle_runtime_contexts(
            {
                "demo/File": {
                    "status": "definition_ready",
                    "provider_url": "file:/app.jar",
                    "super_name": "demo/Missing",
                    "interfaces": ["demo/File"],
                },
                "demo/Platform": {
                    "status": "definition_ready",
                    "provider_url": "jrt:/java.base",
                    "super_name": "demo/PlatformParent",
                    "interfaces": [],
                },
                "demo/NoProvider": {
                    "status": "definition_ready",
                    "provider_url": "",
                    "super_name": "",
                    "interfaces": [],
                },
            },
            [
                "", "[I", "demo/File", "demo/Platform",
                "demo/NoProvider", "demo/Unknown", "demo/Unknown",
            ],
            ["", "app"],
            "platform",
        )
        self.assertIn(("app", "demo/Unknown"), contexts)
        self.assertIn(("platform", "demo/PlatformParent"), contexts)

        reference = {
            "not-mapping": 1,
            "proxy": MappingProxyType({"value": ["same"]}),
            "missing-key": {"a": 1},
        }
        candidate = {
            "not-mapping": {"value": 1},
            "proxy": MappingProxyType({"value": ["same"]}),
            "missing-key": {"a": 1, "b": 2},
        }
        rows, values = oracle._share_equal_observation_values(
            reference, candidate,
        )
        self.assertEqual(rows, 1)
        self.assertGreaterEqual(values, 1)

        class FakeConnection:
            def __init__(self, count):
                self.count = count

            def execute(self, *_args):
                records = [{"payload": {"status": "ready"}}]
                return [{
                    "record_count": self.count,
                    "payload_zlib": zlib.compress(
                        json.dumps(records).encode("utf-8")
                    ),
                }]

        self.assertEqual(list(oracle._iter_reconciliation(
            FakeConnection(1), "provider_binding",
        )), [{"status": "ready"}])
        with self.assertRaises(oracle.BinaryValidationError):
            list(oracle._iter_reconciliation(
                FakeConnection(2), "provider_binding",
            ))

        self.assertIsInstance(oracle._directory_open_flags(), int)
        with (
            patch.object(oracle.os, "O_DIRECTORY", 0, create=True),
            patch.object(oracle.os, "O_NOFOLLOW", 0, create=True),
            patch.object(oracle.os, "O_BINARY", 0, create=True),
        ):
            self.assertEqual(
                oracle._directory_open_flags(), oracle.os.O_RDONLY,
            )
        with patch.object(oracle.os, "O_BINARY", 0x8000, create=True):
            self.assertTrue(oracle._directory_open_flags() & 0x8000)

        with (
            patch.object(oracle.os, "open", return_value=17) as opened,
            patch.object(
                oracle, "_owned_descriptor",
                return_value=contextlib.nullcontext(17),
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFDIR),
            ),
        ):
            with oracle._open_bound_directory(
                "child", dir_fd=9,
            ) as descriptor:
                self.assertEqual(descriptor, 17)
            self.assertEqual(opened.call_args.kwargs["dir_fd"], 9)
        with (
            patch.object(oracle.os, "open", return_value=18),
            patch.object(
                oracle, "_owned_descriptor",
                return_value=contextlib.nullcontext(18),
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFREG),
            ),
        ):
            with self.assertRaises(OSError):
                with oracle._open_bound_directory("file"):
                    pass
            with oracle._open_bound_regular_file(9, "file") as descriptor:
                self.assertEqual(descriptor, 18)
        with (
            patch.object(oracle.os, "open", return_value=19),
            patch.object(
                oracle, "_owned_descriptor",
                return_value=contextlib.nullcontext(19),
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFDIR),
            ),
        ):
            with self.assertRaises(OSError):
                with oracle._open_bound_regular_file(9, "directory"):
                    pass
        with (
            patch.object(oracle.os, "O_NOFOLLOW", 0, create=True),
            patch.object(oracle.os, "O_BINARY", 0x8000, create=True),
            patch.object(oracle.os, "open", return_value=21) as opened,
            patch.object(
                oracle, "_owned_descriptor",
                return_value=contextlib.nullcontext(21),
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFREG),
            ),
        ):
            with oracle._open_bound_regular_file(9, "portable"):
                pass
            self.assertTrue(opened.call_args.args[1] & 0x8000)

        def bound_file(_directory_fd, name):
            return contextlib.nullcontext(1 if name == "left" else 2)

        with (
            patch.object(
                oracle, "_open_bound_regular_file", side_effect=bound_file,
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_size=1),
            ),
            patch.object(oracle.os, "read", side_effect=[b"a", b"b"]),
        ):
            self.assertFalse(
                oracle._bound_files_equal(9, "left", "right")
            )
        with (
            patch.object(
                oracle, "_open_bound_regular_file", side_effect=bound_file,
            ),
            patch.object(
                oracle.os, "fstat",
                side_effect=[
                    SimpleNamespace(st_size=1),
                    SimpleNamespace(st_size=2),
                ],
            ),
        ):
            self.assertFalse(
                oracle._bound_files_equal(9, "left", "right")
            )
        with (
            patch.object(
                oracle, "_open_bound_regular_file", side_effect=bound_file,
            ),
            patch.object(
                oracle.os, "fstat",
                return_value=SimpleNamespace(st_size=1),
            ),
            patch.object(
                oracle.os, "read",
                side_effect=[b"a", b"a", b"", b""],
            ),
        ):
            self.assertTrue(
                oracle._bound_files_equal(9, "left", "right")
            )
        with patch.object(
            oracle, "_open_bound_regular_file", side_effect=OSError("missing"),
        ):
            self.assertFalse(
                oracle._bound_files_equal(9, "left", "right")
            )

        with patch.object(oracle.os, "fsync", return_value=None):
            self.assertTrue(oracle._fsync_bound_directory(9))
        unsupported_errno = next(iter(
            oracle._DIRECTORY_FSYNC_UNSUPPORTED_ERRNOS
        ))
        with patch.object(
            oracle.os, "fsync",
            side_effect=OSError(unsupported_errno, "unsupported"),
        ):
            self.assertFalse(oracle._fsync_bound_directory(9))
        with patch.object(
            oracle.os, "fsync", side_effect=OSError(errno.EIO, "failed"),
        ):
            with self.assertRaises(OSError):
                oracle._fsync_bound_directory(9)

        with tempfile.TemporaryFile() as destination:
            oracle._write_json_descriptor(destination.fileno(), {"value": 1})
            destination.seek(0)
            self.assertEqual(
                json.loads(destination.read().decode("utf-8")), {"value": 1},
            )
        large_result = {
            "issues": [
                {"domain": "provider", "index": index, "text": "问题" * 8}
                for index in range(20_000)
            ]
        }
        real_write = os.write
        write_sizes = []

        def observed_write(descriptor, payload):
            write_sizes.append(len(payload))
            return real_write(descriptor, payload)

        with tempfile.TemporaryFile() as destination, patch.object(
            oracle.os, "write", side_effect=observed_write,
        ), patch.object(
            oracle,
            "surrogate_safe_json_dumps",
            side_effect=AssertionError("full JSON serialization is forbidden"),
        ):
            oracle._write_json_descriptor(destination.fileno(), large_result)
            size = destination.seek(0, os.SEEK_END)
        self.assertGreater(size, 1_000_000)
        self.assertGreater(len(write_sizes), 10)
        self.assertLess(max(write_sizes), 128 * 1024)
        with patch.object(oracle.os, "write", return_value=0):
            with self.assertRaises(OSError):
                oracle._write_json_descriptor(9, {"value": 1})
        write_calls = 0

        def body_then_stall(_descriptor, remaining):
            nonlocal write_calls
            write_calls += 1
            return len(remaining) if write_calls == 1 else 0

        with patch.object(oracle.os, "write", side_effect=body_then_stall):
            with self.assertRaises(OSError):
                oracle._write_json_descriptor(9, {"value": 1})

        expected_path = Path("/generation/run.json")
        with (
            patch.object(
                oracle, "_secure_validation_dirfd_supported",
                return_value=True,
            ),
            patch.object(
                oracle, "_write_validation_attachment_dirfd",
                return_value=expected_path,
            ) as secure,
            patch.object(oracle, "_write_validation_attachment_portable") as portable,
        ):
            self.assertEqual(oracle._write_validation_attachment(
                Path("/generation"), "run", {"status": "passed"},
            ), expected_path)
            secure.assert_called_once()
            portable.assert_not_called()
        with (
            patch.object(
                oracle, "_secure_validation_dirfd_supported",
                return_value=False,
            ),
            patch.object(
                oracle, "_write_validation_attachment_portable",
                return_value=expected_path,
            ) as portable,
        ):
            self.assertEqual(oracle._write_validation_attachment(
                Path("/generation"), "run", {"status": "passed"},
            ), expected_path)
            portable.assert_called_once()

        compact = oracle._CompactObservation({"status": "ready"})
        pool = {}
        compacted = oracle._compact_observations({
            "demo/Compact": compact,
            "demo/Plain": {"values": ["same", "same"]},
        }, pool)
        self.assertIs(compacted["demo/Compact"], compact)
        self.assertIsInstance(compacted["demo/Plain"], oracle._CompactObservation)
        already_compacted = oracle._compact_observations(
            {"demo/Plain": {"values": ("same",)}}, pool,
            values_compacted=True,
        )
        self.assertEqual(already_compacted["demo/Plain"]["values"], ("same",))

        class FallbackNoteError(Exception):
            add_note = None

        fallback = FallbackNoteError("fallback")
        oracle._add_validation_cleanup_note(fallback, "first")
        oracle._add_validation_cleanup_note(fallback, "second")
        self.assertEqual(fallback.__notes__, ["first", "second"])

        class RaisingNoteError(Exception):
            def add_note(self, _note):
                raise RuntimeError("note failed")

        raising = RaisingNoteError("raising")
        oracle._add_validation_cleanup_note(raising, "fallback-note")
        self.assertEqual(raising.__notes__, ["fallback-note"])

        with patch.object(
            oracle.os, "close", side_effect=OSError("close"),
        ):
            with self.assertRaises(OSError):
                with oracle._owned_descriptor(20, "boundary"):
                    pass

    def test_spool_cache_and_closed_world_index_boundary_matrix(self):
        compact = oracle._CompactObservation({
            "status": "ready", "future_field": ("preserved",),
        })
        self.assertEqual(compact["status"], "ready")
        self.assertEqual(compact["future_field"], ("preserved",))
        with self.assertRaises(KeyError):
            compact["members"]
        with self.assertRaises(KeyError):
            compact["absent_future_field"]
        self.assertEqual(set(compact), {"status", "future_field"})
        self.assertEqual(len(compact), 2)

        artifact_sha = "a" * 64
        evidence = oracle._OracleScanEvidence(
            artifact_sha256=artifact_sha,
            complete=True,
            failures=("non_blocking_note",),
            direct_truth=oracle._DirectEdgeTruth(
                artifact_sha256=artifact_sha,
                direct_edges=frozenset({("caller", "target")}),
                dynamic_handle_edges=frozenset({("dynamic", "target")}),
                discovery_classes=frozenset({"demo/Class"}),
            ),
            structural_truth=oracle._StructuralTruth(
                type_edges=frozenset({("caller", "type")}),
                class_init_edges=frozenset({("caller", "clinit")}),
                clinit_classes=frozenset({"demo/Class"}),
                semantic_instructions=frozenset({
                    ("caller", "invoke", ("nested", "value")),
                }),
                declared_members=frozenset({
                    ("demo/Class", "method", "run", "()V", 1),
                }),
                failures=(),
            ),
            structural_class_names=frozenset({"demo/Class"}),
        )
        key = (artifact_sha, "javap")
        cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=0)
        self.addCleanup(cache.clear)
        sentinel = object()
        self.assertIs(cache.get(key, sentinel), sentinel)

        raw = {
            "artifact_sha256": artifact_sha,
            "complete": True,
            "failures": [],
            "edges": [],
            "structural_facts": {
                "type_edges": [], "class_init_edges": [],
                "clinit_classes": [], "semantic_instructions": [],
                "declared_members": [], "class_names": [],
            },
        }
        cache.put_result(key, raw)
        self.assertIsInstance(cache.get(key), bytes)
        prior = cache._entries[key]
        cache.put_evidence(key, evidence)
        self.assertTrue(prior.closed)
        self.assertIs(cache.get(key), cache)

        pooled = {}
        self.assertEqual(
            cache.get_projection(key, "discovery_classes", pooled),
            frozenset({"demo/Class"}),
        )
        self.assertEqual(
            cache.get_projection(key, "discovery_classes"),
            frozenset({"demo/Class"}),
        )
        self.assertEqual(
            cache._compact_projection_rows((("plain", 1),), None),
            frozenset({("plain", 1)}),
        )
        complete = cache.get_evidence(key, pooled)
        self.assertTrue(complete.complete)
        self.assertEqual(complete.failures, ("non_blocking_note",))
        self.assertEqual(
            cache.get_direct_evidence(key, pooled).direct_truth.direct_edges,
            frozenset({("caller", "target")}),
        )
        self.assertEqual(
            cache.get_structural_evidence(
                key, pooled,
            ).structural_truth.type_edges,
            frozenset({("caller", "type")}),
        )

        missing_key = ("b" * 64, "javap")
        for operation in (
            lambda: cache._projection(missing_key, "metadata"),
            lambda: cache.get_evidence(missing_key),
        ):
            with self.assertRaises(KeyError):
                operation()
        with self.assertRaises(KeyError):
            cache._projection(key, "not-a-projection")
        orphan_key = ("2" * 64, "javap")
        cache._entries[orphan_key] = io.BytesIO()
        with self.assertRaises(KeyError):
            cache._projection(orphan_key, "metadata")

        truncated_key = ("c" * 64, "javap")
        truncated_handle = io.BytesIO(b"x")
        cache._entries[truncated_key] = truncated_handle
        cache._projection_offsets[truncated_key] = {"metadata": (0, 2)}
        with self.assertRaises(oracle.BinaryValidationError) as raised:
            cache._projection(truncated_key, "metadata")
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_ORACLE_SHARED_SCAN_TRUNCATED",
        )

        incomplete_key = ("d" * 64, "javap")
        cache.put_evidence(
            incomplete_key,
            oracle._incomplete_oracle_scan_evidence(
                incomplete_key[0], ("scanner_failed",),
            ),
        )
        for view in (
            cache.get_evidence(incomplete_key),
            cache.get_direct_evidence(incomplete_key),
            cache.get_structural_evidence(incomplete_key),
        ):
            self.assertFalse(view.complete)
            self.assertEqual(view.failures, ("scanner_failed",))

        empty_metadata_key = ("3" * 64, "javap")
        cache.put_evidence(
            empty_metadata_key,
            oracle._incomplete_oracle_scan_evidence("", ()),
        )
        self.assertFalse(cache.get_evidence(empty_metadata_key).complete)
        self.assertFalse(cache.get_direct_evidence(empty_metadata_key).complete)
        self.assertFalse(
            cache.get_structural_evidence(empty_metadata_key).complete,
        )

        raw_direct_key = ("e" * 64, "javap")
        raw_direct = dict(raw, artifact_sha256=raw_direct_key[0])
        cache.put_result(raw_direct_key, raw_direct)
        self.assertEqual(
            cache.get_projection(raw_direct_key, "discovery_classes"),
            frozenset(),
        )
        self.assertTrue(cache.get_direct_evidence(raw_direct_key).complete)
        raw_structural_key = ("f" * 64, "javap")
        raw_structural = dict(raw, artifact_sha256=raw_structural_key[0])
        cache.put_result(raw_structural_key, raw_structural)
        self.assertTrue(
            cache.get_structural_evidence(raw_structural_key).complete,
        )
        raw_direct_only_key = ("0" * 64, "javap")
        cache.put_result(
            raw_direct_only_key,
            dict(raw, artifact_sha256=raw_direct_only_key[0]),
        )
        self.assertTrue(cache.get_direct_evidence(raw_direct_only_key).complete)

        failed_handle = MagicMock()
        failed_handle.tell.return_value = 0
        failed_handle.write.side_effect = OSError("spool full")
        with (
            patch.object(cache, "_new_handle", return_value=failed_handle),
            self.assertRaises(OSError),
        ):
            cache.put_evidence(("1" * 64, "javap"), evidence)
        failed_handle.close.assert_called_once_with()

        source = oracle._SpoolStructuralInstructionSource(
            cache,
            ({"sha256": key[0]}, {"sha256": "9" * 64}),
            "javap",
            pooled,
        )
        iterator = source.iter_batches()
        self.assertEqual(
            next(iterator),
            frozenset({("caller", "invoke", ("nested", "value"))}),
        )
        with self.assertRaises(oracle.BinaryValidationError) as raised:
            next(iterator)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_ORACLE_SHARED_SCAN_MISSING",
        )
        empty_source = oracle._SpoolStructuralInstructionSource(
            cache, (), "javap",
        )
        self.assertEqual(list(empty_source), [])
        complete_source = oracle._SpoolStructuralInstructionSource(
            cache, ({"sha256": key[0]},), "javap",
        )
        self.assertEqual(
            list(complete_source),
            [("caller", "invoke", ("nested", "value"))],
        )
        missing_with_path = oracle._SpoolStructuralInstructionSource(
            cache,
            ({"sha256": "8" * 64, "path": "missing.jar"},),
            "javap",
        )
        with self.assertRaises(oracle.BinaryValidationError):
            next(iter(missing_with_path))

        production = oracle._ProductionStructuralSpoolCache(memory_limit=0)
        self.assertNotIn("artifact", production)
        with self.assertRaises(oracle.BinaryValidationError) as raised:
            production.get("artifact")
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_ORACLE_PRODUCTION_STRUCTURAL_CACHE_MISSING",
        )
        production.put(
            "artifact", (("owner", "type"),), (("owner", "clinit"),),
        )
        self.assertIn("artifact", production)
        self.assertEqual(
            production.get("artifact"),
            ({("owner", "type")}, {("owner", "clinit")}),
        )
        production.put("empty-artifact", (), ())
        self.assertEqual(production.get("empty-artifact"), (set(), set()))
        offset, length = production._offsets["artifact"]
        production._offsets["artifact"] = (offset, length + 1_000_000)
        with self.assertRaises(oracle.BinaryValidationError) as raised:
            production.get("artifact")
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_ORACLE_PRODUCTION_STRUCTURAL_CACHE_TRUNCATED",
        )
        production.clear()
        production.clear()

        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        progress = []
        connection.execute("CREATE TABLE batches(value INTEGER)")
        self.assertEqual(
            oracle._ClosedWorldGraphIndex._insert_batches(
                connection,
                "INSERT INTO batches VALUES (?)",
                ((value,) for value in range(5)),
                batch_size=2,
                progress=progress.append,
            ),
            5,
        )
        self.assertEqual(progress, [2, 4, 5])
        self.assertEqual(
            oracle._ClosedWorldGraphIndex._insert_batches(
                connection, "INSERT INTO batches VALUES (?)", (),
            ),
            0,
        )
        self.assertEqual(
            oracle._ClosedWorldGraphIndex._insert_batches(
                connection,
                "INSERT INTO batches VALUES (?)",
                ((20,), (21,)),
                batch_size=1,
            ),
            2,
        )

        connection.execute("ATTACH DATABASE ':memory:' AS facts")
        connection.executescript("""
            CREATE TABLE facts.direct_edges (
                direct_edge_identity TEXT, caller_member_identity TEXT,
                edge_kind TEXT, symbolic_owner TEXT, symbolic_name TEXT,
                symbolic_descriptor TEXT
            );
            CREATE TABLE member_resolution (
                evidence TEXT, status TEXT, resolved_member TEXT
            );
            CREATE TABLE dispatch_resolution (
                evidence TEXT, status TEXT, targets_json TEXT
            );
            CREATE TABLE type_resolution (evidence TEXT, status TEXT);
            CREATE TABLE initialization_resolution (
                evidence TEXT, status TEXT, targets_json TEXT
            );
            CREATE TABLE linkage_resolution (evidence TEXT, status TEXT);
            CREATE TABLE semantic_transition (
                caller TEXT, target TEXT, certainty TEXT, evidence TEXT
            );
        """)
        edges = (
            ("resolved-fallback", "caller", "method", "demo/A", "run", "()V"),
            ("possible-dispatch", "caller", "method", "demo/A", "run", "()V"),
            ("bootstrap", "caller", "invokedynamic_bootstrap", "demo/B", "bsm", "()V"),
            ("unresolved", "caller", "field", "demo/Missing", "value", "I"),
            ("unresolved-alias", "caller", "method", "demo/Missing", "run", "()V"),
            ("unresolved-empty", "caller", "method", "demo/Missing", "run", "()V"),
            ("resolved-empty", "caller", "method", "demo/A", "run", "()V"),
            ("empty-target", "caller", "method", "demo/A", "run", "()V"),
            ("member-irrelevant", "caller", "metadata", "demo/A", "", ""),
            ("type", "caller", "type", "demo/T", "", "Ldemo/T;"),
            ("array-type", "caller", "type", "[I", "", "[I"),
            ("init", "caller", "class_init", "demo/I", "", ""),
            ("init-empty", "caller", "class_init", "demo/I", "", ""),
            ("", "caller", "", "", "", ""),
            ("empty-caller", "", "metadata", "", "", ""),
            ("ignored", "other", "metadata", "demo/X", "", ""),
        )
        connection.executemany(
            "INSERT INTO facts.direct_edges VALUES (?,?,?,?,?,?)", edges,
        )
        connection.executemany(
            "INSERT INTO member_resolution VALUES (?,?,?)",
            (
                ("resolved-fallback", "resolved", "target/fallback"),
                ("possible-dispatch", "resolved", "target/resolved"),
                ("bootstrap", "resolved", "target/bootstrap"),
                ("unresolved", "no_such_member", ""),
                ("unresolved-alias", "no_class_definition", ""),
                ("unresolved-empty", "", ""),
                ("resolved-empty", "resolved", ""),
                ("empty-target", "resolved", "target/unused"),
                ("member-irrelevant", "resolved", "target/irrelevant"),
            ),
        )
        connection.executemany(
            "INSERT INTO dispatch_resolution VALUES (?,?,?)",
            (
                ("resolved-fallback", "exact", "[]"),
                ("possible-dispatch", "partial_possible_set", '["target/one"]'),
                ("bootstrap", "exact", '["target/bootstrap"]'),
                ("resolved-empty", "exact", "[]"),
                ("empty-target", "exact", '[""]'),
            ),
        )
        connection.executemany(
            "INSERT INTO type_resolution VALUES (?,?)",
            (("type", "resolved"), ("array-type", "primitive_or_array_type")),
        )
        connection.execute(
            "INSERT INTO initialization_resolution VALUES (?,?,?)",
            ("init", "resolved", '["target/init", ""]'),
        )
        connection.execute(
            "INSERT INTO initialization_resolution VALUES (?,?,?)",
            ("init-empty", "resolved", ""),
        )
        connection.execute(
            "INSERT INTO linkage_resolution VALUES (?,?)",
            ("resolved-fallback", "linked"),
        )
        connection.execute(
            "INSERT INTO linkage_resolution VALUES (?,?)", ("empty", ""),
        )
        connection.execute(
            "INSERT INTO semantic_transition VALUES (?,?,?,?)",
            ("caller", "target/semantic", "possible", "semantic-evidence"),
        )
        connection.commit()

        index = object.__new__(oracle._ClosedWorldGraphIndex)
        index.connection = connection
        index._paired_missing = {"paired-symbolic"}
        index._aliases = {"unresolved-alias": {"paired-symbolic"}}
        index._closed = False
        self.assertEqual(
            index._unresolved_certainty("no_such_member", "anything"),
            "exact",
        )
        self.assertEqual(
            index._unresolved_certainty(
                "class_definition_failed", "paired-symbolic",
            ),
            "exact",
        )
        self.assertEqual(
            index._unresolved_certainty("ambiguous", "anything"),
            "possible",
        )
        self.assertEqual(
            index._unresolved_certainty("ambiguous", "paired-symbolic"),
            "possible",
        )
        transitions = index.transitions("caller")
        self.assertIn(("target/fallback", "exact", "resolved-fallback"), transitions)
        self.assertIn(("target/one", "possible", "possible-dispatch"), transitions)
        self.assertIn(("target/bootstrap", "possible", "bootstrap"), transitions)
        self.assertIn(("target/init", "exact", "init"), transitions)
        self.assertIn(
            ("target/semantic", "possible", "semantic-evidence"), transitions,
        )
        self.assertEqual(
            index.relations_for_evidence("possible-dispatch"),
            [("caller", "target/one", "possible")],
        )
        self.assertEqual(
            index.relations_for_evidence("semantic-evidence"),
            [("caller", "target/semantic", "possible")],
        )
        self.assertEqual(index.resolution_status("resolved-fallback"), "resolved")
        self.assertEqual(index.resolution_status("missing"), "")
        self.assertEqual(index.linkage_status("resolved-fallback"), "linked")
        self.assertEqual(index.linkage_status("empty"), "")
        self.assertEqual(index.linkage_status("missing"), "")
        self.assertEqual(index._direct_relations(evidence="empty-caller"), [])
        with patch.object(
            index,
            "_direct_relations",
            return_value=[("different-caller", "target", "exact", "edge")],
        ):
            self.assertEqual(index.transitions("filter-only"), [])
        index.close()
        index.close()

    def test_closed_world_index_build_and_semantic_filter_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary)
            database = generation / "current_binary_facts.sqlite"
            connection = sqlite3.connect(database)
            connection.executescript("""
                CREATE TABLE direct_edges (
                    direct_edge_identity TEXT PRIMARY KEY,
                    caller_member_identity TEXT NOT NULL,
                    caller_artifact_instance_identity TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    symbolic_owner TEXT NOT NULL,
                    symbolic_name TEXT NOT NULL,
                    symbolic_descriptor TEXT NOT NULL
                );
                CREATE TABLE reconciliation_records (
                    chunk_identity BLOB PRIMARY KEY,
                    record_kind INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    payload_zlib BLOB NOT NULL
                );
            """)

            def add_chunk(kind, payloads):
                encoded = json.dumps([
                    {"payload": payload} for payload in payloads
                ]).encode("utf-8")
                connection.execute(
                    "INSERT INTO reconciliation_records VALUES (?,?,?,?)",
                    (
                        kind.encode("ascii"),
                        oracle._ORACLE_RECONCILIATION_KIND_CODES[kind],
                        len(payloads),
                        zlib.compress(encoded),
                    ),
                )

            add_chunk("member_resolution", ({
                "direct_edge_identity": "member",
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target/member",
            }, {}))
            add_chunk("dispatch_resolution", ({
                "direct_edge_identity": "dispatch",
                "dispatch_status": "possible",
                "implementation_target_identities": ["target/dispatch"],
            }, {}))
            add_chunk("type_resolution", ({
                "direct_edge_identity": "type",
                "type_resolution_status": "resolved",
            }, {}))
            add_chunk("class_initialization_resolution", ({
                "direct_edge_identity": "init",
                "class_initialization_status": "resolved",
                "initializer_target_identities": ["target/init"],
            }, {}))
            add_chunk("linkage_resolution", ({
                "direct_edge_identity": "linkage",
                "linkage_status": "linked",
            }, {}))
            connection.commit()
            connection.close()

            (generation / "binary_runtime_semantic_overlay.json").write_text(
                json.dumps({"rows": [
                    {
                        "caller_member_identity": "runtime/caller",
                        "target_member_identity": "runtime/exact",
                        "path_certainty": "exact",
                        "semantic_edge_identity": "runtime-exact",
                    },
                    {
                        "caller_member_identity": "runtime/caller",
                        "target_member_identity": "runtime/possible",
                        "path_certainty": "possible",
                    },
                    {
                        "caller_member_identity": "",
                        "target_member_identity": "runtime/no-caller",
                    },
                    {
                        "caller_member_identity": "runtime/no-target",
                        "target_member_identity": "",
                    },
                ]}),
                encoding="utf-8",
            )

            without_inline = oracle._ClosedWorldGraphIndex(
                generation,
                generation / "without-inline.sqlite",
                paired_artifact_missing_targets=set(),
                unresolved_edge_alias_targets={},
            )
            try:
                self.assertEqual(
                    set(without_inline.transitions("runtime/caller")),
                    {
                        ("runtime/exact", "exact", "runtime-exact"),
                        ("runtime/possible", "possible", ""),
                    },
                )
                self.assertEqual(
                    without_inline.resolution_status("member"), "resolved",
                )
                self.assertEqual(
                    without_inline.resolution_status(""), "",
                )
            finally:
                without_inline.close()

            (generation / "binary_inline_overlay.json").write_text(
                json.dumps({"rows": [
                    {
                        "consumption_state": "unchanged",
                        "binding_certainty": "proven",
                        "consumer_member_identity": "inline/caller",
                        "changed_field_member_identity": "inline/ignored-state",
                    },
                    {
                        "consumption_state": "changed_with_source",
                        "binding_certainty": "unknown",
                        "consumer_member_identity": "inline/caller",
                        "changed_field_member_identity": "inline/ignored-binding",
                    },
                    {
                        "consumption_state": "changed_with_source",
                        "binding_certainty": "proven",
                        "consumer_member_identity": "",
                        "changed_field_member_identity": "inline/no-caller",
                    },
                    {
                        "consumption_state": "changed_with_source",
                        "binding_certainty": "possible",
                        "consumer_member_identity": "inline/no-target",
                        "changed_field_member_identity": "",
                    },
                    {
                        "consumption_state": "changed_with_source",
                        "binding_certainty": "proven",
                        "consumer_member_identity": "inline/caller",
                        "changed_field_member_identity": "inline/exact",
                        "inline_overlay_identity": "inline-exact",
                    },
                    {
                        "consumption_state": "changed_with_source",
                        "binding_certainty": "possible",
                        "consumer_member_identity": "inline/caller",
                        "changed_field_member_identity": "inline/possible",
                    },
                ]}),
                encoding="utf-8",
            )
            progress = []
            with_inline = oracle._ClosedWorldGraphIndex(
                generation,
                generation / "with-inline.sqlite",
                paired_artifact_missing_targets=set(),
                unresolved_edge_alias_targets={},
                progress_callback=lambda *event: progress.append(event),
            )
            try:
                self.assertEqual(
                    set(with_inline.transitions("inline/caller")),
                    {
                        ("inline/exact", "exact", "inline-exact"),
                        ("inline/possible", "possible", ""),
                    },
                )
                self.assertEqual(with_inline.linkage_status("linkage"), "linked")
                self.assertTrue(progress)
            finally:
                with_inline.close()

            with (
                patch.object(
                    oracle._ClosedWorldGraphIndex,
                    "_build_reconciliation_indexes",
                    side_effect=RuntimeError("index build failed"),
                ),
                self.assertRaisesRegex(RuntimeError, "index build failed"),
            ):
                oracle._ClosedWorldGraphIndex(
                    generation,
                    generation / "failed.sqlite",
                    paired_artifact_missing_targets=set(),
                    unresolved_edge_alias_targets={},
                )

    def test_artifact_loader_tool_policy_and_compiler_boundary_matrix(self):
        self.assertEqual(oracle._artifact_configs({}), [])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.jar"
            second = root / "second.jar"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            side = {"artifacts": [
                {
                    "path": str(second), "loader_realm": "child", "slot": 2,
                },
                {
                    "path": str(first), "loader_realm": "child", "slot": 1,
                },
            ]}
            digest_cache = {second.resolve(): "cached-digest"}
            configured = oracle._artifact_configs(side, digest_cache)
            self.assertEqual([item["slot"] for item in configured], [1, 2])
            self.assertEqual(configured[1]["sha256"], "cached-digest")
            self.assertEqual(
                configured[0]["sha256"], hashlib.sha256(b"first").hexdigest(),
            )
            self.assertEqual(
                oracle._artifact_configs(
                    {"artifacts": [{
                        "path": str(first), "loader_realm": "", "slot": 0,
                    }]},
                )[0]["loader_realm"],
                "",
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._artifact_configs({"artifacts": [{"path": ""}]})
            self.assertEqual(
                raised.exception.reason_code, "BINARY_ORACLE_ARTIFACT_MISSING",
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._artifact_configs({"artifacts": [
                    {"path": str(first), "loader_realm": "same", "slot": 1},
                    {"path": str(second), "loader_realm": "same", "slot": 1},
                ]})
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE",
            )

            artifacts = [
                {"path": "child-2.jar", "loader_realm": "child", "slot": 2},
                {"path": "parent.jar", "loader_realm": "parent", "slot": 0},
                {"path": "child-1.jar", "loader_realm": "child", "slot": 1},
            ]
            topology = {"realms": [
                "ignored-non-mapping",
                {"identity": ""},
                {"identity": "platform", "kind": "platform"},
                {
                    "identity": "parent", "parent": "platform",
                    "delegation": "parent_first", "module_mode": "unnamed",
                },
                {
                    "identity": "child", "parent": "parent",
                    "delegation": "parent_first", "module_mode": "unnamed",
                },
            ]}
            self.assertEqual(
                [item["path"] for item in oracle._ordered_artifacts_for_realm(
                    artifacts, topology, "child",
                )],
                ["parent.jar", "child-1.jar", "child-2.jar"],
            )
            self.assertEqual(
                [item["path"] for item in oracle._ordered_artifacts_for_realm(
                    [*artifacts, {"path": "unbound.jar", "slot": 0}],
                    topology,
                    "child",
                )],
                ["parent.jar", "child-1.jar", "child-2.jar"],
            )
            child_first = json.loads(json.dumps(topology))
            child_first["realms"][-1]["delegation"] = "child_first"
            self.assertEqual(
                [item["path"] for item in oracle._ordered_artifacts_for_realm(
                    artifacts, child_first, "child",
                )],
                ["child-1.jar", "child-2.jar", "parent.jar"],
            )
            error_topologies = (
                (
                    {"realms": [{
                        "identity": "cycle", "parent": "cycle",
                    }]},
                    "BINARY_ORACLE_LOADER_TOPOLOGY_CYCLE",
                    {},
                ),
                ({"realms": []}, "BINARY_ORACLE_LOADER_REALM_MISSING", {}),
                (
                    {"realms": [{
                        "identity": "bad", "parent": "platform",
                        "module_mode": "named",
                    }, {"identity": "platform", "kind": "platform"}]},
                    "BINARY_ORACLE_LOADER_TOPOLOGY_UNSUPPORTED",
                    {},
                ),
                (
                    {"realms": [{
                        "identity": "bad", "parent": "platform",
                        "delegation": "unsupported",
                    }, {"identity": "platform", "kind": "platform"}]},
                    "BINARY_ORACLE_LOADER_TOPOLOGY_UNSUPPORTED",
                    {},
                ),
                (
                    child_first,
                    "BINARY_ORACLE_LOADER_TOPOLOGY_UNSUPPORTED",
                    {"require_parent_first_unnamed": True},
                ),
                (
                    {"realms": [{"identity": "orphan"}]},
                    "BINARY_ORACLE_PLATFORM_REALM_UNREACHABLE",
                    {},
                ),
            )
            for candidate, reason, kwargs in error_topologies:
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle._ordered_artifacts_for_realm(
                        artifacts, candidate,
                        "child" if candidate is child_first else next(
                            item["identity"] for item in candidate["realms"]
                            if isinstance(item, dict) and item.get("identity")
                        ) if candidate["realms"] else "missing",
                        **kwargs,
                    )
                self.assertEqual(raised.exception.reason_code, reason)

            self.assertEqual(
                oracle._oracle_artifacts_for_entrypoint_realms(
                    artifacts, topology, ("child", "child", ""),
                ),
                [artifacts[1], artifacts[2], artifacts[0]],
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._oracle_artifacts_for_entrypoint_realms(
                    [*artifacts, {
                        "path": "duplicate.jar", "loader_realm": "child",
                        "slot": 1,
                    }],
                    topology,
                    ("child",),
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE",
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._oracle_artifacts_for_entrypoint_realms(
                    [
                        {"path": "implicit.jar", "slot": 0},
                        {
                            "path": "explicit.jar", "loader_realm": "",
                            "slot": 0,
                        },
                    ],
                    topology,
                    (),
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE",
            )
            for realms in ((), ("child", "parent")):
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle._oracle_artifacts_for_entrypoint_realms(
                        artifacts, topology, realms,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_ORACLE_ENTRYPOINT_REALM_ORDER_AMBIGUOUS",
                )

            jdk8 = root / "jdk8"
            for relative in (
                "jre/lib", "jre/lib/ext", "jre/classes/java/lang",
            ):
                (jdk8 / relative).mkdir(parents=True, exist_ok=True)
            self.assertTrue(oracle._is_bound_jdk8_platform_path(
                jdk8 / "jre/lib/rt.jar", jdk8,
            ))
            self.assertTrue(oracle._is_bound_jdk8_platform_path(
                jdk8 / "jre/lib/ext/custom.JAR", jdk8,
            ))
            self.assertFalse(oracle._is_bound_jdk8_platform_path(
                jdk8 / "jre/lib/ext/not-a-jar.zip", jdk8,
            ))
            self.assertFalse(oracle._is_bound_jdk8_platform_path(
                root / "external.jar", jdk8,
            ))
            self.assertTrue(oracle._is_bound_jdk8_platform_path(
                jdk8 / "jre/classes/java/lang/Object.class", jdk8,
            ))

            self.assertEqual(oracle._javap_reference(None), ("", "", ""))
            self.assertEqual(oracle._javap_reference("invalid"), ("", "", ""))
            self.assertEqual(
                oracle._javap_reference("Method demo/Owner.run:()V"),
                ("demo/Owner", "run", "()V"),
            )
            self.assertEqual(
                oracle._javap_reference('InterfaceMethod "run":(I)V'),
                ("", "run", "(I)V"),
            )

            defaults = oracle._oracle_tool_execution_policy({})
            self.assertEqual(defaults["max_attempts"], 2)
            self.assertEqual(defaults["compile_timeout_seconds"], 300.0)
            self.assertEqual(defaults["javap_time_budget_seconds"], 3600.0)
            limits = oracle._oracle_tool_execution_policy({
                "tool_execution_policy": {
                    "oracle_compile_timeout_seconds": 0.01,
                    "oracle_runtime_timeout_seconds": 300,
                    "oracle_runtime_phase_time_budget_seconds": 7200,
                    "oracle_javap_time_budget_seconds": 7200,
                    "oracle_max_attempts": 3,
                },
            })
            self.assertEqual(limits["runtime_timeout_seconds"], 300.0)
            invalid_policies = [
                {"unknown": 1},
                {"oracle_compile_timeout_seconds": "not-a-number"},
                {"oracle_max_attempts": "not-an-integer"},
                {"oracle_max_attempts": 1.5},
                {"oracle_compile_timeout_seconds": 0},
                {"oracle_compile_timeout_seconds": 301},
                {"oracle_runtime_timeout_seconds": 0},
                {"oracle_runtime_timeout_seconds": 301},
                {"oracle_runtime_phase_time_budget_seconds": 0},
                {"oracle_runtime_phase_time_budget_seconds": 7201},
                {"oracle_javap_time_budget_seconds": 0},
                {"oracle_javap_time_budget_seconds": 7201},
                {"oracle_max_attempts": 0},
                {"oracle_max_attempts": 4},
            ]
            invalid_policies.extend(
                {field: True} for field in (
                    "oracle_compile_timeout_seconds",
                    "oracle_runtime_timeout_seconds",
                    "oracle_runtime_phase_time_budget_seconds",
                    "oracle_javap_time_budget_seconds",
                    "oracle_max_attempts",
                )
            )
            for policy in invalid_policies:
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle._oracle_tool_execution_policy({
                        "tool_execution_policy": policy,
                    })
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_ORACLE_TOOL_POLICY_INVALID",
                )

            oracle_source = root / "RuntimeOutcomeOracle.java"
            release = jdk8 / "release"
            oracle_source.write_text("class Oracle {}", encoding="utf-8")
            release.write_text('JAVA_VERSION="1.8"\n', encoding="utf-8")
            success = BinaryToolResult("", "", 0)
            nonretryable_failure = BinaryToolFailure(
                stage="binary_oracle.compile",
                reason_code="BINARY_ORACLE_COMPILE_NONZERO_EXIT",
                failure_kind="nonzero_exit",
                command=("javac",),
                timeout_seconds=1,
                returncode=1,
                stderr="compile failed",
            )
            retryable_failure = BinaryToolFailure(
                stage="binary_oracle.compile",
                reason_code="BINARY_ORACLE_COMPILE_TIMEOUT",
                failure_kind="timeout",
                command=("javac",),
                timeout_seconds=1,
                returncode=None,
                stderr="timeout",
            )
            failed = BinaryToolResult("", "compile failed", 1, nonretryable_failure)
            timed_out = BinaryToolResult("", "timeout", -1, retryable_failure)
            with (
                patch.object(oracle, "ORACLE_SOURCE", oracle_source),
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(oracle, "execute_binary_tool", return_value=success),
            ):
                self.assertRegex(
                    oracle._compile_oracle(jdk8, root / "classes", max_attempts=0),
                    r"^[0-9a-f]{64}$",
                )
            with (
                patch.object(oracle, "ORACLE_SOURCE", oracle_source),
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(oracle, "execute_binary_tool", return_value=success),
                patch.object(
                    oracle,
                    "resolve_jdk_release",
                    side_effect=oracle.JdkPreflightError(
                        "JDK_RELEASE_METADATA_FAILED", "metadata failed"
                    ),
                ),
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._compile_oracle(jdk8, root / "metadata-failed")
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_JDK_RELEASE_MISSING",
            )
            with (
                patch.object(oracle, "ORACLE_SOURCE", oracle_source),
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(
                    oracle, "execute_binary_tool", side_effect=(timed_out, success),
                ) as execute,
            ):
                oracle._compile_oracle(
                    jdk8,
                    root / "retry-classes",
                    timeout_seconds=60,
                    max_attempts=2,
                    phase_deadline=oracle.time.perf_counter() + 10,
                )
                self.assertEqual(execute.call_count, 2)
                self.assertLessEqual(
                    execute.call_args_list[0].kwargs["timeout_seconds"], 10,
                )
            with (
                patch.object(oracle, "ORACLE_SOURCE", oracle_source),
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(oracle, "execute_binary_tool", return_value=failed),
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._compile_oracle(
                    jdk8, root / "failed-classes", max_attempts=3,
                )
            self.assertEqual(
                raised.exception.reason_code, "BINARY_ORACLE_COMPILE_FAILED",
            )
            with (
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(
                    oracle, "execute_binary_tool", return_value=timed_out,
                ),
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._compile_oracle(
                    jdk8, root / "single-timeout", max_attempts=1,
                )
            self.assertEqual(
                raised.exception.reason_code, "BINARY_ORACLE_COMPILE_FAILED",
            )
            with (
                patch.object(oracle, "jdk_tool_path", return_value=Path("javac")),
                patch.object(oracle, "execute_binary_tool") as execute,
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._compile_oracle(
                    jdk8,
                    root / "expired-classes",
                    phase_deadline=oracle.time.perf_counter() - 1,
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_RUNTIME_PHASE_TIME_BUDGET_EXCEEDED",
            )
            execute.assert_not_called()

    def test_classfile_and_module_descriptor_byte_boundary_matrix(self):
        def u2(value):
            return int(value).to_bytes(2, "big")

        def u4(value):
            return int(value).to_bytes(4, "big")

        def classfile(
            *,
            major=53,
            access=oracle.ACC_MODULE,
            owner=b"module-info",
            this_class_override=None,
            super_class=0,
            interfaces=(),
            field_count=0,
            method_count=0,
            attribute_names=(b"Module",),
            all_tags=False,
            invalid_attribute_index=False,
            trailing=b"",
        ):
            entries = []
            next_index = 1

            def add(tag, payload, *, slots=1):
                nonlocal next_index
                index = next_index
                entries.append((tag, payload, slots))
                next_index += slots
                return index

            owner_utf8 = add(1, u2(len(owner)) + owner)
            this_class = add(7, u2(owner_utf8))
            attribute_indexes = {}
            for name in dict.fromkeys(attribute_names):
                attribute_indexes[name] = add(1, u2(len(name)) + name)
            if all_tags:
                dummy_utf8 = add(1, u2(1) + b"x")
                add(3, b"\x00" * 4)
                add(4, b"\x00" * 4)
                add(5, b"\x00" * 8, slots=2)
                add(6, b"\x00" * 8, slots=2)
                add(8, u2(dummy_utf8))
                add(9, b"\x00" * 4)
                add(10, b"\x00" * 4)
                add(11, b"\x00" * 4)
                add(12, b"\x00" * 4)
                add(15, b"\x01\x00\x01")
                add(16, u2(dummy_utf8))
                add(17, b"\x00" * 4)
                add(18, b"\x00" * 4)
                add(19, u2(dummy_utf8))
                add(20, u2(dummy_utf8))
            constant_pool = b"".join(
                bytes((tag,)) + payload for tag, payload, _slots in entries
            )
            attributes = b"".join(
                u2(0xFFFF if invalid_attribute_index else attribute_indexes[name])
                + u4(0)
                for name in attribute_names
            )
            body = (
                u2(access)
                + u2(
                    this_class
                    if this_class_override is None else this_class_override
                )
                + u2(super_class)
                + u2(len(interfaces))
                + b"".join(u2(value) for value in interfaces)
                + u2(field_count)
            )
            if not field_count:
                body += u2(method_count)
                if not method_count:
                    body += u2(len(attribute_names)) + attributes
            return (
                b"\xca\xfe\xba\xbe"
                + u2(0)
                + u2(major)
                + u2(next_index)
                + constant_pool
                + body
                + trailing
            )

        valid = classfile(all_tags=True)
        self.assertEqual(
            oracle._independent_class_access_flags(valid), oracle.ACC_MODULE,
        )
        self.assertTrue(oracle._independent_is_valid_module_descriptor(valid))

        invalid_headers = (
            b"",
            b"not-a-classfile",
            b"\xca\xfe\xba\xbe" + b"\x00" * 4 + u2(0),
        )
        for content in invalid_headers:
            self.assertIsNone(oracle._independent_class_access_flags(content))
            self.assertFalse(
                oracle._independent_is_valid_module_descriptor(content),
            )

        unknown_tag = bytearray(valid)
        unknown_tag[10] = 99
        oversized_utf8 = bytearray(valid)
        oversized_utf8[11:13] = u2(0xFFFF)
        for content in (bytes(unknown_tag), bytes(oversized_utf8), valid[:12]):
            self.assertIsNone(oracle._independent_class_access_flags(content))
        self.assertFalse(
            oracle._independent_is_valid_module_descriptor(bytes(unknown_tag)),
        )
        self.assertFalse(
            oracle._independent_is_valid_module_descriptor(bytes(oversized_utf8)),
        )
        truncated_skip = (
            b"\xca\xfe\xba\xbe" + u2(0) + u2(53) + u2(2)
            + b"\x03\x00"
        )
        self.assertFalse(
            oracle._independent_is_valid_module_descriptor(truncated_skip),
        )

        invalid_descriptors = (
            classfile(major=52),
            classfile(access=0x0021),
            classfile(owner=b"ordinary/Class"),
            classfile(this_class_override=0),
            classfile(super_class=2),
            classfile(interfaces=(2,)),
            classfile(field_count=1),
            classfile(method_count=1),
            classfile(attribute_names=()),
            classfile(attribute_names=(b"Module", b"Module")),
            classfile(attribute_names=(b"Module", b"Unknown")),
            classfile(invalid_attribute_index=True),
            classfile(trailing=b"trailing"),
            valid[:-1],
        )
        for content in invalid_descriptors:
            self.assertFalse(
                oracle._independent_is_valid_module_descriptor(content),
            )
        self.assertTrue(oracle._independent_is_valid_module_descriptor(
            classfile(attribute_names=(b"Module", b"SourceFile")),
        ))

        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "classfiles.jar"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("valid.class", valid)
                archive.writestr("unknown.class", bytes(unknown_tag))
                archive.writestr("truncated.class", valid[:12])
                archive.writestr("wrong-magic.class", b"x" * 32)
                archive.writestr(
                    "zero-pool.class",
                    b"\xca\xfe\xba\xbe" + u2(0) + u2(53) + u2(0),
                )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    oracle._independent_archive_class_access_flags(
                        archive, archive.getinfo("valid.class"),
                    ),
                    oracle.ACC_MODULE,
                )
                for name in (
                    "unknown.class", "truncated.class", "wrong-magic.class",
                    "zero-pool.class",
                ):
                    self.assertIsNone(
                        oracle._independent_archive_class_access_flags(
                            archive, archive.getinfo(name),
                        ),
                    )

    def test_archive_inventory_physical_and_runtime_boundary_matrix(self):
        def u2(value):
            return int(value).to_bytes(2, "big")

        def u4(value):
            return int(value).to_bytes(4, "big")

        def ordinary(access=0x0021):
            return (
                b"\xca\xfe\xba\xbe" + u2(0) + u2(53) + u2(1)
                + u2(access)
            )

        def module_descriptor(owner=b"module-info"):
            module_name = b"Module"
            constant_pool = (
                b"\x01" + u2(len(owner)) + owner
                + b"\x07" + u2(1)
                + b"\x01" + u2(len(module_name)) + module_name
            )
            return (
                b"\xca\xfe\xba\xbe" + u2(0) + u2(53) + u2(4)
                + constant_pool
                + u2(oracle.ACC_MODULE) + u2(2) + u2(0)
                + u2(0) + u2(0) + u2(0)
                + u2(1) + u2(3) + u4(0)
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            comprehensive = root / "comprehensive.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(comprehensive, "w") as archive:
                    archive.writestr("empty-directory/", b"")
                    archive.writestr(
                        "META-INF/MANIFEST.MF",
                        "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
                    )
                    archive.writestr("demo/Base.class", ordinary())
                    archive.writestr("module-info.class", module_descriptor())
                    archive.writestr(
                        "malformed-module.class",
                        module_descriptor(b"wrong-owner"),
                    )
                    archive.writestr("META-INF/ignored.class", ordinary())
                    archive.writestr(
                        "META-INF/versions/9/demo/Malformed.class", b"bad",
                    )
                    archive.writestr(
                        "META-INF/versions/9/demo/Ordinary.class", ordinary(),
                    )
                    archive.writestr(
                        "META-INF/versions/9/module-info.class",
                        module_descriptor(),
                    )
                    archive.writestr(
                        "META-INF/versions/9/demo/BadModule.class",
                        module_descriptor(b"wrong-owner"),
                    )
                    archive.writestr(
                        "META-INF/versions/7/config/pre8.txt", b"pre8",
                    )
                    archive.writestr(
                        "META-INF/versions/9/config/runtime.txt", b"runtime",
                    )
                    archive.writestr(
                        "META-INF/versions/9/META-INF/hidden.txt", b"hidden",
                    )
                    archive.writestr(
                        "META-INF/versions/9/config/../invalid.txt", b"invalid",
                    )
                    archive.writestr(
                        "META-INF/versions/09/config/leading-zero.txt", b"bad",
                    )
                    archive.writestr("demo/Duplicate.class", ordinary())
                    archive.writestr("demo/Duplicate.class", ordinary())

            inventory = oracle._archive_inventory(comprehensive, 17)
            self.assertTrue(inventory["multi_release"])
            self.assertEqual(
                inventory["classes"]["demo/Ordinary"],
                "META-INF/versions/9/demo/Ordinary.class",
            )
            self.assertNotIn("module-info", inventory["classes"])
            self.assertNotIn("META-INF/ignored", inventory["classes"])
            self.assertIn("malformed-module", inventory["classes"])
            self.assertIn("demo/BadModule", inventory["classes"])
            self.assertIn(
                "duplicate_class:demo/Duplicate:0", inventory["failures"],
            )
            self.assertIn("config/runtime.txt", inventory["resources"])
            self.assertNotIn("config/pre8.txt", inventory["resources"])
            self.assertNotIn("META-INF/hidden.txt", inventory["resources"])
            self.assertNotIn("config/../invalid.txt", inventory["resources"])

            no_runtime_candidate = root / "no-runtime-candidate.jar"
            with zipfile.ZipFile(no_runtime_candidate, "w") as archive:
                archive.writestr(
                    "META-INF/versions/9/demo/Only.class", ordinary(),
                )
            self.assertEqual(
                oracle._archive_inventory(
                    no_runtime_candidate, 17,
                )["classes"],
                {},
            )

            duplicate_without_versions = root / "duplicate-manifest-base.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate_without_versions, "w") as archive:
                    archive.writestr("META-INF/MANIFEST.MF", b"first")
                    archive.writestr("meta-inf/manifest.mf", b"second")
                    archive.writestr("META-INF/versions/", b"")
                    archive.writestr("demo/Base.class", ordinary())
            base_inventory = oracle._archive_inventory(
                duplicate_without_versions, 17,
            )
            self.assertFalse(base_inventory["multi_release"])
            self.assertFalse(any(
                item.startswith("ambiguous_multi_release_manifest:")
                for item in base_inventory["failures"]
            ))

    def test_runtime_profile_artifact_identity_and_pairing_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jdk = root / "jdk"
            jdk.mkdir()
            (jdk / "release").write_text(
                'JAVA_VERSION="17.0.1"\nIMPLEMENTOR="Vendor"\n'
                'OS_NAME="TestOS"\nOS_ARCH="test-arch"\n',
                encoding="utf-8",
            )
            empty_identity = oracle._expected_runtime_profile_identity(
                {}, [], platform_identity="platform", jdk_home=jdk,
            )
            self.assertRegex(empty_identity, r"^[0-9a-f]{64}$")

            full_side = {
                "runtime_profile": {
                    "target_jvm": {"vendor": "Supplied", "major": 21},
                    "target_os": "SuppliedOS",
                    "target_arch": "supplied-arch",
                    "runtime_code_source_origin_mapping_identity": "mapping",
                    "field_coverage": {
                        key: "explicit"
                        for key in oracle._RUNTIME_PROFILE_REQUIRED_FIELDS
                    },
                },
                "artifacts": [],
            }
            full_identity = oracle._expected_runtime_profile_identity(
                full_side,
                [{
                    "logical_location": "z.jar", "sha256": "a" * 64,
                    "path_kind": "modulepath", "slot": 2,
                    "loader_realm": "realm",
                }],
                platform_identity="platform",
                jdk_home=jdk,
            )
            self.assertRegex(full_identity, r"^[0-9a-f]{64}$")
            self.assertNotEqual(empty_identity, full_identity)

            reconstructed = oracle._expected_runtime_profile_identity(
                {
                    "runtime_profile": {"field_coverage": {
                        "target_jvm": "known",
                    }},
                    "artifacts": [
                        "ignored",
                        {
                            "logical_location": "",
                            "runtime_code_source_origin_identity": "",
                        },
                        {
                            "logical_location": "a.jar",
                            "runtime_code_source_origin_identity": "origin-a",
                        },
                    ],
                },
                [
                    {"sha256": "b" * 64, "slot": 2},
                    {
                        "logical_location": "a.jar", "sha256": "c" * 64,
                        "path_kind": "", "slot": 1, "loader_realm": "",
                    },
                ],
                platform_identity="platform",
                jdk_home=jdk,
            )
            self.assertRegex(reconstructed, r"^[0-9a-f]{64}$")
            with self.assertRaises(StopIteration):
                oracle._expected_runtime_profile_identity(
                    {"artifacts": []},
                    [{
                        "logical_location": "unbound.jar",
                        "sha256": "d" * 64,
                        "slot": 0,
                    }],
                    platform_identity="platform",
                    jdk_home=jdk,
                )

            flat = root / "flat.jar"
            outer = root / "outer.jar"
            nested_one = root / "nested-one.jar"
            nested_two = root / "nested-two.jar"
            flat.write_bytes(b"flat")
            outer.write_bytes(b"outer")
            nested_one.write_bytes(b"one")
            nested_two.write_bytes(b"two")
            flat_sha = hashlib.sha256(b"flat").hexdigest()
            artifacts = [
                {"path": str(flat), "sha256": flat_sha, "slot": 0},
                {
                    "path": str(nested_one), "outer_artifact_path": str(outer),
                    "sha256": hashlib.sha256(b"one").hexdigest(),
                    "container_entry": "BOOT-INF/lib/one.jar",
                    "loader_realm": "application", "path_kind": "nested",
                    "slot": 1,
                    "container_loader_policy_version": "nested-v1",
                    "runtime_code_source_origin_identity": "origin-one",
                },
                {
                    "path": str(nested_two), "outer_artifact_path": str(outer),
                    "sha256": hashlib.sha256(b"two").hexdigest(),
                    "container_entry": "BOOT-INF/lib/two.jar",
                    "loader_realm": "application", "path_kind": "nested",
                    "slot": 2,
                    "container_loader_policy_version": "nested-v1",
                    "runtime_code_source_origin_identity": "origin-two",
                },
            ]
            oracle._attach_expected_artifact_instances([], "profile")
            with patch.object(
                oracle, "_sha256_file", wraps=oracle._sha256_file,
            ) as digest:
                oracle._attach_expected_artifact_instances(artifacts, "profile")
            self.assertEqual(digest.call_count, 1)
            self.assertEqual(
                artifacts[0]["_expected_artifact_instance_payload"]
                ["container_entry"],
                "<artifact>",
            )
            self.assertEqual(
                artifacts[0]["_expected_artifact_instance_payload"]
                ["runtime_path_kind"],
                "classpath",
            )
            self.assertEqual(
                artifacts[1]["_expected_artifact_instance_payload"]
                ["outer_artifact_sha256"],
                hashlib.sha256(b"outer").hexdigest(),
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._attach_expected_artifact_instances([{
                    "path": str(nested_one),
                    "outer_artifact_path": str(root / "missing.jar"),
                    "sha256": "d" * 64,
                    "slot": 0,
                }], "profile")
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_OUTER_ARTIFACT_MISSING",
            )

            def artifact_connection():
                connection = sqlite3.connect(":memory:")
                connection.row_factory = sqlite3.Row
                connection.execute("""
                    CREATE TABLE artifact_instances (
                        artifact_instance_identity TEXT, coord TEXT,
                        outer_artifact_sha256 TEXT, container_entry TEXT,
                        content_sha256 TEXT, runtime_profile_identity TEXT,
                        loader_realm_identity TEXT, runtime_path_kind TEXT,
                        runtime_classpath_index INTEGER,
                        container_loader_policy_version TEXT,
                        runtime_code_source_origin_identity TEXT
                    )
                """)
                return connection

            def insert_artifact_row(
                connection, *, identity, sha, realm, slot,
                coord="", payload=None,
            ):
                values = dict(payload or {})
                connection.execute(
                    "INSERT INTO artifact_instances VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        identity,
                        coord,
                        values.get("outer_artifact_sha256", ""),
                        values.get("container_entry", ""),
                        sha,
                        values.get("runtime_profile_identity", ""),
                        realm,
                        values.get("runtime_path_kind", ""),
                        slot,
                        values.get("container_loader_policy_version", ""),
                        values.get("runtime_code_source_origin_identity", ""),
                    ),
                )

            loose = artifact_connection()
            self.addCleanup(loose.close)
            insert_artifact_row(
                loose, identity="ambiguous-1", sha="a", realm="amb", slot=0,
            )
            insert_artifact_row(
                loose, identity="ambiguous-2", sha="a", realm="amb", slot=0,
            )
            insert_artifact_row(
                loose, identity="bound", sha="b", realm="ok", slot=1,
            )
            insert_artifact_row(
                loose, identity="wrong-content", sha="actual", realm="bad", slot=2,
            )
            insert_artifact_row(
                loose, identity="", sha="d", realm="missing-id", slot=3,
            )
            insert_artifact_row(
                loose, identity="unexpected", sha="e", realm="extra", slot=4,
            )
            bindings, issues = oracle._artifact_instance_bindings(
                loose,
                [
                    {
                        "loader_realm": "amb", "slot": 0, "sha256": "a",
                        "path": "ambiguous.jar",
                    },
                    {
                        "loader_realm": "ok", "slot": 1, "sha256": "b",
                        "path": "bound.jar",
                    },
                    {
                        "loader_realm": "ok", "slot": 1, "sha256": "b",
                        "path": "duplicate.jar",
                    },
                    {
                        "loader_realm": "bad", "slot": 2,
                        "sha256": "expected", "path": "bad.jar",
                    },
                    {
                        "loader_realm": "missing-id", "slot": 3,
                        "sha256": "d", "path": "missing-id.jar",
                    },
                    {
                        "loader_realm": "unbound", "slot": 9,
                        "sha256": "f", "path": "unbound.jar",
                    },
                ],
                domain="artifact",
            )
            self.assertEqual(bindings, {("ok", 1): "bound"})
            self.assertEqual(
                {issue["reason_code"] for issue in issues},
                {
                    "ORACLE_ARTIFACT_CONFIG_LOCATION_DUPLICATE",
                    "ORACLE_ARTIFACT_INSTANCE_AMBIGUOUS",
                    "ORACLE_ARTIFACT_INSTANCE_UNBOUND",
                    "ORACLE_ARTIFACT_INSTANCE_CONTENT_MISMATCH",
                    "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISSING",
                    "ORACLE_ARTIFACT_INSTANCE_UNEXPECTED",
                },
            )

            strict = artifact_connection()
            self.addCleanup(strict.close)
            strict_artifacts = []
            for slot, source in enumerate(artifacts[:1] * 6):
                candidate = dict(source)
                candidate["slot"] = slot
                candidate["loader_realm"] = "strict"
                payload = dict(source["_expected_artifact_instance_payload"])
                payload["runtime_classpath_index"] = slot
                payload["path_owner_loader_realm_identity"] = "strict"
                candidate["_expected_artifact_instance_payload"] = payload
                actual_identity = oracle._identity(
                    "artifact_instance_identity", payload,
                )
                candidate["_expected_artifact_instance_identity"] = actual_identity
                strict_artifacts.append(candidate)
                insert_artifact_row(
                    strict,
                    identity=actual_identity,
                    sha=candidate["sha256"],
                    realm="strict",
                    slot=slot,
                    payload=payload,
                )

            strict_artifacts[1]["_expected_artifact_instance_payload"] = {}
            strict_artifacts[1]["_expected_artifact_instance_identity"] = ""
            strict.execute(
                "UPDATE artifact_instances SET artifact_instance_identity='wrong' "
                "WHERE runtime_classpath_index=2"
            )
            strict_artifacts[3]["_expected_artifact_instance_identity"] = "wrong"
            strict_artifacts[4]["coord"] = "expected-coord"
            strict_artifacts[4]["_expected_artifact_instance_payload"] = {
                **strict_artifacts[4]["_expected_artifact_instance_payload"],
                "container_entry": "different",
            }
            strict_artifacts[5]["_expected_artifact_instance_payload"] = "bad"
            strict_artifacts[5]["_expected_artifact_instance_identity"] = "present"

            empty_payload = {
                "outer_artifact_sha256": "",
                "container_entry": "",
                "content_sha256": "",
                "runtime_profile_identity": "",
                "path_owner_loader_realm_identity": "",
                "runtime_path_kind": "",
                "runtime_classpath_index": 6,
                "container_loader_policy_version": "",
                "runtime_code_source_origin_identity": "",
            }
            empty_identity = oracle._identity(
                "artifact_instance_identity", empty_payload,
            )
            strict_artifacts.append({
                "loader_realm": "", "slot": 6, "sha256": "", "path": "",
                "_expected_artifact_instance_payload": empty_payload,
                "_expected_artifact_instance_identity": empty_identity,
            })
            insert_artifact_row(
                strict,
                identity=empty_identity,
                sha="",
                realm="",
                slot=6,
                payload=empty_payload,
            )
            insert_artifact_row(
                strict,
                identity="",
                sha="",
                realm="unexpected-empty",
                slot=99,
            )
            strict_bindings, strict_issues = oracle._artifact_instance_bindings(
                strict, strict_artifacts, domain="strict",
            )
            self.assertEqual(strict_bindings, {
                ("strict", 0): strict_artifacts[0][
                    "_expected_artifact_instance_identity"
                ],
                ("", 6): empty_identity,
            })
            self.assertEqual(
                [issue["reason_code"] for issue in strict_issues].count(
                    "ORACLE_ARTIFACT_INSTANCE_EXPECTATION_MISSING"
                ),
                2,
            )
            self.assertEqual(
                [issue["reason_code"] for issue in strict_issues].count(
                    "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISMATCH"
                ),
                3,
            )

            empty_path_loose = artifact_connection()
            self.addCleanup(empty_path_loose.close)
            insert_artifact_row(
                empty_path_loose,
                identity="amb-1", sha="a", realm="ambiguous-empty", slot=0,
            )
            insert_artifact_row(
                empty_path_loose,
                identity="amb-2", sha="a", realm="ambiguous-empty", slot=0,
            )
            insert_artifact_row(
                empty_path_loose,
                identity="content", sha="actual", realm="content-empty", slot=1,
            )
            insert_artifact_row(
                empty_path_loose,
                identity="", sha="id-sha", realm="identity-empty", slot=2,
            )
            _bindings, empty_path_issues = oracle._artifact_instance_bindings(
                empty_path_loose,
                [
                    {
                        "loader_realm": "ambiguous-empty", "slot": 0,
                        "sha256": "a",
                    },
                    {
                        "loader_realm": "content-empty", "slot": 1,
                        "sha256": "expected",
                    },
                    {
                        "loader_realm": "identity-empty", "slot": 2,
                        "sha256": "id-sha",
                    },
                    {
                        "loader_realm": "unbound-empty", "slot": 3,
                        "sha256": "missing",
                    },
                    {
                        "loader_realm": "unbound-empty", "slot": 3,
                        "sha256": "missing",
                    },
                ],
                domain="empty-path",
            )
            self.assertTrue({
                "ORACLE_ARTIFACT_CONFIG_LOCATION_DUPLICATE",
                "ORACLE_ARTIFACT_INSTANCE_AMBIGUOUS",
                "ORACLE_ARTIFACT_INSTANCE_UNBOUND",
                "ORACLE_ARTIFACT_INSTANCE_CONTENT_MISMATCH",
                "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISSING",
            }.issubset({item["reason_code"] for item in empty_path_issues}))

            strict_empty_path = artifact_connection()
            self.addCleanup(strict_empty_path.close)
            empty_path_configs = []
            for slot in (0, 1):
                payload = {
                    **strict_artifacts[0]["_expected_artifact_instance_payload"],
                    "runtime_classpath_index": slot,
                    "path_owner_loader_realm_identity": "strict-empty-path",
                }
                identity = oracle._identity(
                    "artifact_instance_identity", payload,
                )
                candidate = {
                    "loader_realm": "strict-empty-path", "slot": slot,
                    "sha256": strict_artifacts[0]["sha256"],
                    "_expected_artifact_instance_payload": payload,
                    "_expected_artifact_instance_identity": identity,
                }
                empty_path_configs.append(candidate)
                insert_artifact_row(
                    strict_empty_path,
                    identity=identity if slot == 0 else "wrong",
                    sha=candidate["sha256"],
                    realm="strict-empty-path",
                    slot=slot,
                    payload=payload,
                )
            empty_path_configs[0]["_expected_artifact_instance_payload"] = {}
            empty_path_configs[0]["_expected_artifact_instance_identity"] = ""
            _bindings, strict_empty_path_issues = (
                oracle._artifact_instance_bindings(
                    strict_empty_path,
                    empty_path_configs,
                    domain="strict-empty-path",
                )
            )
            self.assertEqual(
                {item["reason_code"] for item in strict_empty_path_issues},
                {
                    "ORACLE_ARTIFACT_INSTANCE_EXPECTATION_MISSING",
                    "ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISMATCH",
                },
            )

            (root / "binary_pairings.json").write_text(json.dumps({
                "pairings": [
                    {"logical_dependency_lineage": "exact", "status": "exact"},
                    {"logical_dependency_lineage": "base", "status": "wrong"},
                    {"logical_dependency_lineage": "current", "status": "current_only"},
                    {"logical_dependency_lineage": "ambiguous", "status": "ambiguous"},
                    {
                        "logical_dependency_lineage": "current-ambiguous",
                        "status": "ambiguous",
                    },
                ],
            }), encoding="utf-8")
            pairing_issues, pairing_truth = oracle._validate_pairings(
                root,
                [
                    {"lineage": "exact"}, {"coord": "base"},
                    {"logical_location": "ambiguous"},
                    {"logical_location": "ambiguous"},
                ],
                [
                    {"lineage": "exact"}, {"coord": "current"},
                    {"logical_location": "ambiguous"},
                    {"logical_location": "current-ambiguous"},
                    {"logical_location": "current-ambiguous"},
                ],
            )
            self.assertEqual(
                pairing_truth["pairings"],
                {
                    "ambiguous": "ambiguous", "base": "base_only",
                    "current": "current_only",
                    "current-ambiguous": "ambiguous", "exact": "exact",
                },
            )
            self.assertEqual(
                [item["reason_code"] for item in pairing_issues],
                ["ORACLE_PAIRING_MISMATCH"],
            )
            (root / "binary_pairings.json").write_text(
                '{"pairings": []}', encoding="utf-8",
            )
            self.assertEqual(
                oracle._validate_pairings(root, [], []),
                ([], {"pairings": {}}),
            )

    def test_source_attestation_boundary_and_adversarial_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary)
            attestation = generation / "binary_source_attestation.json"

            issues, truth = oracle._validate_source_attestation(generation, {})
            self.assertEqual(issues, [])
            self.assertEqual(truth, {
                "source_input_status": "not_provided", "source_file_count": 0,
            })
            attestation.write_text("{}", encoding="utf-8")
            issues, _truth = oracle._validate_source_attestation(generation, {})
            self.assertEqual(
                [item["reason_code"] for item in issues],
                ["ORACLE_UNEXPECTED_SOURCE_ATTESTATION_PRESENT"],
            )
            attestation.unlink()
            issues, truth = oracle._validate_source_attestation(
                generation, {"source_overlay": {"source_sets": []}},
            )
            self.assertEqual(
                [item["reason_code"] for item in issues],
                ["ORACLE_SOURCE_ATTESTATION_MISSING"],
            )
            self.assertEqual(truth["source_input_status"], "provided")

            source_root = generation / "simple-source"
            source_root.mkdir()
            java_file = source_root / "A.java"
            kotlin_file = source_root / "B.kt"
            ignored_file = source_root / "ignored.txt"
            nested_directory = source_root / "nested"
            nested_directory.mkdir()
            java_file.write_text("class A {}\n", encoding="utf-8")
            kotlin_file.write_text("class B\n", encoding="utf-8")
            ignored_file.write_text("ignored\n", encoding="utf-8")
            files = [
                {
                    "owner_type": "", "owner_coord": "", "module": "root",
                    "logical_path": "A.java",
                    "sha256": hashlib.sha256(java_file.read_bytes()).hexdigest(),
                },
                {
                    "owner_type": "", "owner_coord": "", "module": "root",
                    "logical_path": "B.kt",
                    "sha256": hashlib.sha256(kotlin_file.read_bytes()).hexdigest(),
                },
            ]
            source_sets = [{
                "owner_type": "", "owner_coord": "", "module": "root",
                "snapshot_revision": "content-addressed-only", "file_count": 2,
            }]
            expected_gap = {
                "reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
                "language": "kotlin",
                "owner_coord": "",
                "module": "root",
                "logical_path": "B.kt",
            }
            valid_payload = {
                "files": files,
                "source_sets": source_sets,
                "source_snapshot_identity": oracle._identity(
                    "source_snapshot_identity", {"files": files},
                ),
                "file_count": 2,
                "language_file_counts": {"java": 1, "kotlin": 1},
                "coverage_gaps": [expected_gap],
                "coverage_status": "partial",
            }
            attestation.write_text(
                json.dumps(valid_payload), encoding="utf-8",
            )
            simple_config = {"source_overlay": {"source_sets": [{
                "source_dirs": [str(source_root)],
            }]}}
            issues, truth = oracle._validate_source_attestation(
                generation, simple_config,
            )
            self.assertEqual(issues, [])
            self.assertEqual(truth["source_file_count"], 2)
            self.assertEqual(truth["source_coverage_status"], "partial")
            self.assertTrue(truth["source_manifest_exact"])

            invalid_payload = dict(valid_payload)
            invalid_payload.update({
                "files": [],
                "source_sets": [],
                "source_snapshot_identity": "wrong",
                "file_count": 999,
                "language_file_counts": {"java": 999},
                "coverage_gaps": [
                    {},
                    {
                        "reason_code": "INVALID_REASON",
                        "owner_coord": "", "module": "root",
                        "logical_path": "A.java",
                    },
                    {
                        "reason_code": "INVALID_REASON",
                        "owner_coord": "", "module": "root",
                        "logical_path": "A.java",
                    },
                    {
                        "reason_code": "BINARY_SOURCE_PARSE_PARTIAL",
                        "owner_coord": "missing", "module": "root",
                        "logical_path": "Missing.java",
                    },
                ],
                "coverage_status": "complete",
            })
            attestation.write_text(
                json.dumps(invalid_payload), encoding="utf-8",
            )
            issues, truth = oracle._validate_source_attestation(
                generation, simple_config,
            )
            reason_codes = {item["reason_code"] for item in issues}
            self.assertTrue({
                "ORACLE_SOURCE_FILE_MANIFEST_MISMATCH",
                "ORACLE_SOURCE_SET_ATTESTATION_MISMATCH",
                "ORACLE_SOURCE_SNAPSHOT_IDENTITY_MISMATCH",
                "ORACLE_SOURCE_FILE_COUNT_MISMATCH",
                "ORACLE_SOURCE_LANGUAGE_COUNTS_MISMATCH",
                "ORACLE_SOURCE_COVERAGE_GAP_INVALID",
                "ORACLE_SOURCE_COVERAGE_GAPS_MISMATCH",
                "ORACLE_SOURCE_COVERAGE_STATUS_MISMATCH",
            }.issubset(reason_codes))
            self.assertFalse(truth["source_manifest_exact"])

            empty_manifest = {
                "files": [], "source_sets": [],
                "source_snapshot_identity": oracle._identity(
                    "source_snapshot_identity", {"files": []},
                ),
                "file_count": 0, "language_file_counts": {},
                "coverage_gaps": [], "coverage_status": "complete",
            }
            attestation.write_text(
                json.dumps(empty_manifest), encoding="utf-8",
            )
            self.assertEqual(
                oracle._validate_source_attestation(
                    generation,
                    {"source_overlay": {"enabled": True}},
                )[0],
                [],
            )

            first_root = generation / "first-root"
            second_root = generation / "second-root"
            outside_root = generation / "outside-root"
            common_root = generation / "common-root"
            for directory in (
                first_root, second_root, outside_root, common_root,
            ):
                directory.mkdir()
            (outside_root / "Outside.scala").write_text(
                "class Outside\n", encoding="utf-8",
            )
            (common_root / "Inside.groovy").write_text(
                "class Inside {}\n", encoding="utf-8",
            )
            attestation.write_text(
                json.dumps(empty_manifest), encoding="utf-8",
            )
            adversarial_config = {"source_overlay": {"source_sets": [
                None,
                {
                    "source_dirs": [str(first_root), str(second_root)],
                    "owner_coord": "two-roots",
                },
                {
                    "source_dirs": [str(generation / "missing-root")],
                    "source_root": str(common_root),
                },
                {
                    "source_dirs": [str(outside_root)],
                    "source_root": str(common_root),
                    "owner_type": "dependency", "owner_coord": "outside",
                    "module": "outside-module", "snapshot_revision": "rev-out",
                },
                {
                    "source_dirs": [str(common_root)],
                    "source_root": str(common_root),
                    "owner_type": "business", "owner_coord": "inside",
                    "module": "inside-module", "snapshot_revision": "rev-in",
                },
            ]}}
            issues, truth = oracle._validate_source_attestation(
                generation, adversarial_config,
            )
            reason_codes = {item["reason_code"] for item in issues}
            self.assertIn("ORACLE_SOURCE_COMMON_ROOT_MISSING", reason_codes)
            self.assertIn("ORACLE_SOURCE_ROOT_MISSING", reason_codes)
            self.assertIn("ORACLE_SOURCE_FILE_OUTSIDE_SNAPSHOT", reason_codes)
            self.assertIn(
                "ORACLE_SOURCE_COVERAGE_GAPS_MISMATCH", reason_codes,
            )
            self.assertEqual(truth["source_coverage_status"], "complete")

    def test_resource_selection_and_validation_finalization_boundary_matrix(self):
        def resource_connection(rows):
            connection = sqlite3.connect(":memory:")
            connection.row_factory = sqlite3.Row
            connection.execute("""
                CREATE TABLE reconciliation_records (
                    chunk_identity BLOB PRIMARY KEY,
                    record_kind INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    payload_zlib BLOB NOT NULL
                )
            """)
            encoded = json.dumps([
                {"payload": row} for row in rows
            ]).encode("utf-8")
            connection.execute(
                "INSERT INTO reconciliation_records VALUES (?,?,?,?)",
                (
                    b"resource-selection",
                    oracle._ORACLE_RECONCILIATION_KIND_CODES[
                        "resource_selection"
                    ],
                    len(rows),
                    zlib.compress(encoded),
                ),
            )
            return connection

        empty_connection = resource_connection([])
        self.addCleanup(empty_connection.close)
        self.assertEqual(
            oracle._validate_resource_selections(
                empty_connection, [], [], (), {"realms": []},
            ),
            ([], {"resource_selections": []}),
        )

        artifacts = [
            {
                "path": "one.jar", "loader_realm": "child", "slot": 1,
                "runtime_code_source_origin_identity": "origin-one",
            },
            {
                "path": "two.jar", "loader_realm": "child", "slot": 2,
                "runtime_code_source_origin_identity": "",
            },
            {"path": "three.jar", "loader_realm": "child", "slot": 3},
        ]
        inventories = [
            {"resources": {
                "config/runtime.xml": [{
                    "semantic_digest": "xml-one", "sha256": "raw-xml-one",
                    "semantic_facts": [["xml_root", "beans"]],
                }],
                "data.bin": [{
                    "semantic_digest": "unused", "sha256": "data-one",
                    "semantic_facts": [],
                }],
                "META-INF/services/demo.Service": [{
                    "semantic_digest": "service-one", "sha256": "raw-service",
                    "semantic_facts": [["ordered_entry", "demo.One"]],
                }],
            }},
            {"resources": {
                "config/runtime.xml": [{
                    "semantic_digest": "xml-two", "sha256": "raw-xml-two",
                    "semantic_facts": [],
                }],
                "data.bin": [{
                    "semantic_digest": "unused-two", "sha256": "data-two",
                    "semantic_facts": [],
                }],
            }},
        ]
        topology = {"realms": [
            {"identity": "platform", "kind": "platform"},
            {
                "identity": "child", "parent": "platform",
                "delegation": "parent_first", "module_mode": "unnamed",
            },
        ]}
        production_rows = [
            {
                "initiating_loader_realm_identity": "child",
                "resource_name": "config/runtime.xml",
                "resource_mechanism": "ordered_all",
                "selected_resources": [
                    {
                        "runtime_classpath_index": 1,
                        "runtime_code_source_origin_identity": "origin-one",
                        "normalized_resource_digest": "ignored-by-facts",
                        "content_sha256": "ignored",
                        "resource_semantic_facts": [["xml_root", "beans"]],
                    },
                    {
                        "runtime_classpath_index": 2,
                        "runtime_code_source_origin_identity": "",
                        "normalized_resource_digest": "xml-two",
                        "content_sha256": "ignored",
                    },
                ],
            },
            {
                "initiating_loader_realm_identity": "child",
                "resource_name": "data.bin",
                "resource_mechanism": "classloader_first",
                "selected_resources": [{
                    "runtime_classpath_index": 1,
                    "runtime_code_source_origin_identity": "origin-one",
                    "normalized_resource_digest": "ignored",
                    "content_sha256": "data-one",
                    "resource_semantic_facts": [],
                }],
            },
            {
                "initiating_loader_realm_identity": "child",
                "resource_name": "unexpected.bin",
                "resource_mechanism": "classloader_first",
                "selected_resources": [],
            },
        ]
        connection = resource_connection(production_rows)
        self.addCleanup(connection.close)
        issues, truth = oracle._validate_resource_selections(
            connection, artifacts, inventories, ("child",), topology,
        )
        self.assertEqual(
            {item["reason_code"] for item in issues},
            {
                "ORACLE_RESOURCE_SELECTION_MISMATCH",
                "ORACLE_RESOURCE_SELECTION_UNEXPECTED",
            },
        )
        selections = {
            (item["realm"], item["name"], item["mechanism"]): item["selected"]
            for item in truth["resource_selections"]
        }
        self.assertEqual(
            len(selections[("child", "config/runtime.xml", "ordered_all")]),
            2,
        )
        self.assertEqual(
            len(selections[("child", "data.bin", "classloader_first")]),
            1,
        )
        fallback_connection = resource_connection([])
        self.addCleanup(fallback_connection.close)
        with patch.object(
            oracle,
            "_ordered_artifacts_for_realm",
            return_value=[{"path": "implicit.jar", "slot": 0}],
        ):
            fallback_issues, _fallback_truth = (
                oracle._validate_resource_selections(
                    fallback_connection,
                    [{"path": "implicit.jar", "slot": 0}],
                    [{"resources": {"data.bin": [{
                        "semantic_digest": "unused", "sha256": "data",
                        "semantic_facts": [],
                    }]}}],
                    ("entrypoint",),
                    {},
                )
            )
        self.assertEqual(
            [item["reason_code"] for item in fallback_issues],
            ["ORACLE_RESOURCE_SELECTION_MISMATCH"],
        )

        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary)
            written = generation / "validation" / "result.json"
            progress = []
            with (
                patch.object(
                    oracle, "oracle_support_manifest_identity",
                    return_value="oracle-manifest",
                ),
                patch.object(
                    oracle, "validator_implementation_identity",
                    return_value="validator",
                ),
                patch.object(
                    oracle, "_write_validation_attachment",
                    return_value=written,
                ) as write,
            ):
                passed = oracle._finalize_validation_result(
                    generation,
                    {
                        "result_generation_identity": "generation",
                        "active_snapshot_identities": {"facts": "snapshot"},
                    },
                    {},
                    {},
                    [],
                    None,
                )
                failed = oracle._finalize_validation_result(
                    generation,
                    {
                        "result_generation_identity": "",
                        "active_snapshot_identities": [],
                    },
                    {
                        "base": {
                            "status": "not_run", "reason_code": "",
                            "nested": {
                                "status": "not_run", "reason_code": "nested",
                            },
                            "completed": {"status": "passed"},
                            "plain": "value",
                        },
                        "current": {
                            "nested": {
                                "status": "not_run", "reason_code": "current",
                            },
                            "empty-reason": {
                                "status": "not_run", "reason_code": "",
                            },
                        },
                        "other-not-run": {
                            "status": "not_run", "reason_code": "outer",
                        },
                        "other": {"status": "passed"},
                        "plain": "value",
                    },
                    {"helper": "identity"},
                    [
                        {"domain": "first", "reason_code": "ONE"},
                        {"domain": "first", "reason_code": "TWO"},
                        {"domain": "second", "reason_code": "THREE"},
                    ],
                    lambda *event: progress.append(event),
                )
                non_mapping_base = oracle._finalize_validation_result(
                    generation,
                    {"active_snapshot_identities": {}},
                    {"base": "plain"},
                    {},
                    [],
                    None,
                )
            self.assertEqual(passed["status"], "passed")
            self.assertEqual(passed["issue_count"], 0)
            self.assertEqual(passed["skipped_domains"], [])
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["domain_summary"]["first"]["issues"], 2)
            self.assertEqual(
                {item["domain"] for item in failed["skipped_domains"]},
                {
                    "base", "base.nested", "current.empty-reason",
                    "current.nested", "other-not-run",
                },
            )
            self.assertEqual(failed["validation_result_path"], str(written))
            self.assertEqual(non_mapping_base["skipped_domains"], [])
            self.assertEqual(write.call_count, 3)
            self.assertEqual(len(progress), 2)

    def test_validation_attachment_portable_and_dirfd_race_matrix(self):
        class WindowsFlagModelOs:
            O_NOFOLLOW = 0
            O_BINARY = int(getattr(os, "O_CLOEXEC", 0))

            def __getattr__(self, name):
                return getattr(os, name)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            portable_generation = root / "portable"
            portable_generation.mkdir()
            with patch.object(oracle, "os", WindowsFlagModelOs()):
                first = oracle._write_validation_attachment_portable(
                    portable_generation, "same.json", {"value": 1},
                )
                second = oracle._write_validation_attachment_portable(
                    portable_generation, "same.json", {"value": 1},
                )
            self.assertEqual(first, second)
            self.assertEqual(
                json.loads(first.read_text(encoding="utf-8")), {"value": 1},
            )

            portable_collision = root / "portable-collision"
            (portable_collision / "validation").mkdir(parents=True)
            collision = portable_collision / "validation" / "same.json"
            collision.write_text("different", encoding="utf-8")
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._write_validation_attachment_portable(
                    portable_collision, "same.json", {"value": 1},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_IDENTITY_COLLISION",
            )

            portable_symlink_dir = root / "portable-symlink-dir"
            portable_symlink_dir.mkdir()
            portable_external = root / "portable-symlink-external"
            portable_external.mkdir()
            (portable_symlink_dir / "validation").symlink_to(
                portable_external, target_is_directory=True,
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._write_validation_attachment_portable(
                    portable_symlink_dir, "result.json", {},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            )

            real_generation = root / "real-generation"
            real_generation.mkdir()
            linked_generation = root / "linked-generation"
            linked_generation.symlink_to(real_generation, target_is_directory=True)
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._write_validation_attachment_portable(
                    linked_generation, "result.json", {},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            )

            real_parent = root / "real-parent"
            real_parent.mkdir()
            (real_parent / "generation").mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            canonical_destination = (
                oracle._write_validation_attachment_portable(
                    linked_parent / "generation", "result.json", {},
                )
            )
            self.assertEqual(
                canonical_destination.parent,
                (real_parent / "generation" / "validation").resolve(),
            )

            resolve_generation = root / "resolve-race"
            resolve_generation.mkdir()
            validation_dir = resolve_generation / "validation"
            outside = root / "outside-validation"
            outside.mkdir()
            real_resolve = Path.resolve

            def mismatched_validation_resolve(path, strict=False):
                if (
                    path.name == validation_dir.name
                    and path.parent.name == resolve_generation.name
                ):
                    return Path(os.path.realpath(outside))
                return real_resolve(path, strict=strict)

            with (
                patch.object(Path, "resolve", new=mismatched_validation_resolve),
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._write_validation_attachment_portable(
                    resolve_generation, "result.json", {},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            )

            cleanup_generation = root / "portable-cleanup"
            cleanup_generation.mkdir()
            with (
                patch.object(
                    Path, "unlink", side_effect=OSError(errno.EIO, "cleanup"),
                ),
                self.assertRaises(oracle.BinaryValidationError) as raised,
            ):
                oracle._write_validation_attachment_portable(
                    cleanup_generation, "result.json", {"value": 1},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            )

            def portable_post_race(name, mutate):
                generation = root / f"portable-post-{name}"
                generation.mkdir()
                calls = 0

                def fsync_then_mutate(path):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        mutate(generation, generation / "validation")
                    return True

                with (
                    patch.object(
                        oracle, "fsync_directory",
                        side_effect=fsync_then_mutate,
                    ),
                    self.assertRaises(oracle.BinaryValidationError) as error,
                ):
                    oracle._write_validation_attachment_portable(
                        generation, "result.json", {"value": 1},
                    )
                self.assertEqual(
                    error.exception.reason_code,
                    "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
                )

            def replace_validation_with_symlink(generation, validation):
                validation.rename(generation / "validation-original")
                external = generation.parent / "external-validation-post"
                external.mkdir()
                validation.symlink_to(external, target_is_directory=True)

            portable_post_race(
                "validation-symlink", replace_validation_with_symlink,
            )

            def replace_generation_with_symlink(generation, _validation):
                moved = generation.parent / "generation-original"
                generation.rename(moved)
                external = generation.parent / "external-generation-post"
                (external / "validation").mkdir(parents=True)
                generation.symlink_to(external, target_is_directory=True)

            portable_post_race(
                "generation-symlink", replace_generation_with_symlink,
            )

            def replace_destination_with_symlink(generation, validation):
                destination = validation / "result.json"
                destination.unlink()
                external = generation.parent / "external-result.json"
                external.write_text("external", encoding="utf-8")
                destination.symlink_to(external)

            portable_post_race(
                "destination-symlink", replace_destination_with_symlink,
            )
            portable_post_race(
                "destination-missing",
                lambda _generation, validation: (
                    validation / "result.json"
                ).unlink(),
            )

            if oracle._secure_validation_dirfd_supported():
                dirfd_generation = root / "dirfd"
                dirfd_generation.mkdir()
                with patch.object(oracle, "os", WindowsFlagModelOs()):
                    first = oracle._write_validation_attachment_dirfd(
                        dirfd_generation, "same.json", {"value": 1},
                    )
                    second = oracle._write_validation_attachment_dirfd(
                        dirfd_generation, "same.json", {"value": 1},
                    )
                self.assertEqual(first, second)

                dirfd_collision = root / "dirfd-collision"
                (dirfd_collision / "validation").mkdir(parents=True)
                collision = dirfd_collision / "validation" / "same.json"
                collision.write_text("different", encoding="utf-8")
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle._write_validation_attachment_dirfd(
                        dirfd_collision, "same.json", {"value": 1},
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_VALIDATION_IDENTITY_COLLISION",
                )

                class UnlinkFailingOs(WindowsFlagModelOs):
                    @staticmethod
                    def unlink(*_args, **_kwargs):
                        raise OSError(errno.EIO, "cleanup")

                cleanup_dirfd = root / "dirfd-cleanup"
                cleanup_dirfd.mkdir()
                with (
                    patch.object(oracle, "os", UnlinkFailingOs()),
                    self.assertRaises(oracle.BinaryValidationError) as raised,
                ):
                    oracle._write_validation_attachment_dirfd(
                        cleanup_dirfd, "result.json", {"value": 1},
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
                )

                directory_shapes = (
                    [True, True, True, False],
                    [True, True, True, True, False],
                    [True, True, True, True, True, False],
                )
                for index, shape in enumerate(directory_shapes):
                    generation = root / f"dirfd-shape-{index}"
                    generation.mkdir()
                    with (
                        patch.object(
                            oracle.stat, "S_ISDIR", side_effect=shape,
                        ),
                        self.assertRaises(
                            oracle.BinaryValidationError
                        ) as raised,
                    ):
                        oracle._write_validation_attachment_dirfd(
                            generation, "result.json", {"value": 1},
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
                    )

                identity_sequences = (
                    ["parent", "generation", "validation", "changed"],
                    [
                        "parent", "generation", "validation", "parent",
                        "changed",
                    ],
                    [
                        "parent", "generation", "validation", "parent",
                        "generation", "changed",
                    ],
                )
                for index, identities in enumerate(identity_sequences):
                    generation = root / f"dirfd-identity-{index}"
                    generation.mkdir()
                    with (
                        patch.object(
                            oracle, "_descriptor_identity",
                            side_effect=identities,
                        ),
                        self.assertRaises(
                            oracle.BinaryValidationError
                        ) as raised,
                    ):
                        oracle._write_validation_attachment_dirfd(
                            generation, "result.json", {"value": 1},
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
                    )

                def dirfd_shape_race(name, target):
                    parent = root / f"dirfd-physical-{name}"
                    generation = parent / "generation"
                    generation.mkdir(parents=True)
                    calls = 0

                    def mutate_after_publish(_descriptor):
                        nonlocal calls
                        calls += 1
                        if calls != 2:
                            return True
                        if target == "parent":
                            parent.rename(root / f"{parent.name}-original")
                            parent.write_text("not-a-directory", encoding="utf-8")
                        elif target == "generation":
                            generation.rename(parent / "generation-original")
                            generation.write_text(
                                "not-a-directory", encoding="utf-8",
                            )
                        else:
                            validation = generation / "validation"
                            validation.rename(generation / "validation-original")
                            validation.write_text(
                                "not-a-directory", encoding="utf-8",
                            )
                        return True

                    with (
                        patch.object(
                            oracle, "_fsync_bound_directory",
                            side_effect=mutate_after_publish,
                        ),
                        self.assertRaises(
                            oracle.BinaryValidationError
                        ) as raised,
                    ):
                        oracle._write_validation_attachment_dirfd(
                            generation, "result.json", {"value": 1},
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
                    )

                for target in ("parent", "generation", "validation"):
                    dirfd_shape_race(target, target)

    def test_scan_normalization_and_provider_member_attachment_matrix(self):
        def row(**overrides):
            value = {
                "caller_owner": "demo.Caller",
                "caller_member": "run",
                "caller_descriptor": "()V",
                "callee_owner": "demo.Target",
                "callee_member": "call",
                "callee_descriptor": "()V",
                "opcode_family": "invokevirtual",
                "instruction_offset": 1,
                "reference_kind": "method",
                "reference_interface": False,
            }
            value.update(overrides)
            return value

        already = oracle._incomplete_oracle_scan_evidence("a" * 64, ())
        self.assertIs(oracle._normalize_oracle_scan(already), already)
        incomplete = oracle._normalize_oracle_scan({
            "complete": False, "edges": [{"unreadable": True}],
        })
        self.assertFalse(incomplete.complete)
        self.assertEqual(incomplete.artifact_sha256, "")

        invalid_rows = (
            row(opcode_family="unknown", reference_kind="method"),
            row(opcode_family="getstatic", reference_kind="method"),
            row(reference_kind="field", reference_interface=False),
            row(reference_interface=None),
            row(reference_interface=True),
            row(
                opcode_family="invokeinterface",
                reference_kind="interface_method",
                reference_interface=False,
            ),
            row(
                opcode_family="invokedynamic",
                reference_kind="invalid",
                reference_interface=False,
            ),
            row(
                opcode_family="invokedynamic",
                reference_kind="REF_invokeStatic",
                reference_interface=None,
            ),
        )
        for invalid_row in invalid_rows:
            normalized = oracle._normalize_oracle_scan({
                "artifact_sha256": "b" * 64,
                "complete": True,
                "edges": [invalid_row],
                "failures": ["preexisting"],
            })
            self.assertFalse(normalized.complete)
            self.assertEqual(normalized.failures[0], "preexisting")

        valid_rows = [
            row(),
            row(
                caller_member="interfaceCall",
                opcode_family="invokeinterface",
                reference_kind="interface_method",
                reference_interface=True,
            ),
            row(
                caller_member="fieldRead", opcode_family="getstatic",
                reference_kind="field", reference_interface=None,
            ),
            row(
                caller_member="dynamic",
                opcode_family="invokedynamic",
                reference_kind="REF_invokeStatic", reference_interface=False,
            ),
            row(
                caller_member="emptyOwner", callee_owner="",
                opcode_family="invokestatic", reference_kind="method",
            ),
        ]
        raw = {
            "artifact_sha256": "c" * 64,
            "complete": True,
            "edges": valid_rows,
            "failures": ["same", "same"],
            "structural_facts": {
                "class_names": ["demo/Caller"],
                "type_edges": [[
                    "demo/Caller", "run", "()V", 1, "demo/Target",
                    "new", ["nested", "same"],
                ]],
                "class_init_edges": [["demo/Caller", "demo/Target"]],
                "clinit_classes": ["demo/Caller"],
                "semantic_instructions": [[
                    "demo/Caller", "run", ("same", "same"), 1,
                ]],
                "declared_members": [[
                    "demo/Caller", "method", "run", "()V", 1,
                ]],
            },
        }
        pool = {}
        normalized = oracle._normalize_oracle_scan(
            oracle._pack_oracle_scan(raw), pool,
        )
        self.assertTrue(normalized.complete)
        self.assertEqual(len(normalized.direct_truth.direct_edges), 4)
        self.assertEqual(len(normalized.direct_truth.dynamic_handle_edges), 1)
        self.assertEqual(normalized.direct_truth.discovery_classes, {
            "demo/Target",
        })
        self.assertEqual(normalized.failures, ("same", "same"))
        self.assertEqual(
            normalized.structural_truth.clinit_classes,
            frozenset({"demo/Caller"}),
        )
        without_pool = oracle._normalize_oracle_scan(raw)
        self.assertEqual(
            without_pool.direct_truth.direct_edges,
            normalized.direct_truth.direct_edges,
        )
        with self.assertRaises(TypeError):
            oracle._normalize_oracle_scan({
                "artifact_sha256": "d" * 64,
                "complete": True,
                "edges": [],
                "structural_facts": {
                    "semantic_instructions": [[
                        "owner", {"text": "value", 1: "non-string-key"},
                    ]],
                },
            })

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.jar"
            second = root / "second.jar"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            first_uri = f"jar:{first.as_uri()}!/demo/First.class"
            second_uri = f"jar:{second.as_uri()}!/demo/Second.class"

            fallback_observations = {
                "demo/First": {}, "demo/Missing": {},
            }
            oracle._attach_provider_declared_members(
                [],
                {"declared_members": [
                    ("demo/First", "method", "run", "()V", 1),
                    ("demo/First", "method", "run", "()V", 1),
                    ("demo/Absent", "field", "value", "I", 1),
                ]},
                fallback_observations,
                {},
            )
            self.assertEqual(
                fallback_observations["demo/First"]["javap_declared_members"],
                ("method|run|()V|1",),
            )
            untouched = {"demo/First": {}}
            oracle._attach_provider_declared_members(
                [], {}, untouched, {},
            )
            self.assertEqual(untouched, {"demo/First": {}})

            artifacts = [
                {
                    "path": str(first),
                    "_expected_artifact_instance_identity": "first-id",
                },
                {
                    "path": str(second),
                    "_expected_artifact_instance_identity": "",
                },
            ]
            observations = {
                "demo/First": {"provider_resource_url": first_uri},
                "demo/NoProvider": {},
                "demo/Second": {"provider_resource_url": second_uri},
            }
            oracle._attach_provider_declared_members(
                artifacts,
                {"declared_members_by_artifact": [
                    {
                        "artifact_instance_identity": "",
                        "members": [],
                    },
                    {
                        "artifact_instance_identity": "unknown-id",
                        "members": [("demo/First", "method", "ignored", "()V", 1)],
                    },
                    {
                        "artifact_instance_identity": "first-id",
                        "members": [
                            ("demo/First", "method", "run", "()V", 1),
                            ("demo/Other", "field", "value", "I", 1),
                        ],
                    },
                ]},
                observations,
                {},
            )
            self.assertEqual(
                observations["demo/First"]["javap_declared_members"],
                ("method|run|()V|1",),
            )
            self.assertNotIn(
                "javap_declared_members", observations["demo/NoProvider"],
            )
            self.assertNotIn(
                "javap_declared_members", observations["demo/Second"],
            )

            cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=0)
            self.addCleanup(cache.clear)
            evidence = oracle._OracleScanEvidence(
                artifact_sha256="e" * 64,
                complete=True,
                failures=(),
                direct_truth=oracle._DirectEdgeTruth(
                    artifact_sha256="e" * 64,
                    direct_edges=frozenset(), dynamic_handle_edges=frozenset(),
                    discovery_classes=frozenset(),
                ),
                structural_truth=oracle._StructuralTruth(
                    type_edges=frozenset(), class_init_edges=frozenset(),
                    clinit_classes=frozenset(), semantic_instructions=frozenset(),
                    declared_members=frozenset({
                        ("demo/First", "method", "cached", "()V", 1),
                        ("demo/Other", "method", "other", "()V", 1),
                    }),
                    failures=(),
                ),
                structural_class_names=frozenset(),
            )
            cache.put_evidence(("e" * 64, "javap"), evidence)
            cached_observations = {
                "demo/First": {"provider_resource_url": first_uri},
                "demo/NoProvider": {},
            }
            oracle._attach_provider_declared_members_from_scan_cache(
                [
                    {"path": str(second), "sha256": "f" * 64},
                    {"path": str(first), "sha256": "e" * 64},
                ],
                "javap",
                cache,
                cached_observations,
                {},
            )
            self.assertEqual(
                cached_observations["demo/First"]["javap_declared_members"],
                ("method|cached|()V|1",),
            )
            oracle._attach_provider_declared_members_from_scan_cache(
                [], "javap", cache, {"demo/None": {}}, {},
            )
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._attach_provider_declared_members_from_scan_cache(
                    [{"path": str(first), "sha256": "0" * 64}],
                    "javap",
                    cache,
                    {"demo/First": {"provider_resource_url": first_uri}},
                    {},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_SHARED_SCAN_MISSING",
            )

    def test_direct_edge_validator_cache_deadline_and_projection_matrix(self):
        def raw_scan(sha, *, complete=True):
            return {
                "artifact_sha256": sha,
                "complete": complete,
                "failures": [] if complete else ["incomplete"],
                "edges": [],
                "structural_facts": {
                    "type_edges": [], "class_init_edges": [],
                    "clinit_classes": [], "semantic_instructions": [],
                    "declared_members": [], "class_names": [],
                },
            }

        def evidence(sha, *, complete=True):
            failures = () if complete else ("incomplete",)
            return oracle._OracleScanEvidence(
                artifact_sha256=sha,
                complete=complete,
                failures=failures,
                direct_truth=oracle._DirectEdgeTruth(
                    artifact_sha256=sha,
                    direct_edges=frozenset(),
                    dynamic_handle_edges=frozenset(),
                    discovery_classes=frozenset(),
                ),
                structural_truth=oracle._StructuralTruth(
                    type_edges=frozenset(), class_init_edges=frozenset(),
                    clinit_classes=frozenset(),
                    semantic_instructions=frozenset(),
                    declared_members=frozenset(), failures=failures,
                ),
                structural_class_names=frozenset(),
            )

        first = {
            "path": "first.jar", "sha256": "a" * 64,
            "loader_realm": "", "slot": 1,
        }
        second = {
            "path": "second.jar", "sha256": "b" * 64,
            "loader_realm": "realm", "slot": 2,
        }

        def bindings(_connection, artifacts, **_kwargs):
            return ({
                (str(item.get("loader_realm") or ""), int(item["slot"])):
                    f"instance-{item['slot']}"
                for item in artifacts
            }, [])

        def invoke(artifacts, **kwargs):
            with (
                patch.object(
                    oracle, "_artifact_instance_bindings",
                    side_effect=bindings,
                ),
                patch.object(
                    oracle, "_production_direct_truth_for_artifact",
                    return_value=(set(), set()),
                ),
                patch.object(oracle, "clear_immutable_oracle_cache"),
            ):
                return oracle._validate_direct_edges(
                    MagicMock(), artifacts, javap="javap", **kwargs,
                )

        key = (first["sha256"], "javap")
        ordinary_cache = {key: raw_scan(first["sha256"])}
        issues, truth = invoke(
            [first], scan_cache=ordinary_cache, time_budget_seconds=0,
        )
        self.assertEqual(issues, [])
        self.assertIsInstance(ordinary_cache[key], oracle._OracleScanEvidence)
        self.assertEqual(truth["direct_edges"], [])

        # A valid but identity-less independent observation remains usable;
        # a conflicting non-empty identity fails closed.
        issues, _truth = invoke(
            [first], scan_cache={key: evidence("")},
        )
        self.assertEqual(issues, [])
        issues, _truth = invoke(
            [first], scan_cache={key: evidence("c" * 64)},
        )
        self.assertEqual(
            issues[0]["reason_code"],
            "ORACLE_ARTIFACT_CHANGED_DURING_DIRECT_EDGE_VALIDATION",
        )

        empty_truth = oracle._DirectEdgeTruth(
            artifact_sha256="", direct_edges=frozenset(),
            dynamic_handle_edges=frozenset(), discovery_classes=frozenset(),
        )
        issues, _truth = invoke(
            [first], scan_cache={key: evidence(first["sha256"])},
            truth_cache={key: empty_truth},
        )
        self.assertEqual(issues, [])
        conflicting_truth = oracle._DirectEdgeTruth(
            artifact_sha256="d" * 64, direct_edges=frozenset(),
            dynamic_handle_edges=frozenset(), discovery_classes=frozenset(),
        )
        issues, _truth = invoke(
            [first], scan_cache={key: evidence(first["sha256"])},
            truth_cache={key: conflicting_truth},
        )
        self.assertEqual(
            issues[0]["reason_code"],
            "ORACLE_ARTIFACT_CHANGED_DURING_DIRECT_EDGE_VALIDATION",
        )

        direct_row = (
            "demo.Caller", "run", "()V", "", "target", "()V",
            "invokevirtual", 1, "method",
        )
        ordered = [direct_row]
        direct_identity = oracle._artifact_truth_identity(
            "binary_oracle_direct_edge_artifact_truth", ordered,
        )
        dynamic_identity = oracle._artifact_truth_identity(
            "binary_oracle_dynamic_edge_artifact_truth", [],
        )
        projection_cache = {("direct", *key): {
            "direct_record_count": 1,
            "direct_record_identity": direct_identity,
            "dynamic_record_count": 0,
            "dynamic_record_identity": dynamic_identity,
        }}
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", side_effect=bindings,
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
                return_value=({direct_row}, set()),
            ),
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, truth = oracle._validate_direct_edges(
                MagicMock(), [first], javap="javap",
                scan_cache={key: evidence(first["sha256"])},
                validated_projection_cache=projection_cache,
                retain_truth_rows=False,
            )
        self.assertEqual(issues, [])
        self.assertEqual(truth["discovery_classes"], [])
        self.assertEqual(truth["direct_edges"]["record_count"], 1)

        def production_with_issue(_connection, _identity, issue_rows, **_kwargs):
            issue_rows.append({
                "domain": "direct_edge", "reason_code": "PREEXISTING",
            })
            return set(), set()

        with (
            patch.object(
                oracle, "_artifact_instance_bindings", side_effect=bindings,
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
                side_effect=production_with_issue,
            ),
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, _truth = oracle._validate_direct_edges(
                MagicMock(), [first], javap="javap",
                scan_cache={key: evidence(first["sha256"])},
                validated_projection_cache=projection_cache,
            )
        self.assertIn("PREEXISTING", {row["reason_code"] for row in issues})

        # Missing artifact-instance bindings are retained as binding issues
        # and never attempt production or Oracle comparison.
        with (
            patch.object(
                oracle, "_artifact_instance_bindings",
                return_value=({}, [{
                    "domain": "direct_edge", "reason_code": "NO_BINDING",
                }]),
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
            ) as production,
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, _truth = oracle._validate_direct_edges(
                MagicMock(), [first], javap="javap",
                scan_cache={key: evidence(first["sha256"])},
            )
        self.assertEqual(issues[0]["reason_code"], "NO_BINDING")
        production.assert_not_called()

        scans_by_path = {
            "first.jar": raw_scan(first["sha256"]),
            "second.jar": raw_scan(second["sha256"]),
        }
        real_wait = oracle.wait
        empty_wait_returned = False

        def one_empty_wait(active, **kwargs):
            nonlocal empty_wait_returned
            if not empty_wait_returned:
                empty_wait_returned = True
                return set(), set(active)
            return real_wait(active, **kwargs)

        scan_cache = {}
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", side_effect=bindings,
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
                return_value=(set(), set()),
            ),
            patch.object(
                oracle, "_artifact_scan_worker_count", return_value=(1, None),
            ),
            patch.object(
                oracle, "scan_final_artifact",
                side_effect=lambda path, **_kwargs: scans_by_path[str(path)],
            ),
            patch.object(oracle, "wait", side_effect=one_empty_wait),
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, _truth = oracle._validate_direct_edges(
                MagicMock(), [first, second], javap="javap",
                scan_cache=scan_cache,
            )
        self.assertEqual(issues, [])
        self.assertEqual(set(scan_cache), {
            (first["sha256"], "javap"), (second["sha256"], "javap"),
        })
        self.assertTrue(empty_wait_returned)

        # Deadline before submission: synthesize bounded incomplete evidence
        # directly into the spool cache without starting a scanner.
        spool = oracle._OracleScanSpoolCache(memory_limit_per_entry=0)
        self.addCleanup(spool.clear)
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", side_effect=bindings,
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
                return_value=(set(), set()),
            ),
            patch.object(
                oracle, "_artifact_scan_worker_count", return_value=(1, 1),
            ),
            patch.object(oracle.time, "perf_counter", side_effect=[0.0, 2.0]),
            patch.object(oracle, "scan_final_artifact") as scan,
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, _truth = oracle._validate_direct_edges(
                MagicMock(), [first], javap="javap", scan_cache=spool,
                time_budget_seconds=1,
            )
        scan.assert_not_called()
        self.assertEqual(
            issues[0]["reason_code"], "ORACLE_JAVAP_INVENTORY_INCOMPLETE",
        )

        # Deadline reached inside a submitted worker exercises the per-request
        # budget guard and the ordinary-cache incomplete-result path.
        main_thread = threading.current_thread()

        def worker_expired_clock():
            return 2.0 if threading.current_thread() is not main_thread else 0.0

        incomplete_cache = {}
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", side_effect=bindings,
            ),
            patch.object(
                oracle, "_production_direct_truth_for_artifact",
                return_value=(set(), set()),
            ),
            patch.object(
                oracle, "_artifact_scan_worker_count", return_value=(1, 1),
            ),
            patch.object(
                oracle.time, "perf_counter", side_effect=worker_expired_clock,
            ),
            patch.object(oracle, "scan_final_artifact") as scan,
            patch.object(oracle, "clear_immutable_oracle_cache"),
        ):
            issues, _truth = oracle._validate_direct_edges(
                MagicMock(), [first], javap="javap",
                scan_cache=incomplete_cache, time_budget_seconds=1,
            )
        scan.assert_not_called()
        self.assertEqual(
            issues[0]["reason_code"], "ORACLE_JAVAP_INVENTORY_INCOMPLETE",
        )

    def test_structural_validator_sources_projection_and_diff_matrix(self):
        artifact = {
            "path": "artifact.jar", "sha256": "a" * 64,
            "loader_realm": "", "slot": 1,
        }
        inventory = {"classes": {"demo/C": "demo/C.class"}}
        instance_identity = "instance-1"
        scan_key = (
            artifact["sha256"], "javap",
            (("demo/C", "demo/C.class"),),
        )
        direct_key = (artifact["sha256"], "javap")
        type_row = ("demo/C", "run", "()V", 1, "demo/T", "new")
        init_row = (
            "demo/C", "run", "()V", 2, "demo/T", "invokestatic",
        )
        semantic_row = (
            "demo/C", "run", "()V", 3, "invokevirtual", "Method x.y:()V",
        )
        declared_row = ("demo/C", "method", "run", "()V", 1)

        def structural_truth(
            *, failures=(), names=("demo/C",), type_edges=(type_row,),
            init_edges=(init_row,), clinit=("demo/C",),
        ):
            truth = oracle._StructuralTruth(
                type_edges=frozenset(type_edges),
                class_init_edges=frozenset(init_edges),
                clinit_classes=frozenset(clinit),
                semantic_instructions=frozenset({semantic_row}),
                declared_members=frozenset({declared_row}),
                failures=tuple(failures),
            )
            return oracle._OracleScanEvidence(
                artifact_sha256=artifact["sha256"], complete=not failures,
                failures=tuple(failures),
                direct_truth=oracle._DirectEdgeTruth(
                    artifact_sha256=artifact["sha256"],
                    direct_edges=frozenset(),
                    dynamic_handle_edges=frozenset(),
                    discovery_classes=frozenset(),
                ),
                structural_truth=truth,
                structural_class_names=frozenset(names),
            )

        def bindings(_connection, artifacts, **_kwargs):
            return ({
                (str(item.get("loader_realm") or ""), int(item["slot"])):
                    instance_identity
                for item in artifacts
            }, [])

        def invoke(
            *, artifacts=None, inventories=None, binding=True,
            actual_type=(), actual_init=(), production_issue=False,
            production_cache=None, scan_cache=None, direct_scan_cache=None,
            raw_scan=None, digest=None, **kwargs,
        ):
            def production(_connection, _identity, issue_rows):
                if production_issue:
                    issue_rows.append({
                        "domain": "structural_edge",
                        "reason_code": "PREEXISTING",
                    })
                return set(actual_type), set(actual_init)

            binding_result = (
                bindings(None, artifacts or [artifact])
                if binding else ({}, [{
                    "domain": "structural_edge", "reason_code": "NO_BINDING",
                }])
            )
            with (
                patch.object(
                    oracle, "_artifact_instance_bindings",
                    return_value=binding_result,
                ),
                patch.object(
                    oracle, "_production_structural_truth_for_artifact",
                    side_effect=production,
                ),
                patch.object(
                    oracle, "_sha256_file",
                    return_value=artifact["sha256"] if digest is None else digest,
                ),
                patch.object(
                    oracle, "_scan_structural_edges",
                    return_value=raw_scan if raw_scan is not None else {
                        "failures": ["unexpected-fallback"],
                    },
                ),
            ):
                return oracle._validate_structural_edges(
                    MagicMock(), artifacts or [artifact],
                    inventories or [inventory], javap="javap",
                    production_structural_cache=production_cache,
                    scan_cache=scan_cache,
                    direct_scan_cache=direct_scan_cache,
                    **kwargs,
                )

        issues, _truth = invoke(binding=False, scan_cache={
            scan_key: structural_truth().structural_truth,
        })
        self.assertEqual(issues[0]["reason_code"], "NO_BINDING")

        issues, _truth = invoke(
            digest="b" * 64,
            scan_cache={scan_key: structural_truth().structural_truth},
        )
        self.assertEqual(
            issues[0]["reason_code"],
            "ORACLE_ARTIFACT_CHANGED_DURING_STRUCTURAL_VALIDATION",
        )

        empty_production_cache = oracle._ProductionStructuralSpoolCache()
        self.addCleanup(empty_production_cache.clear)
        issues, _truth = invoke(
            production_cache=empty_production_cache,
            scan_cache={scan_key: structural_truth().structural_truth},
        )
        self.assertEqual(
            issues[0]["reason_code"],
            "ORACLE_PRODUCTION_STRUCTURAL_CACHE_MISSING",
        )

        production_cache = oracle._ProductionStructuralSpoolCache()
        self.addCleanup(production_cache.clear)
        production_cache.put(instance_identity, {type_row}, {init_row})
        cached_truth = structural_truth().structural_truth
        issues, truth = invoke(
            production_cache=production_cache,
            scan_cache={scan_key: cached_truth},
            progress_label="base",
        )
        self.assertEqual(issues, [])
        self.assertEqual(truth["type_edges"], [type_row])

        ordered_type = [type_row]
        ordered_init = [init_row]
        projection = {
            "type_edge_count": 1,
            "type_edge_identity": oracle._artifact_truth_identity(
                "binary_oracle_type_edge_artifact_truth", ordered_type,
            ),
            "class_init_edge_count": 1,
            "class_init_edge_identity": oracle._artifact_truth_identity(
                "binary_oracle_class_init_edge_artifact_truth", ordered_init,
            ),
            "semantic_instruction_count": 1,
            "semantic_instruction_identity": "semantic-identity",
            "declared_member_count": 1,
            "declared_member_identity": "declared-identity",
            "clinit_classes": ["demo/C"],
        }
        projection_cache = {
            ("structural", *direct_key, id(inventory)): projection,
        }
        issues, compact = invoke(
            production_cache=production_cache,
            validated_projection_cache=projection_cache,
            retain_truth_rows=False,
        )
        self.assertEqual(issues, [])
        self.assertEqual(compact["type_edges"]["record_counts"]["type_edges"], 1)
        self.assertEqual(compact["clinit_classes"], ["demo/C"])

        mismatched_projection = dict(projection)
        mismatched_projection["type_edge_count"] = 2
        issues, _truth = invoke(
            production_cache=production_cache,
            scan_cache={scan_key: cached_truth},
            validated_projection_cache={
                ("structural", *direct_key, id(inventory)):
                    mismatched_projection,
            },
            retain_truth_rows=False,
        )
        self.assertEqual(issues, [])

        issues, compact = invoke(
            production_cache=production_cache,
            validated_projection_cache=projection_cache,
            retain_truth_rows=False,
            artifacts=[{**artifact, "path": ""}],
        )
        self.assertEqual(issues, [])
        self.assertEqual(compact["clinit_classes"], ["demo/C"])

        # A cached projection is intentionally bypassed when rows are retained
        # or production projection has already emitted an issue.
        issues, _truth = invoke(
            production_cache=production_cache,
            scan_cache={scan_key: cached_truth},
            validated_projection_cache=projection_cache,
            retain_truth_rows=True,
        )
        self.assertEqual(issues, [])
        issues, _truth = invoke(
            actual_type={type_row}, actual_init={init_row},
            production_issue=True,
            scan_cache={scan_key: cached_truth},
            validated_projection_cache=projection_cache,
            retain_truth_rows=False,
        )
        self.assertIn("PREEXISTING", {row["reason_code"] for row in issues})

        incomplete_without_detail = structural_truth(
            failures=("placeholder",),
        )
        incomplete_without_detail = oracle._OracleScanEvidence(
            artifact_sha256=artifact["sha256"], complete=False, failures=(),
            direct_truth=incomplete_without_detail.direct_truth,
            structural_truth=oracle._StructuralTruth(
                type_edges=frozenset(), class_init_edges=frozenset(),
                clinit_classes=frozenset(), semantic_instructions=frozenset(),
                declared_members=frozenset(), failures=(),
            ),
            structural_class_names=frozenset(),
        )
        issues, _truth = invoke(
            direct_scan_cache={direct_key: incomplete_without_detail},
        )
        self.assertEqual(
            next(
                row for row in issues
                if row["reason_code"] == "ORACLE_STRUCTURAL_SCAN_INCOMPLETE"
            )["reason_code"],
            "ORACLE_STRUCTURAL_SCAN_INCOMPLETE",
        )
        incomplete_issue = next(
            row for row in issues
            if row["reason_code"] == "ORACLE_STRUCTURAL_SCAN_INCOMPLETE"
        )
        self.assertIn(
            "shared_direct_oracle_scan_incomplete",
            incomplete_issue["evidence"]["failures"],
        )

        incomplete_with_detail = structural_truth(failures=("direct-failed",))
        issues, _truth = invoke(
            direct_scan_cache={direct_key: incomplete_with_detail},
        )
        incomplete_issue = next(
            row for row in issues
            if row["reason_code"] == "ORACLE_STRUCTURAL_SCAN_INCOMPLETE"
        )
        self.assertIn("direct-failed", incomplete_issue["evidence"]["failures"])

        complete = structural_truth()
        direct_cache = {direct_key: complete}
        issues, truth = invoke(
            actual_type={type_row}, actual_init={init_row},
            direct_scan_cache=direct_cache,
        )
        self.assertEqual(issues, [])
        self.assertEqual(truth["clinit_classes"], ["demo/C"])

        mismatch = structural_truth(names=("demo/Other",))
        issues, _truth = invoke(direct_scan_cache={direct_key: mismatch})
        self.assertIn(
            "shared_direct_oracle_class_universe_mismatch",
            issues[0]["evidence"]["failures"],
        )

        raw_direct = {
            "artifact_sha256": artifact["sha256"], "complete": True,
            "failures": [], "edges": [],
            "structural_facts": {
                "type_edges": [list(type_row)],
                "class_init_edges": [list(init_row)],
                "clinit_classes": ["demo/C"],
                "semantic_instructions": [list(semantic_row)],
                "declared_members": [list(declared_row)],
                "class_names": ["demo/C"],
            },
        }
        raw_direct_cache = {direct_key: raw_direct}
        issues, _truth = invoke(
            actual_type={type_row}, actual_init={init_row},
            direct_scan_cache=raw_direct_cache, string_pool={},
        )
        self.assertEqual(issues, [])
        self.assertIsInstance(
            raw_direct_cache[direct_key], oracle._OracleScanEvidence,
        )

        issues, _truth = invoke(raw_scan={
            "failures": ["fallback-failed"],
        })
        self.assertIn(
            "fallback-failed", issues[0]["evidence"]["failures"],
        )

        successful_fallback = {
            "failures": [],
            "type_edges": {type_row},
            "class_init_edges": {init_row},
            "clinit_classes": {"demo/C"},
            "semantic_instructions": {semantic_row},
            "declared_members": {declared_row},
        }
        issues, _truth = invoke(
            actual_type={(
                "demo/C", "run", "()V", 10, "demo/Extra", "new",
            )},
            actual_init={(
                "demo/C", "run", "()V", 11, "demo/Extra", "invokestatic",
            )},
            raw_scan=successful_fallback,
        )
        self.assertTrue({
            "ORACLE_TYPE_EDGE_MISSING", "ORACLE_TYPE_EDGE_EXTRA",
            "ORACLE_CLASS_INIT_EDGE_MISSING",
            "ORACLE_CLASS_INIT_EDGE_EXTRA",
        }.issubset({row["reason_code"] for row in issues}))

        issues, compact_without_projection_cache = invoke(
            actual_type={type_row}, actual_init={init_row},
            raw_scan=successful_fallback, direct_scan_cache={},
            retain_truth_rows=False,
        )
        self.assertEqual(issues, [])
        self.assertEqual(
            compact_without_projection_cache["type_edges"]["record_counts"][
                "type_edges"
            ],
            1,
        )

        projection_updates = {}
        issues, compact = invoke(
            actual_type={type_row}, actual_init={init_row},
            raw_scan=successful_fallback, string_pool={},
            retain_truth_rows=False,
            validated_projection_cache=projection_updates,
            artifacts=[{**artifact, "path": ""}],
        )
        self.assertEqual(issues, [])
        self.assertTrue(projection_updates)
        self.assertEqual(compact["type_edges"]["record_counts"]["type_edges"], 1)

    def test_structural_scan_and_production_projection_boundary_matrix(self):
        complete_scan = {
            "complete": True,
            "failures": [],
            "structural_facts": {
                "class_names": ["demo/A"],
                "type_edges": [["list", "edge"], ("tuple", "edge")],
                "class_init_edges": [],
                "clinit_classes": ["demo/A"],
                "semantic_instructions": ["scalar-evidence"],
                "declared_members": [],
            },
        }
        with patch.object(
            oracle, "scan_final_artifact", return_value=complete_scan,
        ) as scan:
            projected = oracle._scan_structural_edges(
                Path("artifact.jar"),
                {"classes": {"demo/A": "demo/A.class"}},
                "javap",
            )
        self.assertEqual(projected["failures"], [])
        self.assertEqual(
            projected["type_edges"],
            {("list", "edge"), ("tuple", "edge")},
        )
        self.assertEqual(
            projected["semantic_instructions"], {"scalar-evidence"},
        )
        self.assertFalse(scan.call_args.kwargs["cache_result"])

        with patch.object(oracle, "scan_final_artifact", return_value={
            "complete": False, "structural_facts": {},
        }):
            incomplete = oracle._scan_structural_edges(
                Path("artifact.jar"), {"classes": {"demo/A": "entry"}},
                "javap",
            )
        self.assertIn("structural_fallback_scan_incomplete", incomplete["failures"])
        self.assertTrue(any(
            item.startswith("structural_fallback_class_universe_mismatch:")
            for item in incomplete["failures"]
        ))
        with patch.object(oracle, "scan_final_artifact", return_value={
            "complete": False,
            "failures": ["scanner-failed"],
            "structural_facts": {"class_names": []},
        }):
            failed = oracle._scan_structural_edges(
                Path("artifact.jar"), {"classes": {}}, "javap",
            )
        self.assertEqual(failed["failures"], ["scanner-failed"])

        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE members (
                member_identity TEXT, class_name TEXT,
                member_name TEXT, descriptor TEXT
            );
            CREATE TABLE direct_edges (
                caller_artifact_instance_identity TEXT,
                caller_member_identity TEXT,
                edge_kind TEXT, symbolic_owner TEXT,
                symbolic_name TEXT, symbolic_descriptor TEXT,
                opcode INTEGER, bytecode_offset INTEGER, edge_json TEXT
            );
        """)
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("caller", "demo/Caller", "run", "()V"),
        )

        def add(kind, payload, *, owner="demo/Target", name="call", offset=0):
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact", "caller", kind, owner, name, "()V", 184,
                    offset, json.dumps(payload),
                ),
            )

        owners = ["demo/A", "demo/B"]
        add("type", {"type_use_kind": "new"}, offset=1)
        add("type", {}, owner="demo/DefaultType", offset=2)
        add("class_init", {"trigger_kind": "invokestatic"}, offset=3)
        add("class_init", {}, owner="demo/EmptyInit", offset=4)
        add("method", {}, offset=5)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: "not-a-list",
        }, offset=6)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [],
        }, offset=7)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [""],
        }, offset=8)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [1],
        }, offset=81)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["demo/B", "demo/A"],
        }, offset=9)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "interface": False,
        }, offset=10)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "interface": True,
        }, offset=11)
        add("field", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
        }, name="value", offset=12)
        add("invokedynamic_bootstrap", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "bootstrap": {"tag": 6},
        }, offset=13)
        add("invokedynamic_bootstrap", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "bootstrap": "not-a-handle",
        }, offset=14)
        add("invokedynamic_bootstrap", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "bootstrap": {},
        }, offset=141)
        add("ldc_handle", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "tag": "invalid",
        }, offset=15)
        add("ldc_handle", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "tag": 6,
        }, offset=16)
        connection.commit()

        issues = []
        type_truth, init_truth = (
            oracle._production_structural_truth_for_artifact(
                connection, "artifact", issues,
            )
        )
        self.assertIn(
            ("demo/Caller", "run", "()V", 1, "demo/Target", "new"),
            type_truth,
        )
        self.assertIn(
            (
                "demo/Caller", "run", "()V", 2, "demo/DefaultType",
                "type_instruction",
            ),
            type_truth,
        )
        self.assertIn(
            (
                "demo/Caller", "run", "()V", 4, "demo/EmptyInit", "",
            ),
            init_truth,
        )
        reason_codes = [item["reason_code"] for item in issues]
        self.assertEqual(
            reason_codes.count("ORACLE_LOADING_CONSTRAINT_DECLARATION_INVALID"),
            5,
        )
        self.assertEqual(
            reason_codes.count("ORACLE_LOADING_CONSTRAINT_REFERENCE_KIND_INVALID"),
            3,
        )
        self.assertTrue(any(
            item[-1] == "interface_method" for item in type_truth
        ))
        self.assertTrue(any(item[-1] == "field" for item in type_truth))
        self.assertTrue(any(item[-1] == "REF_invokeStatic" for item in type_truth))

    def test_production_direct_truth_projection_boundary_matrix(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.executescript("""
            CREATE TABLE members (
                member_identity TEXT PRIMARY KEY,
                class_name TEXT NOT NULL,
                member_name TEXT NOT NULL,
                descriptor TEXT NOT NULL
            );
            CREATE TABLE direct_edges (
                caller_artifact_instance_identity TEXT NOT NULL,
                caller_member_identity TEXT NOT NULL,
                edge_kind TEXT NOT NULL,
                symbolic_owner TEXT NOT NULL,
                symbolic_name TEXT NOT NULL,
                symbolic_descriptor TEXT NOT NULL,
                opcode INTEGER,
                bytecode_offset INTEGER NOT NULL,
                edge_json TEXT NOT NULL
            );
        """)
        connection.executemany(
            "INSERT INTO members VALUES (?,?,?,?)",
            [
                ("caller", "demo/Caller", "run", "()V"),
                ("empty-caller", "", "", ""),
            ],
        )

        def add(
            kind, payload=None, *, owner="demo/Target", name="call",
            descriptor="()V", member="caller", offset=0, opcode=184,
            raw_json=None,
        ):
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact", member, kind, owner, name, descriptor,
                    opcode, offset,
                    raw_json if raw_json is not None else json.dumps(payload or {}),
                ),
            )

        owners = ["demo/A", "demo/B"]
        add("method", {"interface": False}, offset=1)
        add("method", {"interface": True}, offset=2)
        add("method", raw_json="not-json", offset=3)
        add("field", offset=4, opcode=180, descriptor="I", name="value")
        add(
            "invokedynamic_handle_method",
            {"tag": 6, "interface": False}, offset=5,
        )
        add(
            "invokedynamic_handle_field",
            {"tag": "6", "interface": False}, offset=6,
        )
        add(
            "invokedynamic_handle_custom",
            {"tag": 6, "interface": "false"}, offset=7,
        )
        add(
            "invokedynamic_bootstrap",
            {"bootstrap": {"tag": 9, "interface": True}},
            owner="demo/Bootstrap", offset=8,
        )
        add(
            "invokedynamic_bootstrap", {}, owner="demo/Bootstrap", offset=9,
        )
        add(
            "invokedynamic_bootstrap",
            {"bootstrap": {"tag": 6, "interface": False}},
            owner="java/lang/invoke/LambdaMetafactory", offset=10,
        )
        add(
            "ldc_constant_dynamic_bootstrap",
            {"tag": 1, "interface": False}, offset=11,
        )
        add("ldc_handle", {"tag": 2, "interface": True}, offset=12)
        add(
            "ldc_bootstrap_handle_argument",
            {"tag": 3, "interface": False}, offset=13,
        )
        add("ldc_bootstrap_handle_invalid", raw_json="bad", offset=14)
        add("type", {"type_use_kind": "new"}, offset=15)
        add("type", {"type_use_kind": ""}, offset=16)
        add("class_init", {"trigger_kind": "invokestatic"}, offset=17)
        add("class_init", {}, offset=18)

        # Exercise every accepted/invalid loading-constraint declaration shape.
        add("method", {"interface": False}, offset=20)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: "not-a-list",
            "interface": False,
        }, offset=21)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [],
            "interface": False,
        }, offset=22)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [1],
            "interface": False,
        }, offset=23)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [""],
            "interface": False,
        }, offset=24)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["demo/B", "demo/A"],
            "interface": False,
        }, offset=25)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "interface": False,
        }, offset=26)
        add("method", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "interface": True,
        }, offset=27)
        add("field", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
        }, name="value", descriptor="I", opcode=180, offset=28)
        add("invokedynamic_bootstrap", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "bootstrap": {"tag": 6, "interface": False},
        }, owner="demo/Bootstrap", offset=29)
        add("invokedynamic_bootstrap", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "bootstrap": {},
        }, owner="demo/Bootstrap", offset=30)
        add("ldc_handle", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "tag": 6, "interface": False,
        }, offset=31)
        add("ldc_handle", {
            oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners,
            "tag": 0, "interface": False,
        }, offset=32)
        add(
            "invokedynamic_bootstrap", {"bootstrap": {}}, owner="",
            name="", descriptor="", member="empty-caller", offset=33,
        )
        add("type", raw_json="bad-type-json", offset=34)
        add("class_init", raw_json="bad-init-json", offset=35)
        add(
            "invokedynamic_bootstrap", raw_json="bad-bootstrap-json",
            owner="demo/Bootstrap", offset=36,
        )
        add(
            "method", raw_json="bad-method-json", member="empty-caller",
            owner="", name="", descriptor="", offset=37,
        )
        connection.commit()

        direct_issues = []
        direct, dynamic = oracle._production_direct_truth_for_artifact(
            connection, "artifact", direct_issues,
        )
        self.assertTrue(any(row[-1] == "method" for row in direct))
        self.assertTrue(any(row[-1] == "interface_method" for row in direct))
        self.assertTrue(any(row[-1] == "field" for row in direct))
        self.assertTrue({
            "invokedynamic", "ldc_bootstrap_handle",
            "ldc_constant_dynamic_bootstrap", "ldc_handle",
        }.issubset({row[-2] for row in dynamic}))
        self.assertGreaterEqual(sum(
            issue["reason_code"]
            == "ORACLE_PRODUCTION_DYNAMIC_REFERENCE_KIND_INVALID"
            for issue in direct_issues
        ), 5)
        self.assertEqual(sum(
            issue["reason_code"]
            == "ORACLE_PRODUCTION_DIRECT_REFERENCE_KIND_INVALID"
            for issue in direct_issues
        ), 2)

        structural_issues = []
        direct_again, dynamic_again, type_truth, init_truth = (
            oracle._production_direct_truth_for_artifact(
                connection, "artifact", structural_issues,
                include_structural=True,
            )
        )
        self.assertEqual(direct_again, direct)
        self.assertEqual(dynamic_again, dynamic)
        self.assertTrue(any(row[-1] == "new" for row in type_truth))
        self.assertTrue(any(row[-1] == "type_instruction" for row in type_truth))
        self.assertTrue(any(row[-1] == "invokestatic" for row in init_truth))
        self.assertTrue(any(row[-1] == "" for row in init_truth))
        structural_reasons = [row["reason_code"] for row in structural_issues]
        self.assertEqual(
            structural_reasons.count(
                "ORACLE_LOADING_CONSTRAINT_DECLARATION_INVALID"
            ),
            5,
        )
        self.assertEqual(
            structural_reasons.count(
                "ORACLE_LOADING_CONSTRAINT_REFERENCE_KIND_INVALID"
            ),
            2,
        )
        self.assertTrue({
            "method", "interface_method", "field", "REF_invokeStatic",
        }.issubset({row[-1] for row in type_truth}))

    def test_validated_edge_replay_reachability_and_empty_root_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def create_database(path, rows=()):
                connection = sqlite3.connect(path)
                connection.executescript("""
                    CREATE TABLE members (
                        member_identity TEXT PRIMARY KEY,
                        class_name TEXT NOT NULL,
                        member_kind TEXT NOT NULL,
                        member_name TEXT NOT NULL,
                        descriptor TEXT NOT NULL
                    );
                    CREATE TABLE direct_edges (
                        caller_member_identity TEXT NOT NULL,
                        edge_kind TEXT NOT NULL,
                        symbolic_owner TEXT NOT NULL,
                        symbolic_name TEXT NOT NULL,
                        symbolic_descriptor TEXT NOT NULL,
                        opcode INTEGER,
                        bytecode_offset INTEGER NOT NULL,
                        edge_json TEXT NOT NULL
                    );
                """)
                connection.executemany(
                    "INSERT INTO members VALUES (?,?,?,?,?)",
                    [
                        ("entry", "demo/Entry", "method", "run", "()V"),
                        (
                            "target", "demo/Target", "method", "target",
                            "()V",
                        ),
                        ("leaf", "demo/Leaf", "method", "leaf", "()V"),
                    ],
                )
                connection.executemany(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?)",
                    rows,
                )
                connection.commit()
                connection.close()

            valid_rows = [
                (
                    "entry", "method", "demo/Target", "target", "()V",
                    182, 1, json.dumps({"interface": False}),
                ),
                (
                    "entry", "method", "demo/Missing", "missing", "()V",
                    185, 2, json.dumps({"interface": True}),
                ),
                (
                    "target", "method", "demo/Leaf", "leaf", "()V",
                    184, 3, json.dumps({"interface": False}),
                ),
                (
                    "leaf", "method", "demo/Target", "target", "()V",
                    183, 4, json.dumps({"interface": False}),
                ),
                (
                    "entry", "field", "demo/Target", "value", "I",
                    180, 5, json.dumps({}),
                ),
                (
                    "entry", "type", "demo/Target", "", "",
                    187, 6, json.dumps({"type_use_kind": "new"}),
                ),
                (
                    "target", "type", "demo/Default", "", "",
                    192, 7, json.dumps({}),
                ),
            ]
            base_database = root / "base.sqlite"
            current_database = root / "current.sqlite"
            empty_database = root / "empty.sqlite"
            create_database(base_database, valid_rows)
            create_database(current_database, valid_rows)
            create_database(empty_database)

            direct = list(oracle._iter_validated_direct_edges(base_database))
            self.assertEqual(len(direct), 5)
            self.assertTrue(any(row[-1] == "method" for row in direct))
            self.assertTrue(any(
                row[-1] == "interface_method" for row in direct
            ))
            self.assertTrue(any(row[-1] == "field" for row in direct))
            self.assertEqual(
                list(oracle._iter_validated_direct_edges(empty_database)), [],
            )

            type_edges = list(oracle._iter_validated_type_edges(base_database))
            self.assertEqual({row[-1] for row in type_edges}, {
                "new", "type_instruction",
            })
            self.assertEqual(
                list(oracle._iter_validated_type_edges(empty_database)), [],
            )

            common_all = list(oracle._iter_common_validated_direct_edges(
                base_database, current_database,
            ))
            self.assertEqual(len(common_all), 5)
            self.assertEqual(list(oracle._iter_common_validated_direct_edges(
                base_database, current_database, [],
            )), [])
            common_target = list(oracle._iter_common_validated_direct_edges(
                base_database, current_database,
                [None, "", "demo.Target", "demo/Target"],
            ))
            self.assertTrue(common_target)
            self.assertTrue(all(row[3] == "demo.Target" for row in common_target))
            self.assertEqual(list(oracle._iter_common_validated_direct_edges(
                base_database, current_database, ["absent.Owner"],
            )), [])

            invalid_payloads = (
                "not-json",
                json.dumps(["not-a-mapping"]),
                json.dumps({}),
            )
            for index, payload in enumerate(invalid_payloads):
                invalid_database = root / f"invalid-{index}.sqlite"
                create_database(invalid_database, [(
                    "entry", "method", "demo/Target", "target", "()V",
                    182, index, payload,
                )])
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    list(oracle._iter_validated_direct_edges(invalid_database))
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_VALIDATED_DIRECT_EDGE_REPLAY_INVALID",
                )

            observations = {
                "demo/Target": {
                    "status": "definition_ready",
                    "members": ["method|target|()V|1"],
                    "super_name": "java/lang/Object",
                    "interfaces": [],
                },
                "demo/Leaf": {
                    "status": "definition_ready",
                    "members": ["method|leaf|()V|1"],
                    "super_name": "java/lang/Object",
                    "interfaces": [],
                },
                "java/lang/Object": {
                    "status": "definition_ready", "members": [],
                    "super_name": "", "interfaces": [],
                },
            }
            entrypoint = {("demo.Entry", "run", "()V")}
            reached = oracle._reachable_validated_current_methods(
                current_database, entrypoint, observations, {},
            )
            self.assertEqual(reached, {
                ("demo.Entry", "run", "()V"),
                ("demo.Target", "target", "()V"),
                ("demo.Leaf", "leaf", "()V"),
            })
            self.assertEqual(
                oracle._reachable_validated_current_methods(
                    current_database, set(), observations, {},
                ),
                set(),
            )

        self.assertEqual(oracle._resolution_affected_owners({}), set())
        stable = {
            "status": "definition_ready", "modifiers": 0,
            "super_name": "", "interfaces": [], "members": [],
            "javap_declared_members": [],
        }
        rich = {
            "status": "definition_ready", "modifiers": 1,
            "super_name": "demo/Parent", "interfaces": ["demo/Api"],
            "members": ["method|rich|()V|1"],
            "javap_declared_members": ["field|value|I|1"],
        }
        base = {
            "demo/Stable": dict(stable),
            "demo/Rich": dict(rich),
            "demo/Changed": dict(stable),
            "demo/Child": {**stable, "super_name": "demo/Changed"},
            "demo/Grandchild": {**stable, "super_name": "demo/Child"},
            "demo/AlreadyChanged": {
                **stable, "super_name": "demo/Changed", "modifiers": 2,
            },
            "demo/OnlyBase": dict(stable),
        }
        current = {
            "demo/Stable": dict(stable),
            "demo/Rich": dict(rich),
            "demo/Changed": {**stable, "modifiers": 4},
            "demo/Child": {**stable, "super_name": "demo/Changed"},
            "demo/Grandchild": {**stable, "super_name": "demo/Child"},
            "demo/AlreadyChanged": {
                **stable, "super_name": "demo/Changed", "modifiers": 8,
            },
            "demo/OnlyCurrent": dict(stable),
        }
        affected = oracle._resolution_affected_owners({
            "base": base, "current": current,
        })
        self.assertTrue({
            "demo/Changed", "demo/Child", "demo/Grandchild",
            "demo/AlreadyChanged", "demo/OnlyBase", "demo/OnlyCurrent",
        }.issubset(affected))
        self.assertNotIn("demo/Stable", affected)
        self.assertNotIn("demo/Rich", affected)

        empty_truth = {
            "exact_entrypoint_count": 0,
            "oracle_candidate_entrypoint_count": 0,
            "production_candidate_entrypoint_count": 0,
            "candidate_activation_gaps": [],
        }
        self.assertTrue(oracle._validated_empty_entrypoint_set(
            {"record_count": 0}, [], empty_truth,
        ))
        self.assertTrue(oracle._validated_empty_entrypoint_set(
            {"records": []}, [], empty_truth,
        ))
        false_cases = (
            ({"record_count": 0}, [], None),
            ({"record_count": 0}, [{"reason_code": "gap"}], empty_truth),
            ({"record_count": 1}, [], empty_truth),
            ({"records": ["root"]}, [], empty_truth),
            ({"record_count": 0, "coverage_gaps": ["gap"]}, [], empty_truth),
            ({"record_count": 0}, [], {
                **empty_truth, "exact_entrypoint_count": 1,
            }),
            ({"record_count": 0}, [], {
                **empty_truth, "oracle_candidate_entrypoint_count": 1,
            }),
            ({"record_count": 0}, [], {
                **empty_truth, "production_candidate_entrypoint_count": 1,
            }),
            ({"record_count": 0}, [], {
                **empty_truth, "candidate_activation_gaps": ["gap"],
            }),
        )
        for payload, issues, truth in false_cases:
            self.assertFalse(oracle._validated_empty_entrypoint_set(
                payload, issues, truth,
            ))

    def test_descriptor_member_resolution_annotation_and_subtype_matrix(self):
        for descriptor in (None, "I", "(", "([", "(Ldemo/Type"):
            self.assertIsNone(oracle._descriptor_parameters(descriptor))
        self.assertEqual(oracle._descriptor_parameters("()V"), ())
        self.assertEqual(
            oracle._descriptor_parameters("([I[[Ljava/lang/String;Z)V"),
            ("[I", "[[Ljava/lang/String;", "Z"),
        )
        self.assertEqual(oracle._descriptor_return_class(None), "")
        self.assertEqual(oracle._descriptor_return_class("()I"), "")
        self.assertEqual(
            oracle._descriptor_return_class("()Ldemo/Result;"), "demo/Result",
        )
        self.assertEqual(oracle._oracle_type_provider_owner("demo/Type"), "demo/Type")
        self.assertEqual(
            oracle._oracle_type_provider_owner("[[Ldemo/Type;"), "demo/Type",
        )
        self.assertEqual(oracle._oracle_type_provider_owner("[[I"), "")

        observations = {
            "demo/Child": {
                "status": "definition_ready",
                "members": ["method|own|()V|1"],
                "javap_declared_members": [
                    "method|own|()V|129", "field|field|I|1",
                ],
                "super_name": "demo/Base",
                "interfaces": ["demo/Api", ""],
            },
            "demo/Base": {
                "status": "definition_ready",
                "members": ["method|base|()V|1", "field|shared|I|1"],
                "super_name": "java/lang/Object",
                "interfaces": [],
            },
            "demo/Api": {
                "status": "definition_ready", "modifiers": 0x0200,
                "members": ["method|api|()V|1"],
                "super_name": "java/lang/Object", "interfaces": [],
            },
            "demo/SubApi": {
                "status": "definition_ready", "modifiers": 0x0200,
                "members": [], "super_name": "java/lang/Object",
                "interfaces": ["demo/Api"],
            },
            "java/lang/Object": {
                "status": "definition_ready",
                "members": [
                    "method|objectMethod|()V|1",
                    "method|staticObject|()V|9",
                    "method|privateObject|()V|2",
                ],
                "interfaces": [], "super_name": "",
            },
            "demo/Partial": {
                "status": "definition_failed", "failure_phase": "member_linkage",
                "javap_declared_members": ["method|partial|()V|1"],
            },
            "demo/Failed": {
                "status": "definition_failed", "failure_phase": "class_linkage",
            },
        }
        declared = oracle._declared_members(observations["demo/Child"])
        self.assertEqual(len([row for row in declared if row[1] == "own"]), 1)
        self.assertFalse(oracle._oracle_class_load_ready(None))
        self.assertTrue(oracle._oracle_class_load_ready(observations["demo/Child"]))
        self.assertTrue(oracle._oracle_class_load_ready(observations["demo/Partial"]))
        self.assertFalse(oracle._oracle_class_load_ready(observations["demo/Failed"]))

        cache = {}
        self.assertEqual(
            oracle._resolve_member(
                observations, "demo/Child", "method", "own", "()V",
                declared_members_cache=cache,
            )[0],
            "demo/Child",
        )
        self.assertEqual(
            oracle._resolve_member(
                observations, "demo/Child", "method", "base", "()V",
                declared_members_cache=cache,
            )[0],
            "demo/Base",
        )
        self.assertEqual(
            oracle._resolve_member(
                observations, "demo/Child", "field", "shared", "I",
                declared_members_cache=cache,
            )[0],
            "demo/Base",
        )
        self.assertEqual(
            oracle._resolve_member(
                observations, "demo/Api", "method", "objectMethod", "()V",
            )[0],
            "java/lang/Object",
        )
        for name in ("staticObject", "privateObject", "missing"):
            self.assertIsNone(oracle._resolve_member(
                observations, "demo/Api", "method", name, "()V",
            ))
        self.assertEqual(
            oracle._resolve_member(
                observations, "demo/SubApi", "method", "api", "()V",
            )[0],
            "demo/Api",
        )
        self.assertIsNone(oracle._resolve_member(
            observations, "demo/Child", "method", "<init>", "()V",
        ))
        self.assertIsNone(oracle._resolve_member(
            observations, "demo/Failed", "method", "x", "()V",
        ))
        self.assertIsNone(oracle._resolve_member(
            observations, "demo/Child", "method", "x", "()V",
            frozenset({"demo/Child"}),
        ))

        self.assertTrue(oracle._is_subtype(observations, "demo/Child", "demo/Child"))
        self.assertTrue(oracle._is_subtype(observations, "demo/Child", "demo/Api"))
        self.assertFalse(oracle._is_subtype(observations, "demo/Child", "demo/Other"))
        self.assertFalse(oracle._is_subtype(
            observations, "demo/Child", "demo/Other", frozenset({"demo/Child"}),
        ))

        observations["meta/One"] = {
            "class_annotations": ["Lmeta/Two;", ""]
        }
        observations["meta/Two"] = {
            "class_annotations": ["Lmeta/One;", "Ltarget/Marker;"]
        }
        closure = oracle._oracle_annotation_closure(
            observations, ["", "invalid", "Lbroken", "broken;", "Lmeta/One;"],
        )
        self.assertIn("Ltarget/Marker;", closure)
        self.assertIn("invalid", closure)
        member_annotations = oracle._oracle_member_annotations({
            "member_annotations": [
                "run|()V|LOne;", "run|()V|LTwo;",
            ],
        })
        self.assertEqual(member_annotations[("run", "()V")], {"LOne;", "LTwo;"})
        self.assertEqual(oracle._oracle_member_annotations({}), {})

        class_values = oracle._oracle_annotation_values([
            "bad", "LAnn;|name|one", "LAnn;|name|two",
        ])
        self.assertEqual(class_values["LAnn;"]["name"], {"one", "two"})
        self.assertEqual(oracle._oracle_annotation_values(None), {})
        member_values = oracle._oracle_annotation_values([
            "bad", "run|()V|LAnn;|name|one",
        ], member_rows=True)
        self.assertEqual(
            member_values[("run", "()V", "LAnn;")]["name"], {"one"},
        )

    def test_closed_world_decision_alias_boundary_matrix(self):
        with patch.object(
            oracle, "_iter_sidecar_object_rows", return_value=iter(()),
        ):
            self.assertEqual(
                oracle._closed_world_decision_aliases(Path("generation")),
                (set(), {}),
            )

        decisions = [
            {
                "fact_scope": {
                    "member_change_kind": "removed",
                    "member_kind": "method",
                    "class_name": "demo.Target",
                    "member_name": "run", "descriptor": "()V",
                },
                "dependency_artifacts": [
                    {"side": "base"}, {"side": "current"}, {},
                ],
                "evidence": {
                    "current_unresolved_direct_edge_identities": [
                        "edge-method", "",
                    ],
                },
            },
            {
                "fact_scope": {
                    "member_change_kind": "removed",
                    "member_kind": "field",
                    "class_name": "", "member_name": "",
                    "descriptor": "",
                },
                "dependency_artifacts": [
                    {"side": "base"}, {"side": "current"},
                ],
                "evidence": {
                    "current_unresolved_direct_edge_identities": [],
                },
            },
            {
                "fact_scope": {
                    "member_change_kind": "removed",
                    "member_kind": "method",
                    "class_name": "demo/Unpaired",
                    "member_name": "run", "descriptor": "()V",
                },
                "dependency_artifacts": [{"side": "base"}],
                "evidence": {},
            },
            {
                "fact_scope": {
                    "member_change_kind": "changed",
                    "member_kind": "method",
                    "class_name": "demo/Changed",
                    "member_name": "run", "descriptor": "()V",
                },
                "evidence": {
                    "current_unresolved_direct_edge_identities": ["edge-change"],
                },
            },
            {
                "fact_scope": {"member_change_kind": "removed"},
                "fact_kind": "class",
                "dependency_artifacts": [],
            },
            {
                "fact_scope": {},
                "fact_kind": "field",
                "evidence": {
                    "current_unresolved_direct_edge_identities": ["edge-fallback"],
                },
            },
            {
                "fact_scope": {"member_kind": ""},
                "fact_kind": "method",
                "evidence": None,
            },
            {},
        ]
        with patch.object(
            oracle, "_iter_sidecar_object_rows", return_value=iter(decisions),
        ):
            paired, aliases = oracle._closed_world_decision_aliases(
                Path("generation"),
            )
        self.assertEqual(len(paired), 2)
        self.assertEqual(set(aliases), {
            "", "edge-method", "edge-change", "edge-fallback",
        })
        self.assertEqual(len(aliases["edge-method"]), 1)
        self.assertEqual(aliases[""], aliases["edge-method"])
        self.assertNotEqual(aliases["edge-change"], aliases["edge-method"])

    def test_closed_world_graph_materialization_boundary_matrix(self):
        def edge(
            identity, kind, *, caller="caller/root", owner="demo/Target",
            name="run", descriptor="()V",
        ):
            return {
                "direct_edge_identity": identity,
                "caller_member_identity": caller,
                "edge_kind": kind,
                "symbolic_owner": owner,
                "symbolic_name": name,
                "symbolic_descriptor": descriptor,
            }

        edges = [
            edge("resolved-dispatch", "method"),
            edge("resolved-possible", "method"),
            edge("resolved-partial", "method"),
            edge("resolved-fallback", "field", name="value", descriptor="I"),
            edge("resolved-empty", "method"),
            edge(
                "unresolved-member", "field", owner="demo/Missing",
                name="value", descriptor="I",
            ),
            edge(
                "unresolved-paired", "method", owner="demo/Paired",
                name="gone",
            ),
            edge(
                "unresolved-paired-other", "method", owner="demo/Paired",
                name="gone",
            ),
            edge(
                "unresolved-nonpaired", "method", owner="demo/Other",
                name="gone",
            ),
            edge("unresolved-empty", "method", owner="demo/Empty"),
            edge("dynamic-bootstrap", "invokedynamic_bootstrap"),
            edge("dynamic-handle", "invokedynamic_handle_method"),
            edge("ldc-dynamic", "ldc_constant_dynamic_bootstrap"),
            edge("unsupported", "type"),
            edge("ldc-handle", "ldc_handle"),
            edge("empty-kind", ""),
            edge("type-good", "type", owner="demo/Type", descriptor="Ldemo/Type;"),
            edge("type-array", "type", owner="[Ldemo/Type;", descriptor="[Ldemo/Type;"),
            edge("type-fail", "type"),
            edge("init-good", "class_init", owner="demo/Init"),
            edge("init-empty", "class_init", owner="demo/EmptyInit"),
            edge("init-fail", "class_init", owner="demo/FailInit"),
        ]
        reconciliations = {
            "member_resolution": [
                {
                    "direct_edge_identity": "resolved-dispatch",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "declared/ignored",
                },
                {
                    "direct_edge_identity": "resolved-possible",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "declared/possible",
                },
                {
                    "direct_edge_identity": "resolved-partial",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "declared/partial",
                },
                {
                    "direct_edge_identity": "resolved-fallback",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "declared/field",
                },
                {
                    "direct_edge_identity": "resolved-empty",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "",
                },
                {
                    "direct_edge_identity": "unresolved-member",
                    "member_resolution_status": "no_such_member",
                },
                {
                    "direct_edge_identity": "unresolved-paired",
                    "member_resolution_status": "no_class_definition",
                },
                {
                    "direct_edge_identity": "unresolved-paired-other",
                    "member_resolution_status": "ambiguous",
                },
                {
                    "direct_edge_identity": "unresolved-nonpaired",
                    "member_resolution_status": "class_definition_failed",
                },
                {
                    "direct_edge_identity": "unresolved-empty",
                    "member_resolution_status": "",
                },
                {
                    "direct_edge_identity": "dynamic-bootstrap",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "bootstrap/target",
                },
                {
                    "direct_edge_identity": "dynamic-handle",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "handle/target",
                },
                {
                    "direct_edge_identity": "ldc-dynamic",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "constant/target",
                },
                {"direct_edge_identity": "unsupported"},
                {"direct_edge_identity": "ldc-handle"},
                {"direct_edge_identity": "empty-kind"},
                {"direct_edge_identity": "missing-edge"},
            ],
            "dispatch_resolution": [
                {
                    "direct_edge_identity": "resolved-dispatch",
                    "dispatch_status": "exact",
                    "implementation_target_identities": ["impl/exact"],
                },
                {
                    "direct_edge_identity": "resolved-possible",
                    "dispatch_status": "possible",
                    "implementation_target_identities": ["impl/possible"],
                },
                {
                    "direct_edge_identity": "resolved-partial",
                    "dispatch_status": "partial_possible_set",
                    "implementation_target_identities": ["impl/partial"],
                },
                {
                    "direct_edge_identity": "dynamic-bootstrap",
                    "dispatch_status": "exact",
                    "implementation_target_identities": ["bootstrap/target"],
                },
                {
                    "direct_edge_identity": "dynamic-handle",
                    "implementation_target_identities": ["handle/target"],
                },
                {
                    "direct_edge_identity": "ldc-dynamic",
                    "implementation_target_identities": ["constant/target"],
                },
            ],
            "type_resolution": [
                {
                    "direct_edge_identity": "type-good",
                    "type_resolution_status": "resolved",
                },
                {
                    "direct_edge_identity": "type-array",
                    "type_resolution_status": "primitive_or_array_type",
                },
                {
                    "direct_edge_identity": "type-fail",
                    "type_resolution_status": "failed",
                },
                {
                    "direct_edge_identity": "missing-type",
                    "type_resolution_status": "resolved",
                },
            ],
            "class_initialization_resolution": [
                {
                    "direct_edge_identity": "init-good",
                    "class_initialization_status": "resolved",
                    "initializer_target_identities": ["init/target", ""],
                },
                {
                    "direct_edge_identity": "init-empty",
                    "class_initialization_status": "resolved",
                    "initializer_target_identities": [],
                },
                {
                    "direct_edge_identity": "init-fail",
                    "class_initialization_status": "failed",
                },
                {
                    "direct_edge_identity": "missing-init",
                    "class_initialization_status": "resolved",
                    "initializer_target_identities": ["missing/target"],
                },
            ],
            "linkage_resolution": [{
                "direct_edge_identity": "dynamic-bootstrap",
                "linkage_status": "linked",
            }],
        }
        decisions = [{
            "fact_scope": {
                "member_change_kind": "removed",
                "member_kind": "method",
                "class_name": "demo.Paired",
                "member_name": "gone", "descriptor": "()V",
            },
            "dependency_artifacts": [
                {"side": "base"}, {"side": "current"},
            ],
            "evidence": {
                "current_unresolved_direct_edge_identities": [
                    "unresolved-paired", "unresolved-paired-other",
                ],
            },
        }]

        def invoke(generation, *, rich=False, inline_payload=None):
            connection = MagicMock()
            rows = edges if rich else []
            domains = reconciliations if rich else {}
            semantic_payload = {"rows": [
                {
                    "caller_member_identity": "semantic/caller",
                    "target_member_identity": "semantic/exact",
                    "path_certainty": "exact",
                    "semantic_edge_identity": "semantic-exact",
                },
                {
                    "caller_member_identity": "semantic/caller",
                    "target_member_identity": "semantic/possible",
                    "path_certainty": "unknown",
                    "semantic_edge_identity": "",
                },
                {
                    "caller_member_identity": "",
                    "target_member_identity": "semantic/no-caller",
                },
                {
                    "caller_member_identity": "semantic/no-target",
                    "target_member_identity": "",
                },
            ]} if rich else {}
            with (
                patch.object(
                    oracle, "_open_immutable_sqlite", return_value=connection,
                ),
                patch.object(oracle, "_rows", return_value=iter(rows)),
                patch.object(
                    oracle, "_reconciliation",
                    side_effect=lambda _connection, kind: iter(
                        domains.get(kind, [])
                    ),
                ),
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    return_value=iter(decisions if rich else ()),
                ),
                patch.object(
                    oracle, "_load_json",
                    return_value=inline_payload or {},
                ),
            ):
                result = oracle._load_closed_world_graph(
                    generation, semantic_payload,
                )
            connection.close.assert_called_once()
            return result

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.mkdir()
            self.assertEqual(invoke(empty), ({}, {}, {}, {}))

            inline_empty = root / "inline-empty"
            inline_empty.mkdir()
            (inline_empty / "binary_inline_overlay.json").write_text(
                "{}", encoding="utf-8",
            )
            self.assertEqual(invoke(
                inline_empty, inline_payload={"rows": []},
            ), ({}, {}, {}, {}))

            rich = root / "rich"
            rich.mkdir()
            (rich / "binary_inline_overlay.json").write_text(
                "{}", encoding="utf-8",
            )
            inline_rows = {"rows": [
                {"consumption_state": "unchanged"},
                {
                    "consumption_state": "changed_with_source",
                    "binding_certainty": "unknown",
                },
                {
                    "consumption_state": "changed_with_source",
                    "binding_certainty": "proven",
                    "consumer_member_identity": "inline/caller",
                    "changed_field_member_identity": "inline/exact",
                    "inline_overlay_identity": "inline-exact",
                },
                {
                    "consumption_state": "changed_with_source",
                    "binding_certainty": "possible",
                    "consumer_member_identity": "inline/caller",
                    "changed_field_member_identity": "inline/possible",
                    "inline_overlay_identity": "",
                },
                {
                    "consumption_state": "changed_with_source",
                    "binding_certainty": "proven",
                    "consumer_member_identity": "",
                    "changed_field_member_identity": "inline/no-caller",
                },
                {
                    "consumption_state": "changed_with_source",
                    "binding_certainty": "possible",
                    "consumer_member_identity": "inline/no-target",
                    "changed_field_member_identity": "",
                },
            ]}
            transitions, relations, resolutions, linkages = invoke(
                rich, rich=True, inline_payload=inline_rows,
            )

        caller_rows = transitions["caller/root"]
        self.assertTrue(any(
            target == "impl/exact" and certainty == "exact"
            for target, certainty, _evidence in caller_rows
        ))
        self.assertTrue(any(
            target == "impl/possible" and certainty == "possible"
            for target, certainty, _evidence in caller_rows
        ))
        self.assertTrue(any(
            target == "bootstrap/target" and certainty == "possible"
            for target, certainty, _evidence in caller_rows
        ))
        self.assertIn("semantic/caller", transitions)
        self.assertIn("inline/caller", transitions)
        self.assertIn("semantic-exact", relations)
        self.assertIn("dynamic-bootstrap", linkages)
        self.assertIn("resolved-dispatch", resolutions)
        self.assertNotIn("", transitions)

    def test_runtime_class_observation_execution_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jdk = root / "jdk"
            jdk.mkdir()
            run_number = 0

            def success(stdout):
                return SimpleNamespace(
                    succeeded=True, stdout=stdout, failure=None,
                )

            def failure(payload, retryable):
                problem = SimpleNamespace(
                    retryable=retryable,
                    to_mapping=lambda: dict(payload),
                )
                return SimpleNamespace(
                    succeeded=False, stdout="", failure=problem,
                )

            def rows_for_requested(command, *, dependencies=False):
                requested = Path(command[-1]).read_text(
                    encoding="utf-8"
                ).splitlines()
                rows = []
                for class_name in requested:
                    row = {
                        "class_name": class_name.replace(".", "/"),
                        "status": "definition_ready",
                    }
                    if dependencies and class_name == "demo.A":
                        row.update({
                            "super_name": "dep/Super",
                            "interfaces": [
                                "dep/Interface", "dep/Observed", "demo/B", "",
                            ],
                        })
                    rows.append(row)
                if dependencies and "demo.A" in requested:
                    rows.append({
                        "class_name": "dep/Observed",
                        "status": "definition_failed",
                    })
                return success("\n".join(
                    json.dumps(row) for row in rows
                ))

            def run(
                initial, execute, *, workers=1, batch_size=32,
                max_attempts=1, budget=None, label="", string_pool=None,
                java8=False, time_values=None,
            ):
                nonlocal run_number
                run_number += 1
                work = root / f"work-{run_number}"
                work.mkdir()
                rt_jar = jdk / "jre" / "lib" / "rt.jar"
                if java8:
                    rt_jar.parent.mkdir(parents=True, exist_ok=True)
                    rt_jar.write_bytes(b"runtime")
                elif rt_jar.exists():
                    rt_jar.unlink()
                patches = [
                    patch.object(
                        oracle, "short_temporary_directory",
                        side_effect=lambda *args, **kwargs: (
                            contextlib.nullcontext(str(work))
                        ),
                    ),
                    patch.object(oracle, "_compile_oracle", return_value="helper"),
                    patch.object(oracle, "jdk_tool_path", return_value="java"),
                    patch.object(
                        oracle, "_runtime_oracle_execution_shape",
                        return_value=(batch_size, workers, 1234),
                    ),
                    patch.object(oracle, "execute_binary_tool", side_effect=execute),
                    patch.object(
                        oracle, "tool_failure_is_retryable",
                        side_effect=lambda item: bool(item.retryable),
                    ),
                    patch.object(
                        oracle, "MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE", 1,
                    ),
                ]
                if time_values is not None:
                    patches.append(patch.object(
                        oracle.time, "perf_counter", side_effect=time_values,
                    ))
                with contextlib.ExitStack() as stack:
                    for active_patch in patches:
                        stack.enter_context(active_patch)
                    progress = []
                    value = oracle._observe_classes(
                        jdk, [{"path": "artifact.jar"}], initial,
                        phase_time_budget_seconds=budget,
                        max_attempts=max_attempts,
                        progress_callback=lambda *event: progress.append(event),
                        progress_label=label,
                        string_pool=string_pool,
                    )
                return value, progress

            (observed, helper), progress = run(
                ["demo/A", "demo/B", "", None],
                lambda command, **kwargs: rows_for_requested(
                    command, dependencies=True,
                ),
                budget=30, string_pool={}, java8=True,
            )
            self.assertEqual(helper, "helper")
            self.assertTrue({
                "demo/A", "demo/B", "dep/Observed", "dep/Super",
                "dep/Interface",
            }.issubset(observed))
            self.assertTrue(progress)

            (empty, _helper), empty_progress = run(
                [], lambda *args, **kwargs: success(""), label="current",
                budget=0,
            )
            self.assertEqual(empty, {})
            self.assertEqual(empty_progress, [])

            (concurrent, _helper), concurrent_progress = run(
                [f"demo/C{index}" for index in range(5)],
                lambda command, **kwargs: rows_for_requested(command),
                workers=2, batch_size=1, label="current",
            )
            self.assertEqual(len(concurrent), 5)
            self.assertTrue(concurrent_progress)

            first_failure = failure({"reason_code": "TRANSIENT"}, True)
            retried, _progress = run(
                ["demo/Retry"],
                MagicMock(side_effect=[
                    first_failure,
                    success(json.dumps({
                        "class_name": "demo/Retry",
                        "status": "definition_failed",
                    })),
                ]),
                max_attempts=2,
            )
            self.assertIn("demo/Retry", retried[0])

            failure_cases = (
                (
                    MagicMock(return_value=failure({}, False)), 2,
                    "BINARY_ORACLE_EXECUTION_FAILED",
                ),
                (
                    MagicMock(return_value=failure(
                        {"reason_code": "TRANSIENT"}, True,
                    )), 2, "BINARY_ORACLE_EXECUTION_RETRY_EXHAUSTED",
                ),
                (
                    MagicMock(return_value=failure(
                        {"reason_code": "TRANSIENT"}, True,
                    )), 1, "TRANSIENT",
                ),
                (
                    MagicMock(return_value=success("not-json")), 1,
                    "BINARY_ORACLE_OUTPUT_INVALID",
                ),
                (
                    MagicMock(return_value=success(json.dumps({}))), 1,
                    "BINARY_ORACLE_OUTPUT_INCOMPLETE",
                ),
            )
            for execute, attempts, reason_code in failure_cases:
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    run(["demo/Failure"], execute, max_attempts=attempts)
                self.assertEqual(raised.exception.reason_code, reason_code)

            never_execute = MagicMock()
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                run(
                    ["demo/Timeout"], never_execute, budget=0.5,
                    time_values=[0.0, 1.0],
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ORACLE_RUNTIME_PHASE_TIME_BUDGET_EXCEEDED",
            )
            never_execute.assert_not_called()

    def test_runtime_semantic_overlay_empty_contract_is_an_exact_match(self):
        with tempfile.TemporaryDirectory() as temp_text, patch.object(
            oracle, "_iter_sidecar_object_rows", return_value=iter(()),
        ):
            issues, truth = oracle._validate_runtime_semantic_overlay(
                Path(temp_text), {}, [{"path": ""}, {}], {}, {}, [], [], [],
            )

        self.assertEqual(issues, [])
        self.assertEqual(truth["validated_exact_edges"], [])
        self.assertEqual(truth["observed_production_exact_edges"], [])
        self.assertEqual(truth["oracle_candidate_edge_count"], 0)
        self.assertEqual(truth["production_candidate_edge_count"], 0)
        self.assertTrue(truth["exact_edge_set_matches"])

    def test_validate_generation_empty_but_valid_orchestration_contract(self):
        digest = "a" * 64
        platform = "b" * 64
        tool_policy = {
            "javap_time_budget_seconds": 1,
            "compile_timeout_seconds": 1,
            "runtime_timeout_seconds": 1,
            "runtime_phase_time_budget_seconds": 1,
            "max_attempts": 1,
        }

        class Connection:
            row_factory = None

            def close(self):
                pass

        def finalized(
            _generation, _manifest, truth_parts, helper_identities, issues,
            _progress_callback,
        ):
            return {
                "status": "failed" if issues else "passed",
                "issues": list(issues),
                "truth_parts": truth_parts,
                "helper_identities": dict(helper_identities),
            }

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            manifest = {
                "result_generation_identity": generation.name,
                "policy_identities": {
                    "base_jdk_preflight_identity": digest,
                    "current_jdk_preflight_identity": digest,
                    "base_platform_image": platform,
                    "current_platform_image": platform,
                },
                "sidecar_content_identities": {},
            }
            scan_cache = MagicMock()
            structural_cache = MagicMock()
            patches = (
                patch.object(
                    oracle, "system_available_memory_bytes",
                    side_effect=RuntimeError("probe unavailable"),
                ),
                patch.object(
                    oracle, "validate_oracle_tool_execution_policy",
                    return_value=tool_policy,
                ),
                patch.object(
                    oracle, "preflight_jdk_home",
                    return_value={"jdk_preflight_identity": digest},
                ),
                patch.object(oracle, "_load_json", return_value=manifest),
                patch.object(
                    oracle, "_expected_result_generation_identity",
                    return_value=generation.name,
                ),
                patch.object(
                    oracle, "_generation_sidecar_declaration_issues",
                    return_value=[],
                ),
                patch.object(oracle, "_artifact_configs", return_value=[]),
                patch.object(
                    oracle, "_expected_runtime_profile_identity",
                    return_value="runtime-profile",
                ),
                patch.object(
                    oracle, "_attach_expected_artifact_instances",
                ),
                patch.object(oracle, "_release_major", return_value=17),
                patch.object(
                    oracle, "_archive_inventory",
                    return_value={"classes": {}, "failures": []},
                ),
                patch.object(
                    oracle, "_validate_pairings",
                    return_value=([], {"pairings": {"status": "passed"}}),
                ),
                patch.object(
                    oracle, "_validate_source_attestation",
                    return_value=([], {"status": "passed"}),
                ),
                patch.object(
                    oracle, "_OracleScanSpoolCache",
                    return_value=scan_cache,
                ),
                patch.object(
                    oracle, "_ProductionStructuralSpoolCache",
                    return_value=structural_cache,
                ),
                patch.object(
                    oracle, "_open_immutable_sqlite",
                    side_effect=lambda _path: Connection(),
                ),
                patch.object(oracle, "jdk_tool_path", return_value="javap"),
                patch.object(
                    oracle, "_validate_direct_edges",
                    return_value=([], {"discovery_classes": []}),
                ),
                patch.object(
                    oracle, "_validate_structural_edges",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "canonical_identity_streaming",
                    return_value="shared-database",
                ),
                patch.object(
                    oracle, "_sqlite_logical_contents_equal",
                    return_value=False,
                ),
                patch.object(
                    oracle, "_oracle_artifacts_for_entrypoint_realms",
                    return_value=[],
                ),
                patch.object(
                    oracle, "_observe_classes",
                    return_value=({}, "helper"),
                ),
                patch.object(
                    oracle,
                    "_attach_provider_declared_members_from_scan_cache",
                ),
                patch.object(
                    oracle, "_compact_observations",
                    side_effect=lambda observations, *_args, **_kwargs: (
                        observations
                    ),
                ),
                patch.object(
                    oracle, "_validate_runtime_outcomes",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_validate_resource_selections",
                    return_value=([], {}),
                ),
                patch.object(oracle, "_prime_large_sidecar_fields"),
                patch.object(
                    oracle, "_validate_cross_version_semantics",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_SpoolStructuralInstructionSource",
                    return_value=(),
                ),
                patch.object(
                    oracle, "_iter_validated_direct_edges",
                    side_effect=lambda *_args, **_kwargs: iter(()),
                ),
                patch.object(
                    oracle, "_validate_entrypoint_discovery",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_validate_runtime_semantic_overlay",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_validate_closed_world_results",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_final_artifact_stability",
                    return_value=([], {}),
                ),
                patch.object(
                    oracle, "_finalize_validation_result",
                    side_effect=finalized,
                ),
            )
            with contextlib.ExitStack() as stack:
                for active_patch in patches:
                    stack.enter_context(active_patch)
                result = oracle.validate_generation(
                    {
                        "base": {"jdk_preflight_identity": digest},
                        "current": {"jdk_preflight_identity": digest},
                    },
                    generation,
                    progress_callback=lambda *_args: None,
                )

                oracle._expected_result_generation_identity.return_value = (
                    "different-generation"
                )
                generation_mismatch = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._expected_result_generation_identity.return_value = (
                    generation.name
                )

                class PolicyChanges(dict):
                    def __init__(self, value):
                        super().__init__(value)
                        self.policy_reads = 0

                    def get(self, key, default=None):
                        if key == "policy_identities":
                            self.policy_reads += 1
                            if self.policy_reads > 1:
                                return []
                        return super().get(key, default)

                oracle._load_json.return_value = PolicyChanges(manifest)
                profile_binding_failure = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._load_json.return_value = manifest

                artifact_path = generation / "artifact.jar"
                artifact_path.write_bytes(b"artifact")
                bad_artifact = {
                    "path": str(artifact_path), "sha256": "0" * 64,
                }
                oracle._artifact_configs.side_effect = (
                    [bad_artifact], [bad_artifact],
                )
                with self.assertRaises(
                    oracle.BinaryValidationError
                ) as changed:
                    oracle.validate_generation(
                        {}, generation,
                        progress_callback=lambda *_args: None,
                    )
                oracle._artifact_configs.side_effect = None
                oracle._artifact_configs.return_value = []

                good_artifact = {
                    "path": str(artifact_path),
                    "sha256": hashlib.sha256(b"artifact").hexdigest(),
                }
                oracle._artifact_configs.side_effect = (
                    [good_artifact], [good_artifact],
                )
                oracle._archive_inventory.return_value = {
                    "classes": {}, "failures": ["invalid archive entry"],
                }
                inventory_failure = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._artifact_configs.side_effect = None
                oracle._artifact_configs.return_value = []
                oracle._archive_inventory.return_value = {
                    "classes": {}, "failures": [],
                }

                base_database = generation / "base_binary_facts.sqlite"
                current_database = generation / "current_binary_facts.sqlite"
                base_database.write_bytes(b"base database")
                current_database.write_bytes(b"current database")
                database_manifest = {
                    **manifest,
                    "sidecar_content_identities": {
                        base_database.name: hashlib.sha256(
                            b"base database"
                        ).hexdigest(),
                        current_database.name: hashlib.sha256(
                            b"current database"
                        ).hexdigest(),
                    },
                }
                oracle._load_json.return_value = database_manifest
                unequal_databases = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )

                oracle._load_json.return_value = manifest
                oracle._validate_direct_edges.return_value = ([{
                    "reason_code": "DIRECT_EDGE_MISMATCH",
                }], {"discovery_classes": []})
                foundational_failure = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._validate_direct_edges.return_value = (
                    [], {"discovery_classes": []},
                )

                def clear_current_truth(
                    _generation, _config, truth_parts, _observations,
                ):
                    truth_parts["current"] = {}
                    return [], {}

                oracle._validate_cross_version_semantics.side_effect = (
                    clear_current_truth
                )
                empty_current_truth = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._validate_cross_version_semantics.side_effect = None
                oracle._validate_cross_version_semantics.return_value = (
                    [], {},
                )

                oracle._validate_runtime_outcomes.return_value = ([{
                    "reason_code": "RUNTIME_MISMATCH",
                }], {})
                runtime_failure = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._validate_runtime_outcomes.return_value = ([], {})

                oracle._validate_cross_version_semantics.return_value = ([{
                    "reason_code": "SEMANTIC_MISMATCH",
                }], {})
                semantic_failure = oracle.validate_generation(
                    {}, generation, progress_callback=lambda *_args: None,
                )
                oracle._validate_cross_version_semantics.return_value = (
                    [], {},
                )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["helper_identities"], {
            "base": "helper", "current": "helper",
        })
        self.assertIn("closed_world_results", result["truth_parts"])
        self.assertEqual(generation_mismatch["status"], "failed")
        self.assertEqual(profile_binding_failure["status"], "failed")
        self.assertEqual(
            changed.exception.reason_code,
            "BINARY_ORACLE_ARTIFACT_CHANGED_DURING_INVENTORY",
        )
        self.assertEqual(inventory_failure["status"], "failed")
        self.assertEqual(unequal_databases["status"], "passed")
        self.assertEqual(foundational_failure["status"], "failed")
        self.assertEqual(empty_current_truth["status"], "passed")
        self.assertEqual(runtime_failure["status"], "failed")
        self.assertEqual(semantic_failure["status"], "failed")
        scan_cache.clear.assert_called()
        structural_cache.clear.assert_called()

    def test_validate_generation_preflight_and_integrity_failure_matrix(self):
        digest = "a" * 64
        tool_policy = {
            "javap_time_budget_seconds": 1,
            "compile_timeout_seconds": 1,
            "runtime_timeout_seconds": 1,
            "runtime_phase_time_budget_seconds": 1,
            "max_attempts": 1,
        }

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            target = root / "physical"
            target.mkdir()
            linked = root / "linked"
            linked.symlink_to(target, target_is_directory=True)
            with (
                patch.object(
                    oracle, "system_available_memory_bytes",
                    return_value=oracle.LOW_AVAILABLE_MEMORY_WARNING_BYTES,
                ),
                patch.object(
                    oracle, "validate_oracle_tool_execution_policy",
                    return_value=tool_policy,
                ),
            ):
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle.validate_generation({}, linked)
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
            )

            with (
                patch.object(
                    oracle, "system_available_memory_bytes",
                    return_value=oracle.LOW_AVAILABLE_MEMORY_WARNING_BYTES - 1,
                ),
                patch.object(
                    oracle, "validate_oracle_tool_execution_policy",
                    return_value=tool_policy,
                ),
                patch.object(
                    oracle, "preflight_jdk_home",
                    side_effect=oracle.JdkPreflightError(
                        "JDK_INVALID", "invalid", diagnostic={"tool": "java"},
                    ),
                ),
            ):
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle.validate_generation({}, target)
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_JDK_PREFLIGHT_FAILED",
            )

            with (
                patch.object(
                    oracle, "system_available_memory_bytes", return_value=None,
                ),
                patch.object(
                    oracle, "validate_oracle_tool_execution_policy",
                    return_value=tool_policy,
                ),
                patch.object(
                    oracle, "preflight_jdk_home",
                    return_value={"jdk_preflight_identity": digest},
                ),
            ):
                with self.assertRaises(oracle.BinaryValidationError) as raised:
                    oracle.validate_generation(
                        {"base": {"jdk_preflight_identity": "b" * 64}},
                        target,
                    )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_VALIDATION_JDK_CHANGED_SINCE_STEP0",
            )

            sidecar_target = root / "sidecar-target.json"
            sidecar_target.write_text("target", encoding="utf-8")
            sidecar_link = target / "linked-sidecar.json"
            sidecar_link.symlink_to(sidecar_target)
            manifests = [
                [],
                {
                    "result_generation_identity": target.name,
                    "policy_identities": {
                        "base_jdk_preflight_identity": digest,
                        "current_jdk_preflight_identity": digest,
                    },
                    "sidecar_content_identities": [],
                },
                {
                    "result_generation_identity": target.name,
                    "policy_identities": {
                        "base_jdk_preflight_identity": digest,
                        "current_jdk_preflight_identity": digest,
                    },
                    "sidecar_content_identities": {
                        "../escape": "0" * 64,
                        "not-a-string.json": 7,
                        "bad-hash.json": "bad",
                        "missing.json": "0" * 64,
                    },
                },
                {
                    "result_generation_identity": target.name,
                    "policy_identities": {
                        "base_jdk_preflight_identity": digest,
                        "current_jdk_preflight_identity": digest,
                    },
                    "sidecar_content_identities": {
                        sidecar_link.name: "0" * 64,
                    },
                },
            ]
            for manifest in manifests:
                with (
                    patch.object(
                        oracle, "system_available_memory_bytes",
                        return_value=None,
                    ),
                    patch.object(
                        oracle, "validate_oracle_tool_execution_policy",
                        return_value=tool_policy,
                    ),
                    patch.object(
                        oracle, "preflight_jdk_home",
                        return_value={"jdk_preflight_identity": digest},
                    ),
                    patch.object(
                        oracle, "_load_json", return_value=manifest,
                    ),
                    patch.object(
                        oracle, "_expected_result_generation_identity",
                        return_value=(
                            target.name if isinstance(manifest, dict) else None
                        ),
                    ),
                    patch.object(
                        oracle, "_generation_sidecar_declaration_issues",
                        return_value=[],
                    ),
                    patch.object(
                        oracle, "_finalize_validation_result",
                        side_effect=lambda *_args: {
                            "status": "failed", "manifest": manifest,
                        },
                    ),
                ):
                    result = oracle.validate_generation({}, target)
                self.assertEqual(result["status"], "failed")

    def test_runtime_semantic_overlay_uncertainty_and_defensive_matrix(self):
        bean = "Lorg/springframework/context/annotation/Bean;"
        component = "Lorg/springframework/stereotype/Component;"
        primary = "Lorg/springframework/context/annotation/Primary;"
        mapper = "Lorg/apache/ibatis/annotations/Mapper;"
        aspect = "Lorg/aspectj/lang/annotation/Aspect;"
        before = "Lorg/aspectj/lang/annotation/Before;"
        get_mapping = (
            "Lorg/springframework/web/bind/annotation/GetMapping;"
        )
        transactional = (
            "Lorg/springframework/transaction/annotation/Transactional;"
        )
        component_scan = (
            "Lorg/springframework/context/annotation/ComponentScan;"
        )
        repositories = (
            "Lorg/springframework/data/jpa/repository/config/"
            "EnableJpaRepositories;"
        )

        def member(name, descriptor="()V", kind="method", flags=1):
            return f"{kind}|{name}|{descriptor}|{flags}"

        def ready(
            path=None, *, members=(), annotations=(), interfaces=(),
            super_name=None, annotation_values=(), member_annotations=(),
            member_annotation_values=(), modifiers=1,
        ):
            return {
                "status": "definition_ready",
                "provider_url": path.as_uri() if path else "",
                "modifiers": modifiers,
                "super_name": super_name,
                "interfaces": list(interfaces),
                "members": list(members),
                "class_annotations": list(annotations),
                "class_annotation_values": list(annotation_values),
                "member_annotations": list(member_annotations),
                "member_annotation_values": list(
                    member_annotation_values
                ),
            }

        def edge(caller, owner, name, descriptor="()V"):
            return (
                caller, "call", "()V", owner, name, descriptor,
                "invokeinterface", 1, "interface_method",
            )

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            business_path = root / "business.jar"
            dependency_path = root / "dependency.jar"
            business_path.write_bytes(b"business")
            dependency_path.write_bytes(b"dependency")
            artifacts = [
                {"path": str(business_path), "path_kind": "application"},
                {"path": str(dependency_path), "path_kind": "dependency"},
                {"path": "", "path_kind": ""},
            ]

            observations = {
                "java/lang/Object": ready(),
                "api/Unique": ready(modifiers=0x0201),
                "api/Cycle": ready(modifiers=0x0201),
                "app/Config": ready(
                    business_path,
                    annotations=[component],
                    annotation_values=[
                        f"{component_scan}|basePackages|dep.scan",
                        f"{component_scan}|basePackages|ignored.Type.class",
                        f"{component_scan}|empty|",
                        f"{repositories}|repositoryBaseClass|custom.Base",
                    ],
                ),
                "app/Cycle": ready(
                    business_path,
                    annotations=[component],
                    interfaces=["api/Cycle"],
                    super_name="app/Cycle",
                ),
                "dep/scan": ready(
                    dependency_path, annotations=[component],
                ),
                "dep/scan/Child": ready(
                    dependency_path, annotations=[component],
                ),
                "dep/outside/PossibleImpl": ready(
                    dependency_path,
                    members=[member("run")],
                    annotations=[component],
                    interfaces=["api/Unique"],
                ),
                "dep/outside/Other": ready(
                    dependency_path, annotations=[component],
                ),
                "app/Factory": ready(
                    business_path,
                    members=[
                        member("same", "()Lapp/Concrete;"),
                        member("wrong", "()Lapp/Concrete;"),
                        member("field", "I", "field"),
                    ],
                    annotations=[component],
                    member_annotations=[
                        "same|()Lapp/Concrete;|" + bean,
                        "same|()Lapp/Concrete;|" + primary,
                        "wrong|()Lapp/Concrete;|" + bean,
                    ],
                ),
                "dep/Factory": ready(
                    dependency_path,
                    members=[
                        member("make", "()Lapp/Concrete;"),
                        member(
                            "security",
                            "()Lorg/springframework/security/web/"
                            "SecurityFilterChain;",
                        ),
                    ],
                    member_annotations=[
                        "make|()Lapp/Concrete;|" + bean,
                        "security|()Lorg/springframework/security/web/"
                        "SecurityFilterChain;|" + bean,
                    ],
                ),
                "app/Concrete": ready(
                    business_path, members=[member("run")],
                ),
                "app/Unrelated": ready(business_path),
                "app/JakartaFilter": ready(
                    business_path,
                    members=[member("doFilter")],
                    interfaces=["jakarta/servlet/Filter"],
                ),
                "app/Repo": ready(
                    dependency_path,
                    members=[
                        member(
                            "find",
                            "(Ljava/lang/Object;)Ljava/lang/Object;",
                        ),
                        member("zero"),
                    ],
                    interfaces=[
                        "org/springframework/data/repository/Repository",
                    ],
                    modifiers=0x0201,
                ),
                "org/springframework/data/jpa/repository/support/"
                "SimpleJpaRepository": ready(
                    dependency_path,
                    members=[
                        member(
                            "find",
                            "(Ljava/lang/Object;)Ljava/lang/Object;",
                        ),
                        member(
                            "find",
                            "(Ljava/lang/String;)Ljava/lang/Object;",
                        ),
                        member("zero"),
                    ],
                ),
                "app/MapperNotInvoked": ready(
                    dependency_path,
                    members=[member("select")],
                    annotations=[mapper],
                    modifiers=0x0201,
                ),
                "app/MapperConcrete": ready(
                    dependency_path,
                    members=[member("select")],
                    annotations=[mapper],
                    modifiers=0,
                ),
                "app/MapperNamespace": ready(
                    dependency_path,
                    members=[member("select")],
                    modifiers=0x0201,
                ),
                "app/BusinessAspect": ready(
                    business_path,
                    members=[member("advice")],
                    annotations=[aspect],
                    member_annotation_values=[
                        "advice|()V|" + before + "|value|"
                        "execution(* app.*.*(..)) && @within(app.Marked) "
                        "&& !@annotation(app.Skip)",
                    ],
                ),
                "dep/Aspect": ready(
                    dependency_path,
                    members=[member("advice")],
                    annotations=[aspect],
                    member_annotation_values=[
                        "advice|()V|" + before + "|value|"
                        "execution(* app.Join.run(..))",
                    ],
                ),
                "app/EmptyAspect": ready(
                    business_path,
                    members=[member("advice")],
                    annotations=[aspect],
                ),
                "app/Join": ready(
                    business_path,
                    members=[
                        member("run"), member("skip"), member("<init>"),
                        member("state", "I", "field"),
                    ],
                    annotations=["Lapp/Marked;"],
                    member_annotations=["skip|()V|Lapp/Skip;"],
                ),
                "app/NoMark": ready(
                    business_path, members=[member("run")],
                ),
                "app/Feign": ready(
                    dependency_path,
                    members=[member("get")],
                    annotations=[
                        "Lorg/springframework/cloud/openfeign/FeignClient;",
                    ],
                ),
                "app/DubboProvider": ready(
                    dependency_path,
                    members=[
                        member("run"), member("<init>"),
                        member("state", "I", "field"),
                    ],
                ),
                "app/Controller": ready(
                    business_path,
                    members=[
                        member("noArgs", "()Lapp/Dto;"),
                        member("broken", "(I)Lbroken"),
                        member("empty", "()"),
                        member("malformed", "bad"),
                        member("missing", "(Lmissing/Dto;)V"),
                        member("plain"),
                    ],
                    member_annotations=[
                        "noArgs|()Lapp/Dto;|" + get_mapping,
                        "broken|(I)Lbroken|" + get_mapping,
                        "empty|()|" + get_mapping,
                        "malformed|bad|" + get_mapping,
                        "missing|(Lmissing/Dto;)V|" + get_mapping,
                    ],
                ),
                "app/Dto": ready(
                    dependency_path,
                    members=[member("value", "I", "field")],
                ),
                "app/MethodTx": ready(
                    business_path,
                    members=[member("methodTx"), member("plain")],
                    member_annotations=[
                        "methodTx|()V|" + transactional,
                    ],
                ),
                "dep/Tx": ready(
                    dependency_path,
                    members=[member("run")],
                    annotations=[transactional],
                ),
                "org/springframework/transaction/interceptor/"
                "TransactionInterceptor": ready(
                    dependency_path,
                    members=[
                        member(
                            "invoke",
                            "(Ljava/lang/Object;)Ljava/lang/Object;",
                        ),
                        member(
                            "invoke",
                            "(Ljava/lang/String;)Ljava/lang/Object;",
                        ),
                    ],
                ),
                "org/springframework/transaction/interceptor/"
                "TransactionAspectSupport": ready(
                    dependency_path,
                    members=[member(
                        "invokeWithinTransaction",
                        "(Ljava/lang/Object;Ljava/lang/Object;"
                        "Ljava/lang/Object;)Ljava/lang/Object;",
                    )],
                ),
                "org/springframework/aop/framework/"
                "ReflectiveMethodInvocation": ready(
                    dependency_path,
                    members=[member("proceed", "()Ljava/lang/Object;")],
                ),
            }
            instructions = [
                (
                    "app/Factory", "same", "()Lapp/Concrete;", 0,
                    "new", "class app/Concrete",
                ),
                (
                    "app/Factory", "wrong", "()Lapp/Concrete;", 0,
                    "new", "class app/Unrelated",
                ),
                (
                    "dep/Factory", "security",
                    "()Lorg/springframework/security/web/"
                    "SecurityFilterChain;", 0, "new",
                    "class app/JakartaFilter",
                ),
                (
                    "dep/Factory", "security",
                    "()Lorg/springframework/security/web/"
                    "SecurityFilterChain;", 1, "invokevirtual",
                    "Method org/springframework/security/config/annotation/"
                    "web/builders/HttpSecurity.addFilterAfter:()V",
                ),
            ]
            direct_edges = [
                edge("app.UniqueCaller", "api.Unique", "run"),
                edge(
                    "app.RepoCaller", "app.Repo", "find",
                    "(Ljava/lang/Object;)Ljava/lang/Object;",
                ),
                edge("app.RepoCaller", "app.Repo", "zero"),
                edge(
                    "app.MapperCaller", "app.MapperConcrete", "select",
                ),
                edge(
                    "app.DubboCaller",
                    "org.apache.dubbo.common.extension.ExtensionLoader",
                    "getActivateExtension",
                ),
            ]
            resources = [
                {
                    "name": "mapper.xml",
                    "selected": [{"semantic_facts": [[
                        "mybatis_mapper_namespace", "app.MapperNamespace",
                    ]]}],
                },
                {
                    "name": "META-INF/dubbo/app.Service",
                    "selected": [
                        {"semantic_facts": [[
                            "ordered_entry", "provider=app.DubboProvider",
                        ]]},
                        {},
                    ],
                },
                {
                    "name": "META-INF/dubbo/internal/empty.Service",
                    "selected": [],
                },
            ]
            decisions = [
                {"fact_scope": {
                    "member_kind": "field", "class_name": "app.Dto",
                    "member_name": "value", "descriptor": "I",
                }},
                {"fact_scope": {
                    "member_kind": "field", "class_name": "missing.Dto",
                    "member_name": "missing", "descriptor": "J",
                }},
                {"fact_scope": {
                    "member_kind": "field", "class_name": "app.Dto",
                    "member_name": "", "descriptor": "I",
                }},
                {"fact_scope": {
                    "member_kind": "field", "class_name": "",
                    "member_name": "missing", "descriptor": "I",
                }},
            ]
            actual_rows = [
                {
                    "semantic_edge_kind": "implicit_data_contract_dispatch",
                    "caller_class_name": "app/Controller",
                    "caller_member_name": "noArgs",
                    "caller_descriptor": "()Lapp/Dto;",
                    "target_class_name": "app/Dto",
                    "target_member_name": "value",
                    "target_descriptor": "I",
                    "path_certainty": "exact",
                },
                {
                    "semantic_edge_kind": "spring_bean_wiring_dispatch",
                    "caller_class_name": "app/UniqueCaller",
                    "caller_member_name": "call",
                    "caller_descriptor": "()V",
                    "target_class_name": "dep/outside/PossibleImpl",
                    "target_member_name": "run",
                    "target_descriptor": "()V",
                    "path_certainty": "exact",
                },
                {"semantic_edge_kind": "dynamic_proxy_callback"},
                {"semantic_edge_kind": "unsupported"},
            ]

            def sidecar_rows(_generation, filename, key, **_kwargs):
                if filename == "binary_runtime_semantic_overlay.json":
                    return iter(actual_rows)
                if key in {
                    "authoritative_change_facts",
                    "diagnostic_candidate_facts",
                }:
                    return iter(decisions)
                return iter(())

            active_side = {"runtime_profile": {
                "business_entrypoint_profile": {
                    "activated_frameworks": [],
                    "activated_component_scan_packages": [
                        "dep.scan", "unused", "",
                    ],
                    "activated_resource_names": [],
                    "main_class": "Main",
                },
                "container_and_launcher_kind": "spring_boot",
                "active_profile_identities": [],
                "resolved_configuration_properties": {},
                "runtime_configuration_coverage_status": "complete",
            }}

            with (
                patch.object(
                    oracle, "_oracle_runtime_semantic_rows",
                    return_value=set(),
                ),
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=sidecar_rows,
                ),
            ):
                custom_issues, custom_truth = (
                    oracle._validate_runtime_semantic_overlay(
                        root, active_side, artifacts, {}, observations,
                        instructions, direct_edges, resources,
                    )
                )

                standard_observations = dict(observations)
                standard_observations["app/Config"] = ready(
                    business_path,
                    annotations=[component],
                    annotation_values=[
                        f"{component_scan}|basePackages|dep.scan",
                    ],
                )
                standard_issues, standard_truth = (
                    oracle._validate_runtime_semantic_overlay(
                        root, active_side, artifacts, {},
                        standard_observations, instructions, direct_edges,
                        resources,
                    )
                )

                inactive_observations = dict(standard_observations)
                inactive_observations[
                    "feign/SynchronousMethodHandler"
                ] = ready(
                    dependency_path,
                    members=[member(
                        "invoke",
                        "(Ljava/lang/Object;)Ljava/lang/Object;",
                    )],
                )
                inactive_issues, inactive_truth = (
                    oracle._validate_runtime_semantic_overlay(
                        root, {}, artifacts, {}, inactive_observations,
                        instructions, direct_edges, resources,
                    )
                )

        for issues in (custom_issues, standard_issues, inactive_issues):
            self.assertEqual(
                {item["reason_code"] for item in issues},
                {"ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH"},
            )
        self.assertTrue(any(
            row[0] == "dubbo_spi_dispatch"
            for row in custom_truth["validated_exact_edges"]
        ))
        self.assertTrue(any(
            row[0] == "spring_data_repository_proxy_dispatch"
            and row[5] == "zero"
            for row in standard_truth["validated_exact_edges"]
        ))
        self.assertFalse(any(
            row[0] == "spring_transaction_proxy_dispatch"
            for row in inactive_truth["validated_exact_edges"]
        ))
        self.assertGreater(custom_truth["oracle_candidate_edge_count"], 0)
        conflicts = custom_issues[0]["evidence"]["certainty_conflicts"]
        self.assertTrue(any(
            row["edge"][0] == "spring_bean_wiring_dispatch"
            and row["oracle_candidate_evidence"]
            for row in conflicts
        ))

    def test_runtime_semantic_overlay_framework_and_proxy_matrix(self):
        bean = "Lorg/springframework/context/annotation/Bean;"
        component = "Lorg/springframework/stereotype/Component;"
        service = "Lorg/springframework/stereotype/Service;"
        primary = "Lorg/springframework/context/annotation/Primary;"
        transactional = (
            "Lorg/springframework/transaction/annotation/Transactional;"
        )

        def member(name, descriptor="()V", kind="method", flags=1):
            return f"{kind}|{name}|{descriptor}|{flags}"

        def ready(
            path, *, members=(), annotations=(), interfaces=(), super_name=None,
            annotation_values=(), member_annotations=(),
            member_annotation_values=(), modifiers=1,
        ):
            return {
                "status": "definition_ready",
                "provider_url": path.as_uri() if path else "",
                "modifiers": modifiers,
                "super_name": super_name,
                "interfaces": list(interfaces),
                "members": list(members),
                "class_annotations": list(annotations),
                "class_annotation_values": list(annotation_values),
                "member_annotations": list(member_annotations),
                "member_annotation_values": list(member_annotation_values),
            }

        def edge(caller, owner, name, descriptor="()V", kind="method"):
            return (
                caller, "call", "()V", owner, name, descriptor,
                "invokeinterface", 1, kind,
            )

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            business_path = root / "business.jar"
            dependency_path = root / "dependency.jar"
            external_path = root / "external.jar"
            for path, content in (
                (business_path, b"business"),
                (dependency_path, b"dependency"),
                (external_path, b"external"),
            ):
                path.write_bytes(content)

            observations = {
                "java/lang/Object": ready(None),
                "api/Service": ready(None, modifiers=0x0201),
                "api/Multi": ready(None, modifiers=0x0201),
                "api/Abstract": ready(None, modifiers=0x0201),
                "app/Main": ready(
                    business_path,
                    annotations=[component],
                    annotation_values=[
                        "Lorg/springframework/context/annotation/ComponentScan;"
                        "|basePackages|app",
                        "Lorg/springframework/context/annotation/ComponentScan;"
                        "|basePackages|ignored.Type.class",
                    ],
                ),
                "app/PrimaryImpl": ready(
                    business_path,
                    members=[
                        member("run"), member("other"),
                        member("state", "I", "field"),
                        member("<init>"), member("<clinit>"),
                        member("skip"),
                    ],
                    annotations=[service, primary, "Lapp/Marked;"],
                    interfaces=["api/Service"],
                    member_annotations=[
                        "run|()V|Lapp/Trace;", "skip|()V|Lapp/Skip;",
                    ],
                ),
                "app/SecondaryImpl": ready(
                    business_path, members=[member("run")],
                    annotations=[service], interfaces=["api/Service"],
                ),
                "app/MultiOne": ready(
                    business_path, members=[member("run")],
                    annotations=[component], interfaces=["api/Multi"],
                ),
                "app/MultiTwo": ready(
                    business_path, members=[member("run")],
                    annotations=[component], interfaces=["api/Multi"],
                ),
                "app/InactiveComponent": ready(
                    business_path, members=[member("run")],
                    annotations=[
                        component,
                        "Lorg/springframework/context/annotation/Profile;",
                    ],
                    annotation_values=[
                        "Lorg/springframework/context/annotation/Profile;"
                        "|value|inactive",
                    ],
                    interfaces=["api/Service"],
                ),
                "app/ConditionalComponent": ready(
                    business_path, members=[member("run")],
                    annotations=[
                        component,
                        "Lorg/springframework/context/annotation/Conditional;",
                    ],
                    interfaces=["api/Service"],
                ),
                "app/XmlExact": ready(
                    dependency_path, members=[member("run")],
                    interfaces=["api/Service"],
                ),
                "app/XmlPossible": ready(
                    dependency_path, members=[member("run")],
                    interfaces=["api/Service"],
                ),
                "app/Factory": ready(
                    business_path,
                    members=[
                        member("make", "()Lapi/Service;"),
                        member("ambiguous", "()Lapi/Abstract;"),
                        member("concrete", "()Lapp/ReturnedConcrete;"),
                        member("primitive", "()I"),
                        member("security", (
                            "()Lorg/springframework/security/web/"
                            "SecurityFilterChain;"
                        )),
                        member("unusedFilter", "()Ljavax/servlet/Filter;"),
                        member("field", "I", "field"),
                    ],
                    annotations=[component],
                    member_annotations=[
                        "make|()Lapi/Service;|" + bean,
                        "ambiguous|()Lapi/Abstract;|" + bean,
                        "concrete|()Lapp/ReturnedConcrete;|" + bean,
                        "primitive|()I|" + bean,
                        "security|()Lorg/springframework/security/web/"
                        "SecurityFilterChain;|" + bean,
                        "unusedFilter|()Ljavax/servlet/Filter;|" + bean,
                    ],
                ),
                "app/FactoryImpl": ready(
                    business_path, members=[member("run")],
                    interfaces=["api/Service"],
                ),
                "app/AmbiguousOne": ready(
                    business_path, interfaces=["api/Abstract"],
                ),
                "app/AmbiguousTwo": ready(
                    business_path, interfaces=["api/Abstract"],
                ),
                "app/ReturnedConcrete": ready(
                    business_path, members=[member("run")],
                ),
                "app/MyFilter": ready(
                    business_path,
                    members=[
                        member("doFilter", "(Ljava/lang/Object;)V"),
                        member("other"), member("state", "I", "field"),
                    ],
                    interfaces=["javax/servlet/Filter"],
                ),
                "app/NotAFilter": ready(
                    business_path, members=[member("doFilter")],
                ),
                "app/Repo": ready(
                    dependency_path, members=[member("find", "(Ljava/lang/Object;)Ljava/lang/Object;")],
                    interfaces=["org/springframework/data/repository/Repository"],
                    modifiers=0x0201,
                ),
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository": ready(
                    dependency_path,
                    members=[
                        member("find", "(Ljava/lang/Object;)Ljava/lang/Object;"),
                        member("find", "()Ljava/lang/Object;"),
                        member("state", "I", "field"),
                    ],
                ),
                "app/MapperAnnotated": ready(
                    dependency_path,
                    members=[member("select", "(I)Ljava/lang/Object;"), member("state", "I", "field")],
                    annotations=["Lorg/apache/ibatis/annotations/Mapper;"],
                    modifiers=0x0201,
                ),
                "app/MapperNamespace": ready(
                    dependency_path, members=[member("load")], modifiers=0x0201,
                ),
                "app/MapperConcrete": ready(
                    dependency_path, members=[member("load")],
                ),
                "org/apache/ibatis/binding/MapperProxy": ready(
                    dependency_path,
                    members=[
                        member("invoke", (
                            "(Ljava/lang/Object;Ljava/lang/reflect/Method;"
                            "[Ljava/lang/Object;)Ljava/lang/Object;"
                        )),
                        member("invoke", "()V"),
                        member("state", "I", "field"),
                    ],
                ),
                "org/apache/ibatis/binding/MapperMethod": ready(
                    dependency_path,
                    members=[
                        member("execute", (
                            "(Ljava/lang/Object;[Ljava/lang/Object;)"
                            "Ljava/lang/Object;"
                        )),
                        member("other"),
                    ],
                ),
                "app/Aspect": ready(
                    business_path,
                    members=[
                        member("before"), member("partial"),
                        member("field", "I", "field"),
                    ],
                    annotations=["Lorg/aspectj/lang/annotation/Aspect;"],
                    member_annotation_values=[
                        "before|()V|Lorg/aspectj/lang/annotation/Before;|value|"
                        "@within(app.Marked) && @annotation(app.Trace) && "
                        "execution(* app.PrimaryImpl.*(..))",
                        "before|(I)V|Lorg/aspectj/lang/annotation/Before;|value|ignored",
                        "other|()V|Lorg/aspectj/lang/annotation/Before;|value|ignored",
                        "before|()V|Lignored/Annotation;|value|ignored",
                        "before|()V|Lorg/aspectj/lang/annotation/Before;|value|unsupported(x)",
                        "partial|()V|Lorg/aspectj/lang/annotation/Around;|value|"
                        "execution(* app.PrimaryImpl.run(..)) && bean(named)",
                    ],
                ),
                "app/NotAspect": ready(
                    business_path, members=[member("before")],
                ),
                "feign/SynchronousMethodHandler": ready(
                    dependency_path,
                    members=[member("invoke", "(Ljava/lang/Object;)Ljava/lang/Object;"), member("state", "I", "field")],
                ),
                "feign/InvocationHandlerFactory$Default": ready(
                    dependency_path, members=[member("invoke", "()Ljava/lang/Object;")],
                ),
                "app/FeignClass": ready(
                    dependency_path, members=[member("get"), member("state", "I", "field")],
                    annotations=["Lorg/springframework/cloud/openfeign/FeignClient;"],
                ),
                "app/FeignMethod": ready(
                    dependency_path, members=[member("post"), member("plain")],
                    member_annotations=["post|()V|Lfeign/RequestLine;"],
                ),
                "app/DubboProvider": ready(
                    dependency_path,
                    members=[
                        member("run"), member("<init>"), member("<clinit>"),
                        member("state", "I", "field"),
                    ],
                ),
                "app/DubboOther": ready(
                    dependency_path, members=[member("run")],
                ),
                "app/Controller": ready(
                    business_path,
                    members=[
                        member("bind", "(Lapp/Dto;I)Lapp/Response;"),
                        member("plain"), member("state", "I", "field"),
                    ],
                    member_annotations=[
                        "bind|(Lapp/Dto;I)Lapp/Response;|"
                        "Lorg/springframework/web/bind/annotation/GetMapping;",
                    ],
                ),
                "app/Dto": ready(
                    dependency_path,
                    members=[member("value", "Ljava/lang/String;", "field")],
                ),
                "app/Response": ready(
                    dependency_path,
                    members=[member("gone", "I", "field")],
                ),
                "app/TransactionalService": ready(
                    business_path,
                    members=[member("classTx"), member("methodTx"), member("plain"), member("state", "I", "field")],
                    annotations=[transactional],
                    member_annotations=["methodTx|()V|" + transactional],
                ),
                "dep/TransactionalIgnored": ready(
                    dependency_path, members=[member("run")],
                    annotations=[transactional],
                ),
                "org/springframework/transaction/interceptor/TransactionInterceptor": ready(
                    dependency_path,
                    members=[member("invoke", "(Ljava/lang/Object;)Ljava/lang/Object;"), member("invoke", "()V")],
                ),
                "org/springframework/transaction/interceptor/TransactionAspectSupport": ready(
                    dependency_path,
                    members=[member("invokeWithinTransaction", "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")],
                ),
                "org/springframework/aop/framework/ReflectiveMethodInvocation": ready(
                    dependency_path, members=[member("proceed", "()Ljava/lang/Object;")],
                ),
                "external/Target": ready(
                    external_path, members=[member("run")],
                ),
            }

            instructions = [
                ("app/Factory", "make", "()Lapi/Service;", 0, "new", "class app/FactoryImpl"),
                ("app/Factory", "ambiguous", "()Lapi/Abstract;", 0, "new", "class app/AmbiguousOne"),
                ("app/Factory", "ambiguous", "()Lapi/Abstract;", 1, "new", 'class "app/AmbiguousTwo"'),
                ("app/Factory", "primitive", "()I", 0, "new", "not-a-class"),
                ("app/Factory", "security", "()Lorg/springframework/security/web/SecurityFilterChain;", 0, "new", "class app/MyFilter"),
                ("app/Factory", "security", "()Lorg/springframework/security/web/SecurityFilterChain;", 1, "new", "class app/NotAFilter"),
                ("app/Factory", "security", "()Lorg/springframework/security/web/SecurityFilterChain;", 2, "invokevirtual", "Method org/springframework/security/config/annotation/web/builders/HttpSecurity.addFilter:(Ljavax/servlet/Filter;)Ljava/lang/Object;"),
                ("app/Factory", "unusedFilter", "()Ljavax/servlet/Filter;", 0, "new", "class app/MyFilter"),
                ("app/Factory", "other", "()V", 0, "invokevirtual", "Method example/Type.other:()V"),
            ]

            class InstructionBatches:
                def iter_batches(self):
                    return iter((
                        (row for row in instructions[:4]),
                        instructions[4:],
                    ))

            direct_edges = [
                ("short", "edge", "()V"),
                edge("app.Caller", "api.Service", "run", kind="field"),
                edge("app.Caller", "api.Service", "field", "I"),
                edge("app.Caller", "api.Service", "run"),
                edge("app.Caller", "api.Multi", "run"),
                edge("app.RepoCaller", "app.Repo", "find", "(Ljava/lang/Object;)Ljava/lang/Object;"),
                edge("app.MapperCaller", "app.MapperAnnotated", "select", "(I)Ljava/lang/Object;"),
                edge("app.MapperCaller", "app.MapperNamespace", "load"),
                edge("app.MapperCaller", "app.MapperConcrete", "load"),
                edge("app.DubboCaller", "org.apache.dubbo.common.extension.ExtensionLoader", "getExtension"),
                edge("app.DubboCaller", "org.apache.dubbo.common.extension.ExtensionLoader", "getAdaptiveExtension"),
                edge("app.DubboCaller", "org.apache.dubbo.common.extension.ExtensionLoader", "other"),
            ]
            resource_truth = [
                {
                    "name": "mapper.xml", "selected": [{"semantic_facts": [
                        ["mybatis_mapper_namespace", "app.MapperNamespace"],
                        ["other", "ignored"],
                    ]}, {}],
                },
                {
                    "name": "beans.xml", "selected": [{"semantic_facts": [
                        ["spring_bean_class", "bean|app.XmlExact"],
                        ["spring_bean_primary", "bean|app.PrimaryImpl"],
                        ["spring_bean_class", "invalid"],
                        ["spring_bean_primary", "invalid"],
                    ]}],
                },
                {
                    "name": "inactive.xml", "selected": [{"semantic_facts": [
                        ["spring_bean_class", "bean|app.XmlPossible"],
                    ]}],
                },
                {
                    "name": "META-INF/dubbo/internal/app.Service", "realm": "app",
                    "selected": [{"semantic_facts": [
                        ["ordered_entry", "primary=app.DubboProvider"],
                        ["ignored", "app.DubboOther"],
                        ["ordered_entry", ""],
                    ]}],
                },
                {
                    "name": "META-INF/dubbo/external/app.Other", "realm": "dep",
                    "selected": [{"semantic_facts": [
                        ["ordered_entry", "app.DubboOther"],
                    ]}],
                },
                {"name": "META-INF/not-dubbo", "selected": []},
                {"selected": [{}]},
            ]
            current_side = {"runtime_profile": {
                "business_entrypoint_profile": {
                    "activated_frameworks": ["spring_boot", "", None],
                    "activated_component_scan_packages": ["app", "", None],
                    "activated_resource_names": ["classpath:beans.xml", "", None],
                    "main_class": "app.Main",
                },
                "container_and_launcher_kind": "custom",
                "active_profile_identities": ["active", "", None],
                "resolved_configuration_properties": {"feature": True, 1: 2},
                "runtime_configuration_coverage_status": "complete",
            }}
            base_observations = {
                "app/Dto": ready(
                    dependency_path,
                    members=[
                        member("old", "I", "field"),
                        member("baseOnly", "J", "field"),
                    ],
                ),
                "app/Response": ready(
                    dependency_path,
                    members=[member("baseGone", "I", "field")],
                ),
            }
            decisions = [
                {"fact_scope": {"member_kind": "method"}},
                {"fact_scope": {"member_kind": "field", "class_name": "", "member_name": ""}},
                {"fact_scope": {"member_kind": "field", "class_name": "app.Dto", "member_name": "value", "descriptor": "Ljava/lang/String;"}},
                {"fact_scope": {"member_kind": "field", "class_name": "app.Dto", "member_name": "baseOnly", "descriptor": "J"}},
                {"fact_scope": {"member_kind": "field", "class_name": "app.Response", "member_name": "fallback", "descriptor": "I"}},
                {},
            ]
            actual_rows = [
                {"semantic_edge_kind": "unsupported"},
                {
                    "semantic_edge_kind": "spring_bean_wiring_dispatch",
                    "caller_class_name": "app/Caller",
                    "caller_member_name": "call",
                    "caller_descriptor": "()V",
                    "target_class_name": "app/PrimaryImpl",
                    "target_member_name": "run",
                    "target_descriptor": "()V",
                    "path_certainty": "possible",
                },
                {"semantic_edge_kind": "reflection_method_invocation", "path_certainty": "exact"},
                {"semantic_edge_kind": "dynamic_proxy_callback", "path_certainty": "possible"},
            ]

            def sidecar_rows(_generation, filename, key, **_kwargs):
                if filename == "binary_runtime_semantic_overlay.json":
                    return iter(actual_rows)
                if key == "authoritative_change_facts":
                    return iter(decisions)
                return iter([{}, *decisions[:3]])

            oracle_rows = {
                (
                    "reflection_method_invocation", "app/Reflect", "call", "()V",
                    "app/PrimaryImpl", "run", "()V", "exact",
                ),
                (
                    "reflection_method_invocation", "app/Reflect", "call", "()V",
                    "external/Target", "run", "()V", "exact",
                ),
                (
                    "reflection_method_invocation", "app/Reflect", "call", "()V",
                    "missing/Target", "run", "()V", "exact",
                ),
            }
            with (
                patch.object(
                    oracle, "_oracle_runtime_semantic_rows",
                    return_value=oracle_rows,
                ),
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=sidecar_rows,
                ),
            ):
                issues, truth = oracle._validate_runtime_semantic_overlay(
                    root, current_side,
                    [
                        {"path": str(business_path), "path_kind": "business"},
                        {"path": str(dependency_path), "path_kind": "dependency"},
                        {},
                    ],
                    base_observations, observations, InstructionBatches(),
                    direct_edges, resource_truth,
                )

        self.assertEqual(
            {item["reason_code"] for item in issues},
            {"ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH"},
        )
        exact_kinds = {row[0] for row in truth["validated_exact_edges"]}
        self.assertTrue({
            "reflection_method_invocation",
            "mybatis_mapper_proxy_dispatch",
            "spring_bean_wiring_dispatch",
            "spring_data_repository_proxy_dispatch",
            "spring_aop_dispatch",
            "spring_security_filter_dispatch",
            "declarative_http_client_dispatch",
            "implicit_data_contract_dispatch",
            "spring_transaction_proxy_dispatch",
        }.issubset(exact_kinds), exact_kinds)
        self.assertEqual(
            set(truth["validated_kinds"]),
            {
                "reflection_method_invocation",
                "reflection_constructor_invocation",
                "reflection_field_access",
                "method_handle_invocation",
                "method_handle_field_access",
                "dynamic_proxy_callback",
                "mybatis_mapper_proxy_dispatch",
                "spring_transaction_proxy_dispatch",
                "spring_bean_wiring_dispatch",
                "spring_data_repository_proxy_dispatch",
                "spring_aop_dispatch",
                "spring_security_filter_dispatch",
                "declarative_http_client_dispatch",
                "dubbo_spi_dispatch",
                "implicit_data_contract_dispatch",
            },
        )
        self.assertGreater(truth["oracle_candidate_edge_count"], 0)
        self.assertGreater(truth["production_candidate_edge_count"], 0)
        self.assertFalse(truth["exact_edge_set_matches"])
        conflict_rows = issues[0]["evidence"]["certainty_conflicts"]
        self.assertTrue(any(
            row["edge"][0] == "spring_bean_wiring_dispatch"
            for row in conflict_rows
        ))

    def test_entrypoint_profile_activation_condition_and_reason_matrix(self):
        scheduled = "Lorg/springframework/scheduling/annotation/Scheduled;"
        conditional = "Lorg/springframework/context/annotation/Conditional;"
        profile_annotation = "Lorg/springframework/context/annotation/Profile;"
        entity_annotation = "Ljakarta/persistence/Entity;"
        pre_persist = "Ljakarta/persistence/PrePersist;"
        component = "Lorg/springframework/stereotype/Component;"
        component_scan = (
            "Lorg/springframework/context/annotation/ComponentScan;"
        )

        def member(name, descriptor="()V", flags=1, kind="method"):
            return f"{kind}|{name}|{descriptor}|{flags}"

        def ready(
            provider, *, members=(), annotations=(), interfaces=(),
            annotation_values=(), member_annotations=(),
            member_annotation_values=(), imports=(), resources=(), modifiers=1,
        ):
            return {
                "status": "definition_ready",
                "provider_url": provider.as_uri() if provider else "",
                "modifiers": modifiers,
                "super_name": "java/lang/Object",
                "interfaces": list(interfaces),
                "members": list(members),
                "class_annotations": list(annotations),
                "class_annotation_values": list(annotation_values),
                "member_annotations": list(member_annotations),
                "member_annotation_values": list(member_annotation_values),
                "class_annotation_imports": list(imports),
                "class_annotation_resources": list(resources),
            }

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            business_path = root / "business.jar"
            dependency_path = root / "dependency.jar"
            business_path.write_bytes(b"business")
            dependency_path.write_bytes(b"dependency")
            artifacts = [
                {
                    "path": str(business_path), "path_kind": "APPLICATION",
                },
                {
                    "path": str(dependency_path), "path_kind": "dependency",
                },
                {"path": str(root / "unknown.jar")},
            ]
            observations = {
                "java/lang/Object": ready(None, members=[]),
                "biz/ProfileMain": ready(
                    business_path,
                    members=[
                        member("main", "([Ljava/lang/String;)V", 9),
                        member("ignoredField", "I", 1, "field"),
                        member("abstracted", "()V", 0x0401),
                    ],
                ),
                "biz/OtherMain": ready(
                    business_path,
                    members=[member("main", "([Ljava/lang/String;)V", 9)],
                ),
                "biz/Declared": ready(
                    business_path, members=[member("declared")],
                ),
                "biz/Configuration": ready(
                    business_path,
                    members=[member("tick")],
                    annotations=[
                        "Lbiz/Meta;", "plain-annotation",
                        "Lunterminated", "trailing-semicolon;",
                    ],
                    annotation_values=[
                        f"{component_scan}|basePackages|dep.scan",
                        f"{component_scan}|basePackages|ignored.Type.class",
                        f"{component_scan}|basePackages|",
                    ],
                    member_annotations=[f"tick|()V|{scheduled}"],
                    imports=[
                        "dep/Imported", "dep/ProfileActivated",
                        "<unresolved:missing.Import>",
                    ],
                    resources=[
                        "classpath:config/exact.xml", "not-xml.txt",
                        "<unresolved:missing-resource>", "",
                    ],
                ),
                "biz/Meta": ready(
                    business_path,
                    annotations=[component],
                    imports=["dep/MetaImported"],
                ),
                "biz/Component": ready(
                    business_path, members=[member("tick")],
                    annotations=[component],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/scan/Scanned": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[component],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/scan": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[component],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "outside/NotScanned": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[component],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/Auto": ready(
                    dependency_path, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/Factory": ready(
                    dependency_path,
                    members=[member("onApplicationEvent"), member("other")],
                ),
                "dep/Imported": ready(
                    dependency_path, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/MetaImported": ready(
                    dependency_path, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/ProfileActivated": ready(
                    dependency_path, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/Unproven": ready(
                    dependency_path, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/Conditional": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[conditional],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/SatisfiedConditional": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[
                        "Lorg/springframework/boot/autoconfigure/condition/"
                        "ConditionalOnClass;",
                    ],
                    annotation_values=[
                        "Lorg/springframework/boot/autoconfigure/condition/"
                        "ConditionalOnClass;|value|biz.ProfileMain",
                    ],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/Inactive": ready(
                    dependency_path, members=[member("tick")],
                    annotations=[profile_annotation],
                    annotation_values=[
                        f"{profile_annotation}|value|inactive-profile",
                    ],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "dep/MemberConditional": ready(
                    dependency_path,
                    members=[member("tick"), member("inactive"), member("ready")],
                    member_annotations=[
                        f"tick|()V|{conditional}",
                        f"inactive|()V|{profile_annotation}",
                        "ready|()V|Lorg/springframework/boot/autoconfigure/"
                        "condition/ConditionalOnClass;",
                        f"ready|()V|{scheduled}",
                    ],
                    member_annotation_values=[
                        f"inactive|()V|{profile_annotation}|value|inactive-profile",
                        "ready|()V|Lorg/springframework/boot/autoconfigure/"
                        "condition/ConditionalOnClass;|value|biz.ProfileMain",
                        "other|()V|Lignored/Annotation;|value|ignored",
                        "ready|(I)V|Lignored/Annotation;|value|ignored",
                    ],
                ),
                "dep/EntityActive": ready(
                    dependency_path, members=[member("before")],
                    annotations=[entity_annotation],
                    member_annotations=[f"before|()V|{pre_persist}"],
                ),
                "dep/EntityUnproven": ready(
                    dependency_path, members=[member("before")],
                    annotations=[entity_annotation],
                    member_annotations=[f"before|()V|{pre_persist}"],
                ),
                "biz/OwnedEntity": ready(
                    business_path, members=[member("before")],
                    annotations=[entity_annotation],
                    member_annotations=[f"before|()V|{pre_persist}"],
                ),
                "biz/Runner": ready(
                    business_path, members=[member("run"), member("other")],
                    interfaces=["org/springframework/boot/ApplicationRunner"],
                ),
                "biz/MainWrongDescriptor": ready(
                    business_path, members=[member("main", "()V", 9)],
                ),
                "biz/MainNonPublic": ready(
                    business_path,
                    members=[member("main", "([Ljava/lang/String;)V", 8)],
                ),
                "biz/MainNonStatic": ready(
                    business_path,
                    members=[member("main", "([Ljava/lang/String;)V", 1)],
                ),
                "dep/MainNotOwned": ready(
                    dependency_path,
                    members=[member("main", "([Ljava/lang/String;)V", 9)],
                ),
                "biz/Rabbit": ready(
                    business_path, members=[member("onMessage"), member("other")],
                    annotations=[
                        "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;"
                    ],
                ),
                "biz/NoProvider": ready(
                    None, members=[member("tick")],
                    member_annotations=[f"tick|()V|{scheduled}"],
                ),
                "biz/AbstractClass": ready(
                    business_path, members=[member("tick")], modifiers=0x0401,
                ),
                "biz/NotReady": {
                    "status": "not_found", "provider_url": business_path.as_uri(),
                },
            }
            observations["dep/Unproven"].pop("modifiers")
            resource_truth = [
                {
                    "name": (
                        "META-INF/spring/org.springframework.boot.autoconfigure."
                        "AutoConfiguration.imports"
                    ),
                    "selected": [{"semantic_facts": [
                        ["ordered_entry", "dep.Auto"],
                    ]}],
                },
                {
                    "name": "META-INF/spring.factories",
                    "selected": [{"semantic_facts": [
                        [
                            "property_entry:org.springframework.context."
                            "ApplicationListener", "dep.Factory",
                        ],
                        [
                            "property_entry:org.springframework.boot.autoconfigure."
                            "EnableAutoConfiguration", "dep.Auto",
                        ],
                        ["property_entry:unknown.Factory", "dep.Ignored"],
                    ]}],
                },
                {
                    "name": "META-INF/persistence.xml",
                    "selected": [{"semantic_facts": [
                        ["jpa_managed_class", "dep.EntityActive"],
                        ["jpa_managed_class", ""],
                        ["other", "dep.Ignored"],
                    ]}, {}],
                },
                {"name": "empty", "selected": []},
            ]
            profile = {
                "main_class": "biz.ProfileMain",
                "coverage_status": "partial",
                "coverage_gaps": ["profile-gap", "", None],
                "activated_frameworks": ["spring_boot", "", None],
                "activated_classes": [
                    "dep.ProfileActivated", "", None,
                ],
                "activated_entity_classes": [
                    "dep.EntityActive", "", None,
                ],
                "active_profile_identities": ["active-profile", "", None],
                "methods": [
                    {
                        "class_name": "biz.Declared",
                        "member_name": "declared", "descriptor": "()V",
                    },
                    {},
                    "invalid-method",
                ],
                "activated_resource_names": [
                    "classpath:config/exact.xml", "", None,
                ],
            }
            current_side = {"runtime_profile": {
                "business_entrypoint_profile": profile,
                "entrypoint_discovery_coverage_gaps": (
                    "runtime-gap", "", None,
                ),
                "loader_topology": {
                    "realms": [
                        {"identity": "platform", "kind": "platform"},
                        {"identity": "app", "kind": "url"},
                        {"identity": "dep", "kind": "url"},
                        {"identity": "", "kind": "url"},
                        {"kind": "url"},
                    ],
                    "entrypoint_realms": ["app", "dep"],
                },
                "container_and_launcher_kind": "custom",
                "active_profile_identities": ["active-profile", "", None],
                "resolved_configuration_properties": {"flag": True, 1: 2},
                "runtime_configuration_coverage_status": "complete",
            }}
            actual_rows = [
                {},
                {
                    "initiating_loader_realm_identity": "app",
                    "class_name": "unexpected/Class",
                    "member_name": "run", "descriptor": "()V",
                    "entry_kind": "unexpected", "path_certainty": "exact",
                    "activation_reason": "unexpected",
                },
                {
                    "initiating_loader_realm_identity": "dep",
                    "class_name": "candidate/Class",
                    "member_name": "run", "descriptor": "()V",
                    "entry_kind": "candidate", "path_certainty": "possible",
                    "activation_reason": "candidate",
                },
            ]

            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    return_value=iter(actual_rows),
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value",
                    side_effect=lambda _generation, _filename, key: (
                        ["attested-gap", "", None]
                        if key == "coverage_gaps" else "complete"
                    ),
                ),
            ):
                issues, truth = oracle._validate_entrypoint_discovery(
                    root, current_side, artifacts, observations,
                    resource_truth, [], [],
                )

        reason_codes = {item["reason_code"] for item in issues}
        self.assertEqual({
            "ORACLE_ENTRYPOINT_SET_MISMATCH",
            "ORACLE_ENTRYPOINT_DECLARED_COVERAGE_GAP_MISSING",
            "ORACLE_ENTRYPOINT_COVERAGE_ATTESTATION_INVALID",
        }, reason_codes)
        exact_rows = {tuple(row) for row in truth["exact_entrypoints"]}
        reasons = {row[6] for row in exact_rows}
        self.assertTrue({
            "runtime_profile_declaration",
            "business_final_artifact_runtime_trigger",
            "spring_boot_auto_configuration_import",
            "spring_factories_runtime_registration",
            "spring_import_from_active_configuration",
            "runtime_profile_activation_declaration",
            "jpa_entity_registration_proved",
        }.issubset(reasons), reasons)
        self.assertGreater(truth["oracle_candidate_entrypoint_count"], 0)
        self.assertGreater(truth["production_candidate_entrypoint_count"], 0)
        self.assertTrue(any(
            gap.startswith("annotation_import:")
            for gap in truth["candidate_activation_gaps"]
        ))
        self.assertTrue(any(
            gap.startswith("resource_import:")
            for gap in truth["candidate_activation_gaps"]
        ))

    def test_entrypoint_adapter_and_xml_resource_callback_matrix(self):
        adapter_owner = (
            "org/springframework/amqp/rabbit/listener/adapter/"
            "MessageListenerAdapter"
        )
        constructor_comment = (
            f'Method {adapter_owner}."<init>":'
            "(Ljava/lang/Object;Ljava/lang/String;)V"
        )

        def member(name, descriptor="()V", kind="method"):
            return f"{kind}|{name}|{descriptor}|1"

        def ready(path, members=(), resources=()):
            return {
                "status": "definition_ready",
                "provider_url": path.as_uri() if path else "",
                "modifiers": 1,
                "super_name": "java/lang/Object",
                "interfaces": [],
                "members": list(members),
                "class_annotations": [],
                "class_annotation_resources": list(resources),
            }

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            business_path = root / "business.jar"
            dependency_path = root / "dependency.jar"
            business_path.write_bytes(b"business")
            dependency_path.write_bytes(b"dependency")
            observations = {
                "java/lang/Object": ready(None),
                "biz/Factory": ready(
                    business_path,
                    resources=[
                        "classpath:config/annotated.xml",
                        "not-an-xml.txt", "<unresolved:resource>", "",
                    ],
                ),
                "dep/Factory": ready(dependency_path),
                "biz/NoCallback": ready(business_path),
                "biz/NotReady": {"status": "not_found"},
                "dep/Receiver": ready(
                    dependency_path,
                    members=[
                        member("receive", "(Ljava/lang/String;)V"),
                        member("ignored", "I", "field"),
                    ],
                ),
                "dep/Ambiguous": ready(
                    dependency_path,
                    members=[member("receive"), member("receive", "(I)V")],
                ),
                "dep/Plugin": ready(
                    dependency_path,
                    members=[member("intercept", "(Ljava/lang/Object;)V")],
                ),
                "dep/Handler": ready(
                    dependency_path,
                    members=[
                        member("setParameter", "(I)V"),
                        member("getResult", "()Ljava/lang/Object;"),
                        member("ignored", "I", "field"),
                    ],
                ),
                "dep/XmlTarget": ready(
                    dependency_path,
                    members=[member("init"), member("state", "I", "field")],
                ),
                "dep/AmbigTarget": ready(
                    dependency_path,
                    members=[member("run"), member("run", "(I)V")],
                ),
            }
            profile = {
                "activated_frameworks": ["spring_boot"],
                "activated_resource_names": [
                    "classpath:config/exact.xml", "", None,
                ],
                "methods": [],
            }
            current_side = {"runtime_profile": {
                "business_entrypoint_profile": profile,
                "loader_topology": {
                    "entrypoint_realms": ["app", "dep"],
                    "realms": [],
                },
                "container_and_launcher_kind": "custom",
            }}
            artifacts = [
                {"path": str(business_path), "path_kind": "business"},
                {"path": str(dependency_path), "path_kind": "dependency"},
            ]
            instructions = [
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 0,
                 "invokevirtual", constructor_comment),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 1,
                 "invokespecial", "Method wrong/Owner.<init>:()V"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 2,
                 "invokespecial", f"Method {adapter_owner}.other:()V"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 3,
                 "invokespecial", f"Method {adapter_owner}.<init>:()V"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 4,
                 "ldc", "not-a-string"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 5,
                 "ldc", "String ignored"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 6,
                 "ldc_w", "String receive"),
                ("biz/Factory", "listener", "(Ldep/Receiver;)V", 7,
                 "invokespecial", constructor_comment),
                ("biz/Factory", "ambiguous", "(Ldep/Ambiguous;)V", 0,
                 "ldc", "String receive"),
                ("biz/Factory", "ambiguous", "(Ldep/Ambiguous;)V", 1,
                 "invokespecial", constructor_comment),
                ("biz/Factory", "primitive", "(I)V", 0,
                 "ldc", "String receive"),
                ("biz/Factory", "primitive", "(I)V", 1,
                 "invokespecial", constructor_comment),
                ("biz/Factory", "noParameters", "()V", 0,
                 "ldc", "String receive"),
                ("biz/Factory", "noParameters", "()V", 1,
                 "invokespecial", constructor_comment),
                ("biz/Factory", "missingReceiver", "(Ldep/Missing;)V", 0,
                 "ldc", "String receive"),
                ("biz/Factory", "missingReceiver", "(Ldep/Missing;)V", 1,
                 "invokespecial", constructor_comment),
                ("dep/Factory", "listener", "(Ldep/Receiver;)V", 0,
                 "ldc", "String receive"),
                ("dep/Factory", "listener", "(Ldep/Receiver;)V", 1,
                 "invokespecial", constructor_comment),
                ("biz/NoCallback", "factory", "(Ldep/Receiver;)V", 0,
                 "invokespecial", constructor_comment),
                ("biz/NotReady", "factory", "(Ldep/Receiver;)V", 0,
                 "ldc", "String receive"),
                ("biz/NotReady", "factory", "(Ldep/Receiver;)V", 1,
                 "invokespecial", constructor_comment),
                ("missing/Factory", "factory", "(Ldep/Receiver;)V", 0,
                 "ldc", "String receive"),
                ("missing/Factory", "factory", "(Ldep/Receiver;)V", 1,
                 "invokespecial", constructor_comment),
            ]

            class InstructionBatches:
                def iter_batches(self):
                    return iter(([], instructions[:9], instructions[9:]))

            exact_facts = [
                ["mybatis_plugin_registration", "dep.Plugin"],
                ["mybatis_type_handler_registration", "java|dep.Handler"],
                ["mybatis_statement_type_handler", "stmt|dep.Handler"],
                ["mybatis_plugin_registration", ""],
                ["spring_init_method", "bean|dep.XmlTarget|init"],
                ["spring_scheduled_method", ""],
                ["spring_scheduled_method", "one|two"],
                ["spring_scheduled_method", "bean||run"],
                ["spring_scheduled_method", "bean|dep.XmlTarget|"],
                ["spring_scheduled_method", "bean|dep.AmbigTarget|run"],
                ["spring_quartz_method", "bean|dep.Missing|run"],
                ["unknown", "ignored"],
                [None, None],
            ]
            resource_truth = [
                {"name": "ordinary.txt", "realm": "app", "selected": []},
                {
                    "name": "config/exact.xml", "realm": "app",
                    "selected": [
                        {"semantic_facts": exact_facts}, {},
                    ],
                },
                {
                    "name": "config/other.xml", "realm": "dep",
                    "selected": [{"semantic_facts": [
                        ["mybatis_plugin_registration", "dep.Plugin"],
                        ["spring_init_method", "bean|dep.XmlTarget|init"],
                    ]}],
                },
                {
                    "name": "config/annotated.xml", "realm": "app",
                    "selected": [{"semantic_facts": [
                        ["spring_init_method", "bean|dep.XmlTarget|init"],
                    ]}],
                },
                {"name": "empty.xml", "realm": "app", "selected": []},
                {"realm": "", "selected": [{}]},
            ]
            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows", return_value=iter(()),
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value",
                    side_effect=lambda _generation, _filename, key: (
                        [] if key == "coverage_gaps" else None
                    ),
                ),
            ):
                issues, truth = oracle._validate_entrypoint_discovery(
                    root, current_side, artifacts, observations,
                    resource_truth, [], InstructionBatches(),
                )

            # Exercise the non-batched instruction contract and an inactive
            # Spring runtime with an otherwise valid adapter registration.
            inactive_side = {"runtime_profile": {
                "business_entrypoint_profile": {"methods": []},
                "loader_topology": {"entrypoint_realms": ["app"]},
                "container_and_launcher_kind": "custom",
            }}
            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows", return_value=iter(()),
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value",
                    side_effect=lambda _generation, _filename, key: (
                        [] if key == "coverage_gaps" else "complete"
                    ),
                ),
            ):
                oracle._validate_entrypoint_discovery(
                    root, inactive_side, artifacts, observations,
                    [], [], instructions[4:8],
                )

        self.assertEqual(
            {item["reason_code"] for item in issues},
            {"ORACLE_ENTRYPOINT_SET_MISMATCH"},
        )
        exact_rows = {tuple(row) for row in truth["exact_entrypoints"]}
        exact_reasons = {row[6] for row in exact_rows}
        self.assertIn(
            "spring_message_listener_adapter_registration", exact_reasons,
        )
        self.assertIn("mybatis_resource_registration", exact_reasons)
        self.assertIn("spring_import_resource_activation", exact_reasons)
        self.assertGreater(truth["oracle_candidate_entrypoint_count"], 0)
        self.assertTrue(any(
            gap.startswith("resource_import:")
            for gap in truth["candidate_activation_gaps"]
        ))

    def test_entrypoint_profile_fallback_manifest_and_direct_activation_matrix(self):
        def sidecar_context(actual=(), gaps=(), status=None):
            return (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    return_value=iter(actual),
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value",
                    side_effect=lambda _generation, _filename, key: (
                        list(gaps) if key == "coverage_gaps" else status
                    ),
                ),
            )

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            with sidecar_context()[0], sidecar_context()[1]:
                baseline_issues, baseline_truth = (
                    oracle._validate_entrypoint_discovery(
                        root, {}, [], {}, [], [], [],
                    )
                )
            self.assertEqual(baseline_issues, [])
            self.assertEqual(baseline_truth["exact_entrypoint_count"], 0)

            invalid_gaps = {
                "entrypoint_discovery_coverage_gaps_invalid",
                "entrypoint_profile_invalid",
            }
            invalid_side = {"runtime_profile": {
                "business_entrypoint_profile": "invalid-profile",
                "entrypoint_discovery_coverage_gaps": {"invalid": True},
                "loader_topology": {
                    "realms": [
                        {"identity": "platform", "kind": "platform"},
                        {"identity": "fallback", "kind": "url"},
                        {"identity": None, "kind": "url"},
                    ],
                    "entrypoint_realms": [],
                },
            }}
            invalid_patches = sidecar_context(gaps=invalid_gaps, status=None)
            with invalid_patches[0], invalid_patches[1]:
                invalid_issues, _ = oracle._validate_entrypoint_discovery(
                    root, invalid_side, [], {}, [], [], [],
                )
            self.assertEqual(invalid_issues, [])

            business_jar = root / "business.jar"
            dependency_jar = root / "dependency.jar"
            for path, main_class in (
                (business_jar, "manifest.Main"),
                (dependency_jar, "ignored.DependencyMain"),
            ):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("META-INF/", b"")
                    archive.writestr("other.txt", b"ignored")
                    archive.writestr(
                        "META-INF/MANIFEST.MF",
                        (
                            "Manifest-Version: 1.0\r\n"
                            f"Main-Class: {main_class}\r\n"
                            "Start-Class: manifest.Start\r\n\r\n"
                        ).encode(),
                    )

            def ready(path, class_name):
                return {
                    "status": "definition_ready",
                    "provider_url": path.as_uri(),
                    "modifiers": 1,
                    "super_name": "java/lang/Object",
                    "interfaces": [],
                    "class_annotations": [],
                    "members": [
                        "method|main|([Ljava/lang/String;)V|9",
                        f"method|{class_name.rsplit('/', 1)[-1]}|()V|1",
                    ],
                }

            manifest_observations = {
                "manifest/Main": ready(business_jar, "manifest/Main"),
                "manifest/Start": ready(business_jar, "manifest/Start"),
                "ignored/DependencyMain": ready(
                    dependency_jar, "ignored/DependencyMain",
                ),
            }
            manifest_side = {"runtime_profile": {
                "business_entrypoint_profile": {
                    "activated_frameworks": ["spring_boot"],
                    "methods": [],
                },
                "container_and_launcher_kind": "java-jar",
                "loader_topology": {"entrypoint_realms": ["app"]},
            }}
            manifest_patches = sidecar_context(status="complete")
            with manifest_patches[0], manifest_patches[1]:
                manifest_issues, manifest_truth = (
                    oracle._validate_entrypoint_discovery(
                        root, manifest_side,
                        [
                            {
                                "path": str(dependency_jar),
                                "path_kind": "dependency",
                            },
                            {
                                "path": str(business_jar),
                                "path_kind": "business_classes",
                            },
                        ],
                        manifest_observations, [], [], [],
                    )
                )
            self.assertIn(
                "ORACLE_ENTRYPOINT_SET_MISMATCH",
                {item["reason_code"] for item in manifest_issues},
            )
            self.assertTrue(any(
                row[1] == "manifest/Main" and row[2] == "main"
                for row in manifest_truth["exact_entrypoints"]
            ))

            caller_observation = ready(business_jar, "biz/Caller")
            caller_observation["members"] = ["method|launch|()V|1"]
            direct_observations = {
                "biz/Caller": caller_observation,
                "biz/Main": ready(business_jar, "biz/Main"),
            }
            direct_profile = {
                "main_class": "biz.Main",
                "activated_frameworks": [],
                "methods": [{
                    "class_name": "biz.Caller",
                    "member_name": "launch", "descriptor": "()V",
                }],
            }
            direct_side = {"runtime_profile": {
                "business_entrypoint_profile": direct_profile,
                "container_and_launcher_kind": "custom",
                "loader_topology": {"entrypoint_realms": ["app"]},
            }}
            service_descriptor = "([Ljava/lang/String;)V"
            edges = [
                ("short", "edge", "()V"),
                (
                    "biz.Caller", "launch", "()V", "other.Owner", "run",
                    service_descriptor, "invokestatic", 1, "field",
                ),
                (
                    "biz.Caller", "launch", "()V", "other.Owner", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "biz.Caller", "launch", "()V",
                    "org.springframework.boot.SpringApplication", "other",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "missing.Caller", "launch", "()V",
                    "org.springframework.boot.SpringApplication", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "biz.Caller", "notDeclared", "()V",
                    "org.springframework.boot.SpringApplication", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "biz.Main", "notMain", "()V",
                    "org.springframework.boot.SpringApplication", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "biz.Main", "main", "()V",
                    "org.springframework.boot.SpringApplication", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
                (
                    "biz.Caller", "launch", "()V",
                    "org.springframework.boot.SpringApplication", "run",
                    service_descriptor, "invokestatic", 1, "method",
                ),
            ]
            auto_resource = [{
                "name": (
                    "META-INF/spring/org.springframework.boot.autoconfigure."
                    "AutoConfiguration.imports"
                ),
                "selected": [{"semantic_facts": [
                    ["ordered_entry", "biz.Caller"],
                ]}],
            }]
            direct_patches = sidecar_context(status="complete")
            with direct_patches[0], direct_patches[1]:
                direct_issues, direct_truth = (
                    oracle._validate_entrypoint_discovery(
                        root, direct_side,
                        [{"path": str(business_jar), "path_kind": "application"}],
                        direct_observations, auto_resource, edges, [],
                    )
                )
            self.assertIn(
                "ORACLE_ENTRYPOINT_SET_MISMATCH",
                {item["reason_code"] for item in direct_issues},
            )
            self.assertGreater(direct_truth["exact_entrypoint_count"], 0)

            no_match_patches = sidecar_context(status="complete")
            with no_match_patches[0], no_match_patches[1]:
                no_match_issues, no_match_truth = (
                    oracle._validate_entrypoint_discovery(
                        root, direct_side,
                        [{"path": str(business_jar), "path_kind": "application"}],
                        direct_observations, auto_resource, edges[:-1], [],
                    )
                )
            self.assertEqual(
                {item["reason_code"] for item in no_match_issues},
                {"ORACLE_ENTRYPOINT_SET_MISMATCH"},
            )
            self.assertEqual(
                {row[6] for row in no_match_truth["exact_entrypoints"]},
                {
                    "runtime_profile_declaration",
                    "business_final_artifact_runtime_trigger",
                },
            )

            launcher_side = {"runtime_profile": {
                "business_entrypoint_profile": {"methods": []},
                "container_and_launcher_kind": "spring-boot",
                "loader_topology": {"entrypoint_realms": []},
            }}
            launcher_patches = sidecar_context(status="complete")
            with launcher_patches[0], launcher_patches[1]:
                oracle._validate_entrypoint_discovery(
                    root, launcher_side, [], {}, [], [], [],
                )

    def test_closed_world_empty_projection_public_surface_matrix(self):
        summary_fields = {
            "authoritative_change_fact_count": 0,
            "formal_projection_count": 0,
            "formal_trace_result_count": 0,
            "unique_reported_api_total": 0,
            "reachable_total": 0,
            "uncertain_total": 0,
            "not_found_in_static_analysis_total": 0,
            "not_analyzed_total": 0,
            "probable_impact_total": 0,
        }
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            csv_path = generation / "binary_formal_results.csv"

            nonempty_records = {
                ("binary_projections.json", "formal_projections"): [],
                ("binary_formal_results.json", "results"): [
                    {"projection_identity": ""},
                    {"projection_identity": "projection-extra"},
                ],
                ("binary_formal_results.json", "by_api"): [
                    {"reported_api_identity": ""},
                    {"reported_api_identity": "api-extra"},
                ],
                ("binary_decisions.json", "authoritative_change_facts"): [
                    {}, {},
                ],
            }

            def rows_for(records):
                return lambda _generation, filename, key, **_kwargs: iter(
                    records[(filename, key)]
                )

            csv_path.write_text(
                "reported_api_identity,display_owner\napi-extra,demo.Api\n",
                encoding="utf-8-sig",
            )
            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=rows_for(nonempty_records),
                ),
                patch.object(oracle, "_load_json", return_value={}),
            ):
                issues, truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                    )
                )
            self.assertEqual({
                "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
                "ORACLE_API_AGGREGATION_MISMATCH",
                "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
                "ORACLE_SUMMARY_AGGREGATION_MISMATCH",
            }, {item["reason_code"] for item in issues})
            self.assertEqual(truth["formal_result_count"], 2)
            self.assertFalse(truth["formal_identity_set_closed"])

            empty_records = {
                ("binary_projections.json", "formal_projections"): [],
                ("binary_formal_results.json", "results"): [],
                ("binary_formal_results.json", "by_api"): [],
                ("binary_decisions.json", "authoritative_change_facts"): [],
            }
            csv_path.write_text(
                "reported_api_identity\n", encoding="utf-8-sig",
            )
            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=rows_for(empty_records),
                ),
                patch.object(
                    oracle, "_load_json", return_value=summary_fields,
                ),
            ):
                issues, truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                    )
                )
            self.assertEqual(issues, [])
            self.assertTrue(truth["formal_identity_set_closed"])
            self.assertEqual(
                truth["reachability_rebuild_status"],
                "not_required_no_formal_projections",
            )

    def test_closed_world_legacy_graph_path_and_aggregation_matrix(self):
        exact_scope = {
            "initiating_loader_realm_identity": "app",
            "class_name": "demo.Api",
            "member_kind": "method",
            "member_name": "run",
            "descriptor": "()V",
        }

        def decision(identity, change, scope, gaps=(), artifacts=()):
            return {
                "decision_identity": identity,
                "change_fact_identity": change,
                "fact_kind": "method",
                "fact_scope": scope,
                "coverage_gaps": list(gaps),
                "dependency_artifacts": list(artifacts),
            }

        decisions = [
            {},
            decision(
                "d-exact", "c-exact", exact_scope,
                artifacts=[
                    {"coord": "g:base", "side": "base"},
                    {"coord": "g:current", "side": "current"},
                    {"coord": "", "side": "base"},
                    {"coord": "g:ignored", "side": "other"},
                    {},
                ],
            ),
            decision("d-uncertain", "c-uncertain", {
                **exact_scope, "class_name": "demo.Uncertain",
            }),
            decision(
                "d-notfound", "c-notfound", None,
            ),
            decision("d-gap", "c-gap", {
                **exact_scope, "class_name": "demo.Gap",
            }, gaps=["decision-gap"]),
        ]
        projections = [
            {},
            *[
                {
                    "projection_identity": projection_id,
                    "projection_assessment_identity": assessment_id,
                }
                for projection_id, assessment_id in (
                    ("p-missing", "a-missing"),
                    ("p-exact2", "a-exact2"),
                    ("p-exact", "a-exact"),
                    ("p-uncertain", "a-uncertain"),
                    ("p-notfound", "a-notfound"),
                    ("p-gap", "a-gap"),
                    ("p-bad-change", "a-bad-change"),
                    ("p-no-result", "a-no-result"),
                )
            ],
        ]
        assessments = [
            {},
            {"projection_assessment_identity": "a-missing", "decision_identity": "absent-decision"},
            {"projection_assessment_identity": "a-exact2", "decision_identity": "d-exact"},
            {"projection_assessment_identity": "a-exact", "decision_identity": "d-exact"},
            {"projection_assessment_identity": "a-uncertain", "decision_identity": "d-uncertain"},
            {"projection_assessment_identity": "a-notfound", "decision_identity": "d-notfound"},
            {"projection_assessment_identity": "a-gap", "decision_identity": "d-gap"},
            {"projection_assessment_identity": "a-bad-change", "decision_identity": "d-exact"},
            {"projection_assessment_identity": "a-no-result", "decision_identity": "d-exact"},
        ]

        legacy_transitions = {
            "root-exact": [
                ("target-exact", "exact", "e1"),
                ("target-possible", "possible", "e-possible-direct"),
                ("root-exact", "exact", "e-cycle"),
            ],
            "target-exact": [
                ("target-deep", "exact", "e-deep"),
                ("target-possible", "possible", "e2"),
            ],
            "root-possible": [
                ("target-from-possible", "exact", "e3"),
            ],
        }
        legacy_relations = {
            "e1": [
                ("root-exact", "target-exact", "exact"),
                ("wrong-caller", "ignored", "possible"),
            ],
            "e2": [("target-exact", "target-possible", "possible")],
            "e3": [("root-possible", "target-from-possible", "exact")],
            "e-empty": [("root-exact", "nowhere", "exact")],
        }
        legacy_resolutions = {
            "e1": {"member_resolution_status": "resolved"},
            "e2": {"member_resolution_status": "unresolved"},
            "e-empty": {"member_resolution_status": ""},
        }
        legacy_linkages = {
            "e1": {"linkage_status": "linked"},
            "e2": {"linkage_status": "incompatible"},
            "e-empty": {"linkage_status": ""},
        }

        def path(entrypoint, targets, edges, certainty, *, identity=True):
            entrypoint_records = [
                {}, {"entrypoint_record_identity": "entry-record"},
            ]
            result = {
                "entrypoint_member_identity": entrypoint,
                "entrypoint_records": entrypoint_records,
                "edges": [
                    ({"direct_edge_identity": value} if value else {})
                    for value in edges
                ],
                "path_certainty": certainty,
            }
            result["path_identity"] = (
                oracle._identity("binary_trace_path_identity", {
                    "entrypoint_member_identity": entrypoint,
                    "entrypoint_record_identities": [
                        row.get("entrypoint_record_identity")
                        for row in entrypoint_records
                    ],
                    "target_nodes": list(targets),
                    "edge_identities": list(edges),
                    "path_certainty": certainty,
                })
                if identity else "wrong-path-identity"
            )
            return result

        def formal_result(
            projection_id, change_id, targets, status, *, exact=False,
            paths=(), member_statuses=(), linkage_statuses=(), complete=True,
            runtime_profile="runtime-profile", correct_identity=True,
        ):
            result = {
                "projection_identity": projection_id,
                "change_fact_identity": change_id,
                "runtime_profile_identity": runtime_profile,
                "target_nodes": list(targets),
                "reachability_status": status,
                "analysis_status": status,
                "is_reachable": exact,
                "impact_conclusion": (
                    "probable_impact" if exact else "inconclusive"
                ),
                "decision_bucket": (
                    "probable_impact" if exact else "inconclusive"
                ),
                "runtime_verification_status": (
                    "required_not_executed" if exact else "undetermined"
                ),
                "runtime_verification_executed_by_system": False,
                "exact_path_exists": exact,
                "possible_path_exists": status in {"reachable", "uncertain"},
                "path_set_complete": complete,
                "paths": list(paths),
                "member_resolution_statuses": list(member_statuses),
                "linkage_resolution_statuses": list(linkage_statuses),
            }
            result["trace_result_identity"] = (
                oracle._identity(
                    "binary_trace_result_identity", dict(result),
                ) if correct_identity else "wrong-result-identity"
            )
            return result

        exact_targets = ["target-exact", ""]
        exact_path = path("root-exact", exact_targets, ["e1"], "exact")
        possible_targets = ["target-possible", "target-from-possible"]
        possible_path = path(
            "root-exact", possible_targets, ["e1", "e2"], "possible",
        )
        possible_root_path = path(
            "root-possible", possible_targets, ["e3"], "possible",
        )
        results = [
            {
                "projection_identity": "p-missing",
            },
            formal_result(
                "p-exact2", "c-exact", ["target-exact"],
                "not_analyzed", complete=False,
                runtime_profile="runtime-profile", correct_identity=False,
            ),
            formal_result(
                "p-exact", "c-exact", exact_targets, "reachable",
                exact=True, paths=[exact_path], member_statuses=["resolved"],
                linkage_statuses=["linked"],
            ),
            formal_result(
                "p-uncertain", "c-uncertain", possible_targets, "uncertain",
                paths=[possible_path, possible_root_path],
                member_statuses=["resolved", "unresolved"],
                linkage_statuses=["incompatible", "linked"],
            ),
            formal_result(
                "p-notfound", "c-notfound", [],
                "not_found_in_static_analysis",
                paths=[
                    path("root-exact", [], ["e-empty"], "exact", identity=False),
                ],
            ),
            formal_result(
                "p-gap", "c-gap", ["absent"], "not_analyzed",
                complete=False,
                paths=[
                    path("", ["absent"], [""], "possible", identity=False),
                    path("root-exact", ["absent"], ["e-empty"], "possible", identity=False),
                ],
                member_statuses=["wrong"], linkage_statuses=["wrong"],
                correct_identity=False,
            ),
            {
                "projection_identity": "p-bad-change",
                "change_fact_identity": "c-other",
                "runtime_profile_identity": "runtime-profile",
            },
            {
                "change_fact_identity": "c-exact",
                "runtime_profile_identity": "runtime-profile",
                "path_set_complete": True,
            },
        ]
        next(
            item for item in results
            if item.get("projection_identity") == "p-notfound"
        ).pop("reachability_status")
        entrypoint_rows = [
            {"member_identity": "root-exact", "path_certainty": "exact"},
            {"member_identity": "root-possible", "path_certainty": "possible"},
            {"member_identity": "root-exact", "path_certainty": "possible"},
            {"path_certainty": "other"},
        ]
        records = {
            ("binary_projections.json", "formal_projections"): projections,
            ("binary_entrypoints.json", "records"): entrypoint_rows,
            ("binary_decisions.json", "authoritative_change_facts"): decisions,
            ("binary_projections.json", "authoritative_projection_assessments"): assessments,
            ("binary_decisions.json", "diagnostic_candidate_facts"): [
                {}, {"coverage_gaps": ["diagnostic-gap"]},
            ],
            ("binary_formal_results.json", "results"): results,
        }
        known_api_identity = oracle._identity("reported_api_identity", {
            "analysis_context_identity": "analysis-context",
            "current_runtime_profile_identity": "runtime-profile",
            "class_name": "demo.Api",
            "member_kind": "method",
            "member_name": "run",
            "descriptor": "()V",
            "grouping_rule_version": "binary-reported-api-v2",
        })
        api_rows = [
            {
                "reported_api_identity": known_api_identity,
                "display_owner": "demo.Api",
                "display_member": "wrong",
            },
            {"reported_api_identity": "unexpected-api"},
            {},
        ]
        records[("binary_formal_results.json", "by_api")] = api_rows
        top_values = {
            ("binary_entrypoints.json", "coverage_gaps"): [],
            ("binary_runtime_semantic_overlay.json", "coverage_gaps"):
                ["semantic-gap"],
            ("binary_decisions.json", "analysis_context_identity"):
                "analysis-context",
        }

        def rows(_generation, filename, key, **_kwargs):
            return iter(records[(filename, key)])

        def top(_generation, filename, key):
            return top_values[(filename, key)]

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            ordered_fields = (
                "display_descriptor", "display_member", "display_owner",
                "impact_conclusion", "reachability_status",
                "runtime_verification_status",
            )
            header = "reported_api_identity," + ",".join(ordered_fields)
            generation.joinpath("binary_formal_results.csv").write_text(
                header + "\n"
                + f"{known_api_identity},,csv-wrong,demo.Api,,,\n"
                + "unexpected-api,,,,,,\n"
                + ",,,,,,\n",
                encoding="utf-8-sig",
            )

            def load_json(path):
                if path.name == "binary_coverage.json":
                    return {"trace_coverage_gaps": [
                        "semantic-gap", "decision-gap", "diagnostic-gap",
                        "trace_path_enumeration_limit_exceeded",
                        "trace_node_limit_exceeded",
                    ]}
                if path.name == "binary_runtime_semantic_overlay.json":
                    return {"rows": []}
                if path.name == "binary_summary.json":
                    return {}
                raise AssertionError(path)

            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows", side_effect=rows,
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value", side_effect=top,
                ),
                patch.object(oracle, "_load_json", side_effect=load_json),
                patch.object(
                    oracle, "_validated_empty_entrypoint_set",
                    return_value=False,
                ),
                patch.object(
                    oracle, "_load_closed_world_graph",
                    return_value=(
                        legacy_transitions, legacy_relations,
                        legacy_resolutions, legacy_linkages,
                    ),
                ),
            ):
                issues, truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                        entrypoint_validation_issues=[{"reason_code": "fixture"}],
                        entrypoint_truth={"fixture": True},
                    )
                )

        reason_codes = {item["reason_code"] for item in issues}
        self.assertTrue({
            "ORACLE_FORMAL_RESULT_DECISION_BINDING_MISMATCH",
            "ORACLE_TRACE_PATH_ENTRYPOINT_MISMATCH",
            "ORACLE_TRACE_PATH_CONTINUITY_MISMATCH",
            "ORACLE_TRACE_PATH_CERTAINTY_MISMATCH",
            "ORACLE_TRACE_PATH_IDENTITY_MISMATCH",
            "ORACLE_FORMAL_STATE_MISMATCH",
            "ORACLE_FORMAL_RESULT_IDENTITY_MISMATCH",
            "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
            "ORACLE_API_AGGREGATION_MISMATCH",
            "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
            "ORACLE_SUMMARY_AGGREGATION_MISMATCH",
        }.issubset(reason_codes), reason_codes)
        self.assertEqual(truth["reachability_rebuild_status"], "completed_full_graph")
        self.assertGreaterEqual(truth["exact_reachable_node_count"], 3)
        self.assertGreater(
            truth["possible_reachable_node_count"],
            truth["exact_reachable_node_count"],
        )

    def test_closed_world_valid_empty_root_and_indexed_graph_matrix(self):
        scope = {
            "initiating_loader_realm_identity": "app",
            "class_name": "demo.Empty",
            "member_kind": "method",
            "member_name": "run",
            "descriptor": "()V",
        }
        decision = {
            "decision_identity": "decision",
            "change_fact_identity": "change",
            "fact_kind": "method",
            "fact_scope": scope,
            "coverage_gaps": [],
            "dependency_artifacts": [
                {"coord": "g:base", "side": "base"},
                {"coord": "g:current", "side": "current"},
            ],
        }
        projection = {
            "projection_identity": "projection",
            "projection_assessment_identity": "assessment",
        }
        assessment = {
            "projection_assessment_identity": "assessment",
            "decision_identity": "decision",
        }
        result = {
            "projection_identity": "projection",
            "change_fact_identity": "change",
            "runtime_profile_identity": "runtime-profile",
            "target_nodes": [],
            "reachability_status": "not_found_in_static_analysis",
            "analysis_status": "not_found_in_static_analysis",
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "decision_bucket": "inconclusive",
            "runtime_verification_status": "undetermined",
            "runtime_verification_executed_by_system": False,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "path_set_complete": True,
            "paths": [],
            "member_resolution_statuses": [],
            "linkage_resolution_statuses": [],
        }
        result["trace_result_identity"] = oracle._identity(
            "binary_trace_result_identity", dict(result),
        )
        api_identity = oracle._identity("reported_api_identity", {
            "analysis_context_identity": "analysis-context",
            "current_runtime_profile_identity": "runtime-profile",
            "class_name": scope["class_name"],
            "member_kind": scope["member_kind"],
            "member_name": scope["member_name"],
            "descriptor": scope["descriptor"],
            "grouping_rule_version": "binary-reported-api-v2",
        })
        api_row = {
            "reported_api_identity": api_identity,
            "display_owner": "demo.Empty",
            "display_member": "run",
            "display_descriptor": "()V",
            "display_member_kind": "method",
            "initiating_loader_realms": ["app"],
            "reachability_status": "not_found_in_static_analysis",
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "runtime_verification_status": "undetermined",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": True,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "contributing_projection_ids": ["projection"],
            "contributing_change_fact_ids": ["change"],
            "base_dependency_coords": ["g:base"],
            "current_dependency_coords": ["g:current"],
        }
        summary = {
            "authoritative_change_fact_count": 1,
            "formal_projection_count": 1,
            "formal_trace_result_count": 1,
            "unique_reported_api_total": 1,
            "reachable_total": 0,
            "uncertain_total": 0,
            "not_found_in_static_analysis_total": 1,
            "not_analyzed_total": 0,
            "probable_impact_total": 0,
        }
        records = {
            ("binary_projections.json", "formal_projections"): [projection],
            ("binary_entrypoints.json", "records"): [],
            ("binary_decisions.json", "authoritative_change_facts"): [decision],
            ("binary_projections.json", "authoritative_projection_assessments"):
                [assessment],
            ("binary_decisions.json", "diagnostic_candidate_facts"): [],
            ("binary_formal_results.json", "results"): [result],
            ("binary_formal_results.json", "by_api"): [api_row],
        }
        top_values = {
            ("binary_entrypoints.json", "coverage_gaps"): [],
            ("binary_runtime_semantic_overlay.json", "coverage_gaps"): [],
            ("binary_decisions.json", "analysis_context_identity"):
                "analysis-context",
        }

        def rows(_generation, filename, key, **_kwargs):
            return iter(records[(filename, key)])

        def top(_generation, filename, key):
            return top_values[(filename, key)]

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            generation.joinpath("binary_formal_results.csv").write_text(
                (
                    "reported_api_identity,display_descriptor,display_member,"
                    "display_owner,impact_conclusion,reachability_status,"
                    "runtime_verification_status\n"
                    f"{api_identity},()V,run,demo.Empty,inconclusive,"
                    "not_found_in_static_analysis,undetermined\n"
                ),
                encoding="utf-8-sig",
            )

            def load_json(path):
                if path.name == "binary_coverage.json":
                    return {"trace_coverage_gaps": []}
                if path.name == "binary_summary.json":
                    return summary
                raise AssertionError(path)

            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows", side_effect=rows,
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value", side_effect=top,
                ),
                patch.object(oracle, "_load_json", side_effect=load_json),
                patch.object(
                    oracle, "_validated_empty_entrypoint_set",
                    return_value=True,
                ),
            ):
                issues, truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                    )
                )
            self.assertEqual(issues, [])
            self.assertTrue(truth["formal_identity_set_closed"])
            self.assertEqual(
                truth["reachability_rebuild_status"],
                "not_required_validated_empty_entrypoint_set",
            )

            class FakeGraphIndex:
                def __init__(self):
                    self.closed = False

                def transitions(self, caller):
                    return (
                        [("target", "exact", "edge")]
                        if caller == "root" else []
                    )

                def relations_for_evidence(self, evidence):
                    return (
                        [("root", "target", "exact")]
                        if evidence == "edge" else []
                    )

                def resolution_status(self, evidence):
                    return "resolved" if evidence == "edge" else ""

                def linkage_status(self, evidence):
                    return "linked" if evidence == "edge" else ""

                def close(self):
                    self.closed = True

            fake_index = FakeGraphIndex()
            indexed_path = {
                "entrypoint_member_identity": "root",
                "entrypoint_records": [],
                "edges": [{"direct_edge_identity": "edge"}],
                "path_certainty": "exact",
            }
            indexed_path["path_identity"] = oracle._identity(
                "binary_trace_path_identity", {
                    "entrypoint_member_identity": "root",
                    "entrypoint_record_identities": [],
                    "target_nodes": ["target"],
                    "edge_identities": ["edge"],
                    "path_certainty": "exact",
                },
            )
            indexed_result = {
                **result,
                "target_nodes": ["target"],
                "reachability_status": "reachable",
                "analysis_status": "reachable",
                "is_reachable": True,
                "impact_conclusion": "probable_impact",
                "decision_bucket": "probable_impact",
                "runtime_verification_status": "required_not_executed",
                "exact_path_exists": True,
                "possible_path_exists": True,
                "paths": [indexed_path],
                "member_resolution_statuses": ["resolved"],
                "linkage_resolution_statuses": ["linked"],
            }
            indexed_result.pop("trace_result_identity", None)
            indexed_result["trace_result_identity"] = oracle._identity(
                "binary_trace_result_identity", dict(indexed_result),
            )
            indexed_records = dict(records)
            indexed_records[("binary_entrypoints.json", "records")] = [{
                "member_identity": "root", "path_certainty": "exact",
            }]
            indexed_records[("binary_formal_results.json", "results")] = [
                indexed_result,
            ]
            indexed_records[("binary_formal_results.json", "by_api")] = []
            generation.joinpath("current_binary_facts.sqlite").touch()
            generation.joinpath("binary_formal_results.csv").write_text(
                "reported_api_identity\nextra-csv-identity\n",
                encoding="utf-8-sig",
            )

            def indexed_rows(_generation, filename, key, **_kwargs):
                return iter(indexed_records[(filename, key)])

            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=indexed_rows,
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value", side_effect=top,
                ),
                patch.object(oracle, "_load_json", side_effect=load_json),
                patch.object(
                    oracle, "_validated_empty_entrypoint_set",
                    return_value=False,
                ),
                patch.object(
                    oracle, "_closed_world_decision_aliases",
                    return_value=({"missing"}, {"edge": "alias"}),
                ) as aliases,
                patch.object(
                    oracle, "_ClosedWorldGraphIndex",
                    return_value=fake_index,
                ) as graph_constructor,
            ):
                indexed_issues, indexed_truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                    )
                )
            aliases.assert_called_once_with(generation)
            graph_constructor.assert_called_once()
            self.assertTrue(fake_index.closed)
            self.assertEqual(
                indexed_truth["reachability_rebuild_status"],
                "completed_full_graph",
            )
            self.assertIn(
                "ORACLE_API_AGGREGATION_MISMATCH",
                {item["reason_code"] for item in indexed_issues},
            )

            invalid_records = dict(records)
            invalid_records[("binary_formal_results.json", "by_api")] = []

            def invalid_rows(_generation, filename, key, **_kwargs):
                return iter(invalid_records[(filename, key)])

            for invalid_key in ("entrypoint", "semantic"):
                invalid_top = dict(top_values)
                invalid_top[
                    (
                        "binary_entrypoints.json"
                        if invalid_key == "entrypoint"
                        else "binary_runtime_semantic_overlay.json"
                    ),
                    "coverage_gaps",
                ] = {}
                with (
                    patch.object(
                        oracle, "_iter_sidecar_object_rows",
                        side_effect=invalid_rows,
                    ),
                    patch.object(
                        oracle, "_sidecar_top_level_value",
                        side_effect=lambda _g, filename, key, values=invalid_top: (
                            values[(filename, key)]
                        ),
                    ),
                    patch.object(
                        oracle, "_validated_empty_entrypoint_set",
                        return_value=True,
                    ),
                    patch.object(
                        oracle, "_load_json",
                        return_value={"trace_coverage_gaps": []},
                    ),
                ):
                    with self.assertRaises(oracle.BinaryValidationError) as raised:
                        oracle._validate_closed_world_results_in_workspace(
                            generation, graph_directory=generation / "graph",
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_VALIDATION_JSON_INVALID",
                )

            zero_records = {
                ("binary_projections.json", "formal_projections"): [projection],
                ("binary_entrypoints.json", "records"): [],
                ("binary_decisions.json", "authoritative_change_facts"): [],
                ("binary_projections.json", "authoritative_projection_assessments"):
                    [],
                ("binary_decisions.json", "diagnostic_candidate_facts"): [],
                ("binary_formal_results.json", "results"): [],
                ("binary_formal_results.json", "by_api"): [],
            }
            zero_top = {
                ("binary_entrypoints.json", "coverage_gaps"): [],
                ("binary_runtime_semantic_overlay.json", "coverage_gaps"): [],
                ("binary_decisions.json", "analysis_context_identity"): None,
            }
            zero_summary = {
                "current_runtime_profile_identity": "summary-runtime-profile",
                "authoritative_change_fact_count": 0,
                "formal_projection_count": 1,
                "formal_trace_result_count": 0,
                "unique_reported_api_total": 0,
                "reachable_total": 0,
                "uncertain_total": 0,
                "not_found_in_static_analysis_total": 0,
                "not_analyzed_total": 0,
                "probable_impact_total": 0,
            }
            generation.joinpath("binary_formal_results.csv").write_text(
                "reported_api_identity\nextra-csv-identity\n",
                encoding="utf-8-sig",
            )

            def zero_rows(_generation, filename, key, **_kwargs):
                return iter(zero_records[(filename, key)])

            def zero_load(path):
                return (
                    {"trace_coverage_gaps": []}
                    if path.name == "binary_coverage.json" else zero_summary
                )

            with (
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=zero_rows,
                ),
                patch.object(
                    oracle, "_sidecar_top_level_value",
                    side_effect=lambda _g, filename, key: zero_top[(filename, key)],
                ),
                patch.object(oracle, "_load_json", side_effect=zero_load),
                patch.object(
                    oracle, "_validated_empty_entrypoint_set",
                    return_value=True,
                ),
            ):
                zero_issues, zero_truth = (
                    oracle._validate_closed_world_results_in_workspace(
                        generation, graph_directory=generation / "graph",
                    )
                )
            self.assertEqual(zero_truth["formal_result_count"], 0)
            self.assertTrue({
                "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
                "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
            }.issubset({item["reason_code"] for item in zero_issues}))

    def test_runtime_outcome_provider_and_definition_boundary_matrix(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE direct_edges (
                direct_edge_identity TEXT PRIMARY KEY,
                edge_kind TEXT NOT NULL,
                symbolic_owner TEXT NOT NULL,
                symbolic_name TEXT NOT NULL,
                symbolic_descriptor TEXT NOT NULL,
                opcode INTEGER
            );
            CREATE TABLE members (
                member_identity TEXT PRIMARY KEY,
                class_name TEXT NOT NULL,
                member_name TEXT NOT NULL,
                descriptor TEXT NOT NULL
            );
            """
        )
        self.addCleanup(connection.close)

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            jdk_home = root / "jdk"
            jdk_home.mkdir()
            (jdk_home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8",
            )
            runtime_archive = jdk_home / "jre" / "lib" / "rt.jar"
            artifact_path = root / "selected.jar"
            other_path = root / "other.jar"
            artifact_path.write_bytes(b"selected")
            other_path.write_bytes(b"other")

            def ready(location=None):
                result = {
                    "status": "definition_ready", "modifiers": 1,
                    "super_name": "", "interfaces": [], "members": [],
                }
                if location is not None:
                    result["provider_resource_url"] = location
                return result

            artifact_location = (
                f"jar:{artifact_path.as_uri()}!/demo/Provider.class"
            )
            observations = {
                "demo/MissingBinding": ready(),
                "demo/NoObservation": {},
                "demo/NoLocationResolved": {
                    **ready(),
                    "provider_resource_url": "<resource-error:denied>",
                    "provider_url": "<unknown>",
                },
                "demo/NoLocationMissing": ready(),
                "demo/PlatformWrong": ready("jrt:/java.base/demo/PlatformWrong.class"),
                "demo/PlatformGood": ready("jrt:/java.base/demo/PlatformGood.class"),
                "demo/Jdk8Good": ready(runtime_archive.as_uri()),
                "demo/ArtifactUnresolved": ready(artifact_location),
                "demo/ArtifactNoExpected": ready(other_path.as_uri()),
                "demo/ArtifactWrong": ready(artifact_location),
                "demo/ArtifactGoodMissingDefinition": ready(artifact_location),
                "demo/DefinitionStatusMismatch": ready(artifact_location),
                "demo/ClassLoadMismatch": ready(artifact_location),
                "demo/FailedGood": {
                    "status": "definition_failed",
                    "failure_phase": "class_load",
                    "provider_resource_url": artifact_location,
                    "modifiers": 0x0400,
                    "super_name": None,
                    "interfaces": ["demo/Marker"],
                    "members": [],
                },
                "demo/Skipped": {
                    "status": "not_found", "super_name": "demo/Base",
                    "interfaces": [], "members": [],
                },
            }
            contexts = [
                ("app", name) for name in observations
                if name != "demo/Skipped"
            ]
            provider_rows = []
            omitted = object()
            # Keep the selected identity absent for one row so the nullable
            # reconciliation evidence path is exercised without an invalid
            # BinaryFactStore row.
            def add_provider(name, status, selected=omitted):
                row = {
                    "initiating_loader_realm_identity": "app",
                    "class_name": name,
                    "class_provider_status": status,
                }
                if selected is not omitted:
                    row["selected_artifact_instance_identity"] = selected
                provider_rows.append(row)

            add_provider("demo/NoObservation", "missing")
            add_provider("demo/NoLocationResolved", "resolved")
            add_provider("demo/NoLocationMissing", "missing", None)
            add_provider("demo/PlatformWrong", "resolved", "artifact-instance")
            add_provider("demo/PlatformGood", "resolved", "platform-image:java.base")
            add_provider("demo/Jdk8Good", "resolved", "platform-image:jre")
            add_provider("demo/ArtifactUnresolved", "missing", None)
            add_provider("demo/ArtifactNoExpected", "resolved", "unexpected")
            add_provider("demo/ArtifactWrong", "resolved", "wrong-instance")
            add_provider(
                "demo/ArtifactGoodMissingDefinition", "resolved", "instance-good",
            )
            add_provider(
                "demo/DefinitionStatusMismatch", "resolved", "instance-good",
            )
            add_provider("demo/ClassLoadMismatch", "resolved", "instance-good")
            add_provider("demo/FailedGood", "resolved", "instance-good")

            definition_rows = []

            def definition(name, definition_status, load_status):
                definition_rows.append({
                    "initiating_loader_realm_identity": "app",
                    "class_name": name,
                    "class_definition_status": definition_status,
                    "class_load_status": load_status,
                })

            for name in (
                "demo/PlatformWrong", "demo/PlatformGood", "demo/Jdk8Good",
                "demo/ArtifactNoExpected", "demo/ArtifactWrong",
            ):
                definition(name, "definition_ready", "ready")
            definition("demo/DefinitionStatusMismatch", "definition_failed", "failed")
            definition("demo/ClassLoadMismatch", "definition_ready", "failed")
            definition("demo/FailedGood", "definition_failed", "failed")
            records = {
                "provider_binding": provider_rows,
                "class_definition": definition_rows,
                "member_resolution": [],
                "dispatch_resolution": [],
            }
            instance_by_location = {
                ("app", 0): "instance-good",
                ("duplicate", 1): "instance-other",
            }
            oracle_artifacts = [
                {
                    "loader_realm": "app", "slot": 0,
                    "path": str(artifact_path),
                },
                {
                    "loader_realm": "duplicate", "slot": 1,
                    "path": str(artifact_path),
                },
                {"path": str(other_path)},
            ]
            with (
                patch.object(
                    oracle, "_artifact_instance_bindings",
                    return_value=(instance_by_location, [{
                        "reason_code": "ORACLE_FIXTURE_BINDING_ISSUE",
                    }]),
                ),
                patch.object(
                    oracle, "_oracle_runtime_contexts", return_value=contexts,
                ),
                patch.object(
                    oracle, "_iter_reconciliation",
                    side_effect=lambda _connection, kind: iter(records[kind]),
                ),
            ):
                issues, truth = oracle._validate_runtime_outcomes(
                    connection, [], oracle_artifacts,
                    [{"classes": {"demo/Application": "entry"}}],
                    observations, ["app"], ["demo/Application"],
                    "platform", jdk_home,
                )

        reason_codes = {item["reason_code"] for item in issues}
        self.assertTrue({
            "ORACLE_FIXTURE_BINDING_ISSUE",
            "ORACLE_PROVIDER_BINDING_MISSING",
            "ORACLE_PROVIDER_FALSE_RESOLUTION",
            "ORACLE_PLATFORM_PROVIDER_MISMATCH",
            "ORACLE_PROVIDER_MISSED",
            "ORACLE_ARTIFACT_PROVIDER_MISMATCH",
            "ORACLE_DEFINITION_READY_MISMATCH",
            "ORACLE_CLASS_LOAD_READY_MISMATCH",
        }.issubset(reason_codes), reason_codes)
        self.assertEqual(truth["provider_count"], len(provider_rows))
        self.assertEqual(truth["member_resolution_count"], 0)
        self.assertEqual(truth["dispatch_count"], 0)

    def test_runtime_outcome_member_and_dispatch_boundary_matrix(self):
        def create_schema(connection):
            connection.row_factory = sqlite3.Row
            connection.executescript(
                """
                CREATE TABLE direct_edges (
                    direct_edge_identity TEXT PRIMARY KEY,
                    edge_kind TEXT NOT NULL,
                    symbolic_owner TEXT NOT NULL,
                    symbolic_name TEXT NOT NULL,
                    symbolic_descriptor TEXT NOT NULL,
                    opcode INTEGER
                );
                CREATE TABLE members (
                    member_identity TEXT PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    member_name TEXT NOT NULL,
                    descriptor TEXT NOT NULL
                );
                """
            )

        def edge(identity, kind, owner, name, descriptor="()V", opcode=182):
            return (identity, kind, owner, name, descriptor, opcode)

        resolution_edges = [
            edge("r-type", "type", "TypeOwner", "value", "LType;", None),
            edge("r-false", "method", "FalseOwner", "missing"),
            edge("r-none-missing", "method", "NoneOwner", "missing"),
            edge("r-missed", "method", "PresentOwner", "missed"),
            edge("r-selected-none", "method", "PresentOwner", "selectedNone"),
            edge("r-match", "method", "PresentOwner", "match"),
            edge("r-owner-mismatch", "method", "PresentOwner", "wrongOwner"),
            edge("r-field", "field", "FieldOwner", "field", "I", 180),
        ]
        dispatch_edges = [
            edge("d-field", "field", "Base", "run", opcode=182),
            edge("d-bad-opcode", "method", "Base", "run", opcode=184),
            edge("d-match", "method", "Base", "run", opcode=182),
            edge("d-status-bad", "method", "Base", "other", opcode=185),
            edge("d-leaf", "method", "Leaf", "run", opcode=182),
            edge("d-abstract-leaf", "method", "AbstractLeaf", "run", opcode=182),
            edge("d-final-method", "method", "FinalMethod", "run", opcode=182),
            edge("d-final-class", "method", "FinalClass", "run", opcode=182),
            edge("d-no-decl", "method", "NoDeclaration", "run", opcode=182),
            edge("d-jfr", "method", "JfrChild", "begin", opcode=182),
            edge("d-not-event", "method", "NotEvent", "begin", opcode=182),
            edge("d-synthetic-other", "method", "SyntheticOther", "custom", opcode=182),
            edge("d-non-synthetic", "method", "NonSynthetic", "begin", opcode=182),
            edge("d-cycle", "method", "CycleA", "run", opcode=182),
            edge("d-missing-only", "method", "MissingOnly", "run", opcode=185),
        ]
        members = [
            ("m-decl", "App/Decl", "method", "()V"),
            ("m-wrong", "Wrong/Owner", "method", "()V"),
            ("m-field", "App/Field", "field", "I"),
            ("t-impl", "App/Impl", "run", "()V"),
            ("t-grand", "App/Grand", "run", "()V"),
            ("t-leaf", "Leaf", "run", "()V"),
            ("t-final-method", "FinalMethod", "run", "()V"),
            ("t-final-class", "FinalClass", "run", "()V"),
            ("t-extra", "App/Extra", "run", "()V"),
            ("t-jfr", "jdk/jfr/Event", "begin", "()V"),
            ("t-not-event", "NotEvent", "begin", "()V"),
            ("t-synthetic-other", "SyntheticOther", "custom", "()V"),
            ("t-non-synthetic", "NonSynthetic", "begin", "()V"),
            ("t-cycle-a", "CycleA", "run", "()V"),
            ("t-cycle-b", "CycleB", "run", "()V"),
        ]

        def observation(modifiers=0, super_name=None, interfaces=()):
            return {
                "status": "definition_ready", "modifiers": modifiers,
                "super_name": super_name, "interfaces": list(interfaces),
                "members": [],
            }

        observations = {
            "Base": observation(0x0400),
            "App/Impl": observation(super_name="Base"),
            "AbstractChild": observation(0x0400, super_name="Base"),
            "App/Grand": observation(super_name="AbstractChild"),
            "Leaf": observation(),
            "AbstractLeaf": observation(0x0400),
            "FinalMethod": observation(),
            "FinalClass": observation(0x0010),
            "NoDeclaration": observation(),
            "JfrChild": observation(),
            "NotEvent": observation(),
            "SyntheticOther": observation(),
            "NonSynthetic": observation(),
            "CycleA": observation(super_name="CycleB"),
            "CycleB": observation(super_name="CycleA"),
            "InterfaceParent": observation(0x0200),
            "InterfaceImpl": observation(interfaces=("InterfaceParent",)),
            "Skipped": {"status": "not_found", "modifiers": 0},
        }

        def method(owner, name, flags=0):
            return (owner, ("method", name, "()V", flags))

        def field(owner):
            return (owner, ("field", "field", "I", 1))

        resolution_table = {
            ("PresentOwner", "missed"): method("App/Decl", "missed"),
            ("PresentOwner", "selectedNone"):
                method("App/Decl", "selectedNone"),
            ("PresentOwner", "match"): method("App/Decl", "match"),
            ("PresentOwner", "wrongOwner"):
                method("App/Decl", "wrongOwner"),
            ("FieldOwner", "field"): field("App/Field"),
            ("Base", "run"): method("Base", "run"),
            ("App/Impl", "run"): method("App/Impl", "run"),
            ("App/Grand", "run"): method("App/Grand", "run"),
            ("Base", "other"): method("Base", "other"),
            ("App/Impl", "other"): method("App/Impl", "other"),
            ("Leaf", "run"): method("Leaf", "run"),
            ("AbstractLeaf", "run"): method("AbstractLeaf", "run"),
            ("FinalMethod", "run"): method("FinalMethod", "run", 0x0010),
            ("FinalClass", "run"): method("FinalClass", "run"),
            ("JfrChild", "begin"): method("JfrChild", "begin", 0x1010),
            ("NotEvent", "begin"): method("NotEvent", "begin", 0x1010),
            ("SyntheticOther", "custom"):
                method("SyntheticOther", "custom", 0x1010),
            ("NonSynthetic", "begin"):
                method("NonSynthetic", "begin", 0x0010),
            ("CycleA", "run"): method("CycleA", "run"),
            ("CycleB", "run"): method("CycleB", "run"),
            ("MissingOnly", "run"): method("App/Impl", "run"),
        }

        def resolve_member(_observations, owner, _kind, name, _descriptor, **_):
            return resolution_table.get((owner, str(name)))

        resolution_rows = [
            {
                "direct_edge_identity": "r-absent",
                "member_resolution_status": "missing",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-type",
                "member_resolution_status": "missing",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-false",
                "member_resolution_status": "resolved",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-none-missing",
                "member_resolution_status": "missing",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-missed",
                "member_resolution_status": "missing",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-selected-none",
                "member_resolution_status": "resolved",
                "resolved_member_identity": None,
            },
            {
                "direct_edge_identity": "r-match",
                "member_resolution_status": "resolved",
                "resolved_member_identity": "m-decl",
            },
            {
                "direct_edge_identity": "r-owner-mismatch",
                "member_resolution_status": "resolved",
                "resolved_member_identity": "m-wrong",
            },
            {
                "direct_edge_identity": "r-field",
                "member_resolution_status": "resolved",
                "resolved_member_identity": "m-field",
            },
        ]
        dispatch_rows = [
            {"direct_edge_identity": "d-absent"},
            {"direct_edge_identity": "d-field"},
            {"direct_edge_identity": "d-bad-opcode"},
            {
                "direct_edge_identity": "d-match",
                "implementation_target_identities": ["t-impl", "t-grand"],
                "dispatch_status": "exact",
            },
            {
                "direct_edge_identity": "d-status-bad",
                "implementation_target_identities": [],
                "dispatch_status": "unresolved",
            },
            {
                "direct_edge_identity": "d-leaf",
                "implementation_target_identities": ["missing-target"],
                "dispatch_status": "exact",
            },
            {
                "direct_edge_identity": "d-abstract-leaf",
                "implementation_target_identities": [],
                "dispatch_status": "not_applicable",
            },
            {
                "direct_edge_identity": "d-final-method",
                "implementation_target_identities": ["t-final-method"],
                "dispatch_status": "possible",
            },
            {"direct_edge_identity": "d-final-class"},
            {
                "direct_edge_identity": "d-no-decl",
                "implementation_target_identities": ["t-extra"],
                "dispatch_status": "exact",
            },
            {
                "direct_edge_identity": "d-jfr",
                "implementation_target_identities": ["t-jfr"],
                "dispatch_status": "proven_receiver",
            },
            {
                "direct_edge_identity": "d-not-event",
                "implementation_target_identities": ["t-not-event"],
                "dispatch_status": "partial_possible_set",
            },
            {
                "direct_edge_identity": "d-synthetic-other",
                "implementation_target_identities": ["t-synthetic-other"],
                "dispatch_status": "exact",
            },
            {
                "direct_edge_identity": "d-non-synthetic",
                "implementation_target_identities": ["t-non-synthetic"],
                "dispatch_status": "exact",
            },
            {
                "direct_edge_identity": "d-cycle",
                "implementation_target_identities": ["t-cycle-a", "t-cycle-b"],
                "dispatch_status": "exact",
            },
        ]

        class SmallVariableLimitConnection:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def getlimit(self, _category):
                return 9

            def execute(self, *args, **kwargs):
                return self.wrapped.execute(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            database_path = root / "facts.sqlite"
            raw_connection = sqlite3.connect(database_path)
            raw_connection.row_factory = sqlite3.Row
            create_schema(raw_connection)
            raw_connection.executemany(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?)",
                resolution_edges + dispatch_edges,
            )
            raw_connection.executemany(
                "INSERT INTO members VALUES (?,?,?,?)", members,
            )
            raw_connection.commit()
            connection = SmallVariableLimitConnection(raw_connection)
            jdk_home = root / "jdk"
            jdk_home.mkdir()
            (jdk_home / "release").write_text(
                'JAVA_VERSION="17.0.12"\n', encoding="utf-8",
            )
            records = {
                "provider_binding": [], "class_definition": [],
                "member_resolution": resolution_rows,
                "dispatch_resolution": dispatch_rows,
            }
            application_classes = {
                name: name + ".class" for name in (
                    "App/Decl", "App/Field", "App/Impl", "App/Grand",
                    "Leaf", "FinalMethod", "FinalClass", "App/Extra",
                    "jdk/jfr/Event", "NotEvent", "SyntheticOther",
                    "NonSynthetic", "CycleA", "CycleB",
                )
            }
            with (
                patch.object(
                    oracle, "_artifact_instance_bindings",
                    return_value=({}, []),
                ),
                patch.object(
                    oracle, "_oracle_runtime_contexts", return_value=[],
                ),
                patch.object(
                    oracle, "_iter_reconciliation",
                    side_effect=lambda _connection, kind: iter(records[kind]),
                ),
                patch.object(
                    oracle, "_resolve_member", side_effect=resolve_member,
                ),
                patch.object(
                    oracle, "_is_subtype",
                    side_effect=lambda _observations, owner, target: (
                        owner == "JfrChild" and target == "jdk/jfr/Event"
                    ),
                ),
            ):
                issues, truth = oracle._validate_runtime_outcomes(
                    connection, [], [], [{"classes": application_classes}],
                    observations, [], [], "platform", jdk_home,
                )
            raw_connection.close()

        reason_codes = {item["reason_code"] for item in issues}
        self.assertTrue({
            "ORACLE_MEMBER_FALSE_RESOLUTION",
            "ORACLE_MEMBER_MISSED",
            "ORACLE_MEMBER_OWNER_MISMATCH",
            "ORACLE_DISPATCH_TARGET_MISMATCH",
            "ORACLE_DISPATCH_STATUS_MISMATCH",
        }.issubset(reason_codes), reason_codes)
        self.assertEqual(truth["member_resolution_count"], len(resolution_rows))
        self.assertEqual(truth["dispatch_count"], len(dispatch_rows))

        memory_connection = sqlite3.connect(":memory:")
        self.addCleanup(memory_connection.close)
        create_schema(memory_connection)
        memory_connection.executemany(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?)", [
                edge("seen-edge", "method", "NoDeclaration", "run", opcode=182),
                edge("missing-edge", "method", "NoDeclaration", "run", opcode=185),
            ],
        )
        memory_connection.commit()
        memory_records = {
            "provider_binding": [], "class_definition": [],
            "member_resolution": [],
            "dispatch_resolution": [{
                "direct_edge_identity": "seen-edge",
                "implementation_target_identities": [],
                "dispatch_status": "not_applicable",
            }],
        }
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", return_value=({}, []),
            ),
            patch.object(oracle, "_oracle_runtime_contexts", return_value=[]),
            patch.object(
                oracle, "_iter_reconciliation",
                side_effect=lambda _connection, kind: iter(memory_records[kind]),
            ),
            patch.object(oracle, "_resolve_member", return_value=None),
            patch.object(oracle, "_release_major", return_value=17),
        ):
            memory_issues, memory_truth = oracle._validate_runtime_outcomes(
                memory_connection, [], [], [],
                {"NoDeclaration": observation()}, [], [], "platform",
                Path("/jdk-without-release"),
            )
        self.assertEqual(memory_issues, [])
        self.assertEqual(memory_truth["dispatch_count"], 1)

        class BrokenLimitConnection:
            def getlimit(self, _category):
                raise sqlite3.OperationalError("limit unavailable")

            def execute(self, *args, **kwargs):
                return memory_connection.execute(*args, **kwargs)

        empty_records = {
            "provider_binding": [], "class_definition": [],
            "member_resolution": [], "dispatch_resolution": [],
        }
        with (
            patch.object(
                oracle, "_artifact_instance_bindings", return_value=({}, []),
            ),
            patch.object(oracle, "_oracle_runtime_contexts", return_value=[]),
            patch.object(
                oracle, "_iter_reconciliation",
                side_effect=lambda _connection, kind: iter(empty_records[kind]),
            ),
            patch.object(oracle, "_resolve_member", return_value=None),
            patch.object(oracle, "_release_major", return_value=17),
        ):
            oracle._validate_runtime_outcomes(
                BrokenLimitConnection(), [], [], [], {}, [], [], "platform",
                Path("/jdk-without-release"),
            )

    def test_runtime_outcome_dispatch_completeness_ignores_shadowed_callers(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            # Production persists facts on disk, while focused callers and
            # embedding integrations may supply an in-memory full schema.  The
            # selected-caller completeness rule must be identical in both
            # storage modes.
            connection = sqlite3.connect(":memory:")
            connection.row_factory = sqlite3.Row
            self.addCleanup(connection.close)
            connection.executescript(
                """
                CREATE TABLE direct_edges (
                    direct_edge_identity TEXT PRIMARY KEY,
                    caller_member_identity TEXT NOT NULL,
                    caller_artifact_instance_identity TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    symbolic_owner TEXT NOT NULL,
                    symbolic_name TEXT NOT NULL,
                    symbolic_descriptor TEXT NOT NULL,
                    opcode INTEGER
                );
                CREATE TABLE members (
                    member_identity TEXT PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    member_name TEXT NOT NULL,
                    descriptor TEXT NOT NULL,
                    class_variant_identity TEXT NOT NULL
                );
                CREATE TABLE classes (
                    class_variant_identity TEXT PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    artifact_instance_identity TEXT NOT NULL
                );
                """
            )
            connection.executemany(
                "INSERT INTO classes VALUES (?,?,?)",
                [
                    ("active-variant", "App/Caller", "active-artifact"),
                    ("shadowed-variant", "App/Caller", "shadowed-artifact"),
                    ("target-variant", "App/Impl", "target-artifact"),
                ],
            )
            connection.executemany(
                "INSERT INTO members VALUES (?,?,?,?,?)",
                [
                    ("active-caller", "App/Caller", "call", "()V", "active-variant"),
                    (
                        "shadowed-caller", "App/Caller", "call", "()V",
                        "shadowed-variant",
                    ),
                    ("target-member", "App/Impl", "run", "()V", "target-variant"),
                ],
            )
            connection.executemany(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        "active-edge", "active-caller", "active-artifact",
                        "method", "Base", "run", "()V", 182,
                    ),
                    (
                        "shadowed-edge", "shadowed-caller", "shadowed-artifact",
                        "method", "Base", "run", "()V", 182,
                    ),
                    (
                        "selected-missing-edge", "active-caller",
                        "active-artifact", "method", "NoDeclaration", "run",
                        "()V", 185,
                    ),
                ],
            )
            connection.commit()
            jdk_home = root / "jdk"
            jdk_home.mkdir()
            (jdk_home / "release").write_text(
                'JAVA_VERSION="17.0.12"\n', encoding="utf-8",
            )
            observations = {
                "Base": {
                    "status": "definition_ready", "modifiers": 0x0400,
                    "super_name": None, "interfaces": [], "members": [],
                },
                "App/Impl": {
                    "status": "definition_ready", "modifiers": 0,
                    "super_name": "Base", "interfaces": [], "members": [],
                },
            }
            records = {
                "provider_binding": [
                    {
                        "initiating_loader_realm_identity": "app",
                        "class_name": "App/Caller",
                        "class_provider_status": "resolved",
                        "selected_artifact_instance_identity": "active-artifact",
                    },
                    {
                        "initiating_loader_realm_identity": "app",
                        "class_name": "App/Impl",
                        "class_provider_status": "resolved",
                        "selected_artifact_instance_identity": "target-artifact",
                    },
                ],
                "class_definition": [],
                "member_resolution": [],
                "dispatch_resolution": [{
                    "direct_edge_identity": "active-edge",
                    "implementation_target_identities": ["target-member"],
                    "dispatch_status": "exact",
                }],
            }

            def resolve_member(
                _observations, owner, _kind, name, _descriptor, **_kwargs,
            ):
                if name != "run" or owner not in {"Base", "App/Impl"}:
                    return None
                return owner, ("method", "run", "()V", 0)

            with (
                patch.object(
                    oracle, "_artifact_instance_bindings", return_value=({}, []),
                ),
                patch.object(oracle, "_oracle_runtime_contexts", return_value=[]),
                patch.object(
                    oracle, "_iter_reconciliation",
                    side_effect=lambda _connection, kind: iter(records[kind]),
                ),
                patch.object(oracle, "_resolve_member", side_effect=resolve_member),
            ):
                issues, truth = oracle._validate_runtime_outcomes(
                    connection, [], [], [{"classes": {"App/Impl": "entry"}}],
                    observations, [], [], "platform", jdk_home,
                )

        self.assertEqual(issues, [])
        self.assertEqual(truth["dispatch_count"], 1)

    def test_cross_version_semantics_resolution_graph_and_resource_matrix(self):
        def direct_edge(
            caller, target_owner, target_name, target_descriptor="()V",
            *, opcode="invokevirtual", offset=1, reference_kind="method",
        ):
            return (
                caller, "call", "()V", target_owner, target_name,
                target_descriptor, opcode, offset, reference_kind,
            )

        def resolved(owner, kind, name, descriptor):
            return (owner, (kind, name, descriptor, 1))

        resolution_edges = [
            direct_edge("demo.None", "demo.None", "neither"),
            direct_edge("demo.Same", "demo.Same", "same"),
            direct_edge("demo.Current", "demo.Current", "currentOnly"),
            direct_edge("demo.Inherited", "demo.Inherited", "baseInherited"),
            direct_edge("demo.Plain", "demo.Plain", "basePlain"),
            direct_edge("demo.Different", "demo.Different", "different"),
            direct_edge(
                "demo.Field", "demo.Field", "removed", "I",
                opcode="getfield", reference_kind="field", offset=7,
            ),
            direct_edge(
                "demo.BadMethodOpcode", "demo.BadMethodOpcode", "bad",
                opcode="getfield", reference_kind="method",
            ),
            direct_edge(
                "demo.BadFieldOpcode", "demo.BadFieldOpcode", "bad", "I",
                opcode="invokevirtual", reference_kind="field",
            ),
            direct_edge(
                "demo.BadKind", "demo.BadKind", "bad",
                reference_kind="type",
            ),
            direct_edge("demo.BaseNotReady", "demo.BaseNotReady", "skip"),
            direct_edge(
                "demo.CurrentNotReady", "demo.CurrentNotReady", "skip",
            ),
        ]
        graph_edges = [
            (
                "demo.Entry", "entry", "()V", "demo.Middle", "middle",
                "()V", "invokestatic", 1, "method",
            ),
            (
                "demo.Middle", "middle", "()V", "demo.End", "end",
                "()V", "invokevirtual", 2, "method",
            ),
            (
                "demo.End", "end", "()V", "demo.Entry", "entry",
                "()V", "invokevirtual", 3, "method",
            ),
            (
                "demo.Entry", "entry", "()V", "demo.Missing", "missing",
                "()V", "invokevirtual", 4, "method",
            ),
            ("demo.Short", "call", "()V"),
            direct_edge(
                "demo.BadGraphKind", "demo.Target", "call",
                reference_kind="field",
            ),
            direct_edge(
                "demo.BadGraphDescriptor", "demo.Target", "value", "I",
            ),
        ]
        service_descriptor = "(Ljava/lang/Class;)Ljava/util/ServiceLoader;"
        service_edges = [
            ("demo.ShortLoad", "call", "()V"),
            direct_edge(
                "demo.BadLoadKind", "java.util.ServiceLoader", "load",
                service_descriptor, opcode="invokestatic",
                reference_kind="field",
            ),
            direct_edge(
                "demo.BadLoadOwner", "demo.Loader", "load",
                service_descriptor, opcode="invokestatic",
            ),
            direct_edge(
                "demo.BadLoadName", "java.util.ServiceLoader", "other",
                service_descriptor, opcode="invokestatic",
            ),
            direct_edge(
                "demo.BadLoadDescriptor", "java.util.ServiceLoader", "load",
                "()V", opcode="invokestatic",
            ),
            (
                "demo.Entry", "entry", "()V", "java.util.ServiceLoader",
                "load", service_descriptor, "invokestatic", 20, "method",
            ),
            (
                "demo.Far", "call", "()V", "java.util.ServiceLoader",
                "load", service_descriptor, "invokestatic", 100, "method",
            ),
            (
                "demo.Unreached", "call", "()V", "java.util.ServiceLoader",
                "load", service_descriptor, "invokestatic", 20, "method",
            ),
        ]
        current_edges = resolution_edges + graph_edges + service_edges

        base_observations = {}
        current_observations = {}
        for edge in resolution_edges:
            owner = str(edge[3]).replace(".", "/")
            base_observations[owner] = {"ready": True}
            current_observations[owner] = {"ready": True}
        base_observations["demo/BaseNotReady"] = {"ready": False}
        current_observations["demo/CurrentNotReady"] = {"ready": False}
        observations = {
            "base": base_observations,
            "current": current_observations,
        }
        resolution_table = {
            ("base", "demo/Same", "same"):
                resolved("shared/Owner", "method", "same", "()V"),
            ("current", "demo/Same", "same"):
                resolved("shared/Owner", "method", "same", "()V"),
            ("current", "demo/Current", "currentOnly"):
                resolved("current/Owner", "method", "currentOnly", "()V"),
            ("base", "demo/Inherited", "baseInherited"):
                resolved("base/Inherited", "method", "baseInherited", "()V"),
            ("base", "demo/Plain", "basePlain"):
                resolved("base/Plain", "method", "basePlain", "()V"),
            ("base", "demo/Different", "different"):
                resolved("base/Different", "method", "different", "()V"),
            ("current", "demo/Different", "different"):
                resolved("current/Different", "method", "different", "()V"),
            ("base", "demo/Field", "removed"):
                resolved("base/Field", "field", "removed", "I"),
            ("current", "demo/Middle", "middle"):
                resolved("demo/Middle", "method", "middle", "()V"),
            ("current", "demo/End", "end"):
                resolved("demo/End", "method", "end", "()V"),
            ("current", "demo/Entry", "entry"):
                resolved("demo/Entry", "method", "entry", "()V"),
        }

        def resolve_member(side_observations, owner, kind, name, descriptor, **_):
            side = "base" if side_observations is base_observations else "current"
            return resolution_table.get((side, owner, str(name)))

        expected_current_only = (
            "demo.Current", "call", "()V", 1, "demo.Current",
            "currentOnly", "()V", "", "current.Owner",
        )

        def decision_for(change):
            return {
                "reason_code": "RUNTIME_MEMBER_RESOLUTION_CHANGED",
                "fact_scope": {
                    "class_name": change[4], "member_name": change[5],
                    "descriptor": change[6],
                },
                "evidence": {
                    "semantic_caller_edge": {
                        "caller_class": change[0].replace(".", "/"),
                        "caller_member": change[1],
                        "caller_descriptor": change[2],
                        "bytecode_offset": change[3],
                    },
                    "base_resolution": {"resolved_owner": change[7]},
                    "current_resolution": {"resolved_owner": change[8]},
                },
            }

        service_a = "META-INF/services/demo.Service"
        service_b = "META-INF/services/demo.Other"
        base_resources = [
            {
                "realm": "app", "name": "ordinary.txt",
                "mechanism": "first", "selected": ["old"],
            },
            {
                "realm": "app", "name": "META-INF/services/demo.Same",
                "mechanism": "service_loader", "selected": ["same"],
            },
            {
                "realm": "app", "name": service_a,
                "mechanism": "service_loader", "selected": ["old"],
            },
            {
                "realm": "app", "name": service_b,
                "mechanism": "service_loader", "selected": ["old"],
            },
        ]
        current_resources = [
            {**base_resources[0], "selected": ["new"]},
            dict(base_resources[1]),
            {**base_resources[2], "selected": ["new"]},
            {**base_resources[3], "selected": ["new"]},
        ]
        type_edges = [
            ("demo/Entry", "entry", "()V", 18, "demo/Service", "other"),
            ("demo/Entry", "entry", "()V", 18, "demo/Unknown", "class_literal"),
            ("demo/NoLoad", "call", "()V", 18, "demo/Service", "class_literal"),
            ("demo/Far", "call", "()V", 101, "demo/Service", "class_literal"),
            ("demo/Far", "call", "()V", 90, "demo/Service", "class_literal"),
            ("demo/Unreached", "call", "()V", 18, "demo/Service", "class_literal"),
            ("demo/Entry", "entry", "()V", 18, "demo/Service", "class_literal"),
        ]
        config = {"current": {"runtime_profile": {
            "business_entrypoint_profile": {"methods": [
                {
                    "class_name": "demo/Entry", "member_name": "entry",
                    "descriptor": "()V",
                },
                {},
            ]},
        }}}
        decisions = [
            {"reason_code": "NOT_A_RESOLUTION_CHANGE"},
            decision_for(expected_current_only),
            {
                "reason_code": "RUNTIME_MEMBER_RESOLUTION_CHANGED",
                "fact_scope": None, "evidence": None,
            },
        ]
        formal_rows = [
            {"resource_name": service_a, "activation_status": "reachable"},
            {
                "resource_name": service_b,
                "activation_status": "not_found_in_static_analysis",
            },
        ]

        def sidecar_rows(_generation, filename, *_args, **_kwargs):
            return iter(decisions if filename == "binary_decisions.json" else formal_rows)

        truth_parts = {
            "base": {
                "direct_edges": resolution_edges,
                "resource_selections": base_resources,
            },
            "current": {
                "direct_edges": current_edges,
                "type_edges": type_edges,
                "resource_selections": current_resources,
            },
        }
        with (
            patch.object(oracle, "_resolve_member", side_effect=resolve_member),
            patch.object(
                oracle, "_oracle_class_load_ready",
                side_effect=lambda item: bool(item and item.get("ready")),
            ),
            patch.object(
                oracle, "_is_subtype",
                side_effect=lambda _observations, _owner, target: (
                    target == "base/Inherited"
                ),
            ),
            patch.object(
                oracle, "_iter_sidecar_object_rows", side_effect=sidecar_rows,
            ),
        ):
            issues, truth = oracle._validate_cross_version_semantics(
                Path("/generation"), config, truth_parts, observations,
            )

        reason_codes = [item["reason_code"] for item in issues]
        self.assertIn("ORACLE_MEMBER_RESOLUTION_CHANGE_MISSING", reason_codes)
        self.assertIn("ORACLE_MEMBER_RESOLUTION_CHANGE_EXTRA", reason_codes)
        self.assertNotIn("ORACLE_RESOURCE_ACTIVATION_MISMATCH", reason_codes)
        self.assertEqual(
            truth["resource_activation_status"], {
                service_a: "reachable",
                service_b: "not_found_in_static_analysis",
            },
        )
        self.assertEqual(len(truth["member_resolution_changes"]), 5)
        self.assertIn(expected_current_only, truth["member_resolution_changes"])
        self.assertIn(
            (
                "demo.Inherited", "call", "()V", 1, "base.Inherited",
                "baseInherited", "()V", "base.Inherited", "",
            ),
            truth["member_resolution_changes"],
        )

        compact_config = {"current": {"runtime_profile": {
            "business_entrypoint_profile": {"methods": [{
                "class_name": "demo/Compact", "member_name": "entry",
                "descriptor": "()V",
            }]},
        }}}
        empty_sidecars = lambda *_args, **_kwargs: iter(())
        for compact_base, compact_current in (({}, []), ([], {})):
            compact_truth = {
                "base": {
                    "direct_edges": compact_base, "resource_selections": [],
                },
                "current": {
                    "direct_edges": compact_current,
                    "resource_selections": [],
                },
            }
            with (
                patch.object(
                    oracle, "_resolution_affected_owners", return_value=set(),
                ),
                patch.object(
                    oracle, "_iter_common_validated_direct_edges",
                    return_value=iter(()),
                ),
                patch.object(
                    oracle, "_iter_validated_direct_edges",
                    side_effect=lambda _path: iter(()),
                ),
                patch.object(
                    oracle, "_iter_validated_type_edges",
                    side_effect=lambda _path: iter(()),
                ),
                patch.object(
                    oracle, "_reachable_validated_current_methods",
                    side_effect=lambda _path, entrypoints, *_args: set(entrypoints),
                ),
                patch.object(
                    oracle, "_iter_sidecar_object_rows",
                    side_effect=empty_sidecars,
                ),
            ):
                compact_issues, compact_result = (
                    oracle._validate_cross_version_semantics(
                        Path("/generation"), compact_config, compact_truth,
                        {"base": {}, "current": {}},
                    )
                )
            self.assertEqual(compact_issues, [])
            self.assertEqual(compact_result["resource_activation_status"], {})

        empty_truth = {
            "base": {"direct_edges": [], "resource_selections": []},
            "current": {
                "direct_edges": [], "type_edges": [],
                "resource_selections": [],
            },
        }
        fallback_configs = (
            {},
            {"current": {"runtime_profile": {}}},
            {"current": {"runtime_profile": {
                "business_entrypoint_profile": {},
            }}},
        )
        for fallback_config in fallback_configs:
            with patch.object(
                oracle, "_iter_sidecar_object_rows",
                side_effect=lambda *_args, **_kwargs: iter(({},)),
            ):
                fallback_issues, _ = oracle._validate_cross_version_semantics(
                    Path("/generation"), fallback_config, empty_truth,
                    {"base": {}, "current": {}},
                )
            self.assertEqual(
                [item["reason_code"] for item in fallback_issues],
                ["ORACLE_RESOURCE_ACTIVATION_MISMATCH"],
            )

    def test_cross_version_oracle_preserves_every_service_loader_callsite(self):
        service_name = "META-INF/services/demo.Service"
        caller = ("demo.Loader", "load", "()V")
        service_descriptor = "(Ljava/lang/Class;)Ljava/util/ServiceLoader;"
        current_edges = [
            (*caller, "java.util.ServiceLoader", "load", service_descriptor,
             "invokestatic", 11, "method"),
            (*caller, "java.util.ServiceLoader", "load", service_descriptor,
             "invokestatic", 100, "method"),
        ]
        selections = [{
            "realm": "application-loader",
            "name": service_name,
            "mechanism": "service_loader",
            "selected": ["demo.Provider"],
        }]
        truth_parts = {
            "base": {
                "direct_edges": [],
                "resource_selections": [{
                    **selections[0], "selected": ["demo.OldProvider"],
                }],
            },
            "current": {
                "direct_edges": current_edges,
                "type_edges": [[
                    *caller, 10, "demo/Service", "class_literal",
                ]],
                "resource_selections": selections,
            },
        }
        config = {"current": {"runtime_profile": {
            "business_entrypoint_profile": {"methods": [{
                "class_name": caller[0],
                "member_name": caller[1],
                "descriptor": caller[2],
            }]},
        }}}

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            (generation / "binary_decisions.json").write_text(
                json.dumps({"authoritative_change_facts": []}),
                encoding="utf-8",
            )
            (generation / "binary_formal_results.json").write_text(
                json.dumps({"resource_activation_results": [{
                    "resource_name": service_name,
                    "activation_status": "reachable",
                }]}),
                encoding="utf-8",
            )
            issues, truth = oracle._validate_cross_version_semantics(
                generation, config, truth_parts,
                {"base": {}, "current": {}},
            )

        self.assertEqual(issues, [])
        self.assertEqual(
            truth["resource_activation_status"], {service_name: "reachable"},
        )

    def test_runtime_semantic_reflection_and_proxy_reconstruction_matrix(self):
        self.assertEqual(oracle._oracle_runtime_semantic_rows({}, []), set())

        observations = {
            "demo/Target": {
                "status": "definition_ready",
                "members": [
                    "method|run|()V|1",
                    "method|overloaded|()V|1",
                    "method|overloaded|(I)V|1",
                    "method|<init>|()V|1",
                    "method|<init>|(I)V|1",
                    "field|value|I|1", "field|other|J|1",
                ],
                "super_name": "java/lang/Object", "interfaces": [],
            },
            "demo/SingleCtor": {
                "status": "definition_ready",
                "members": ["method|<init>|()V|1"],
                "super_name": "java/lang/Object", "interfaces": [],
            },
            "demo/EmptyName": {
                "status": "definition_ready",
                "members": ["field||I|1", "method|named|()V|1"],
                "super_name": "java/lang/Object", "interfaces": [],
            },
            "demo/Handler": {
                "status": "definition_ready",
                "members": [
                    "method|invoke|(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;|1",
                    "method|other|()V|1", "field|invoke|I|1",
                ],
                "super_name": "java/lang/Object",
                "interfaces": ["java/lang/reflect/InvocationHandler"],
            },
            "demo/MultiHandler": {
                "status": "definition_ready",
                "members": [
                    "method|invoke|()V|1", "method|invoke|(I)V|1",
                ],
                "super_name": "java/lang/Object",
                "interfaces": ["java/lang/reflect/InvocationHandler"],
            },
            "demo/NotHandler": {
                "status": "definition_ready", "members": [],
                "super_name": "java/lang/Object", "interfaces": [],
            },
            # Equality makes the interface a subtype of itself even when its
            # optional observation payload is empty.
            "java/lang/reflect/InvocationHandler": {},
            "java/lang/Object": {
                "status": "definition_ready", "members": [],
                "super_name": "", "interfaces": [],
            },
        }
        instructions = []

        def ref(owner, name, descriptor="()V", interface=False):
            prefix = "InterfaceMethod" if interface else "Method"
            return f"{prefix} {owner}.{name}:{descriptor}"

        def add_sequence(caller, rows):
            for index, (opcode, comment) in enumerate(rows):
                instructions.append((
                    "demo/Caller", caller, "()V", index, opcode, comment,
                ))

        add_sequence("forNameExact", [
            ("ldc", "String demo.Target"),
            ("invokestatic", ref("java/lang/Class", "forName")),
            ("ldc_w", "String run"),
            ("invokevirtual", ref("java/lang/Class", "getMethod")),
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
        ])
        add_sequence("forNameWithoutPrecedingString", [
            ("ldc", "class demo/Target"),
            ("invokestatic", ref("java/lang/Class", "forName")),
            ("ldc", "String run"),
            ("invokevirtual", ref("java/lang/Class", "getDeclaredMethod")),
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
        ])
        add_sequence("overloaded", [
            ("ldc", "class demo/Target"),
            ("nop", "String ignored-by-opcode"),
            ("ldc", "not-a-string"),
            ("ldc", "String overloaded"),
            ("invokevirtual", ref("java/lang/Class", "getDeclaredMethod")),
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
        ])
        add_sequence("lookupWithoutTerminal", [
            ("ldc", "class demo/Target"),
            ("ldc", "String run"),
            ("invokevirtual", ref("java/lang/Class", "getMethod")),
        ])
        add_sequence("terminalBeforeLookup", [
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
            ("ldc", "class demo/Target"),
            ("ldc", "String run"),
            ("invokevirtual", ref("java/lang/Class", "getMethod")),
        ])
        add_sequence("stringWithoutType", [
            ("ldc", "String missing"),
            ("invokevirtual", ref("java/lang/Class", "getMethod")),
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
        ])
        add_sequence("typeWithoutString", [
            ("ldc_w", "class demo/EmptyName"),
            ("invokevirtual", ref("java/lang/Class", "getField")),
            ("invokevirtual", ref("java/lang/reflect/Field", "get")),
        ])
        add_sequence("typeAfterString", [
            ("ldc", "String run"),
            ("ldc", "class demo/Target"),
            ("invokevirtual", ref("java/lang/Class", "getMethod")),
            ("invokevirtual", ref("java/lang/reflect/Method", "invoke")),
        ])

        lookup_cases = (
            ("getConstructor", "demo/SingleCtor", None,
             "java/lang/reflect/Constructor", "newInstance"),
            ("getDeclaredConstructor", "demo/Target", None,
             "java/lang/reflect/Constructor", "newInstance"),
            ("getField", "demo/Target", "value",
             "java/lang/reflect/Field", "get"),
            ("getDeclaredField", "demo/Target", "other",
             "java/lang/reflect/Field", "set"),
            ("findStatic", "demo/Target", "run",
             "java/lang/invoke/MethodHandle", "invoke"),
            ("findVirtual", "demo/Target", "run",
             "java/lang/invoke/MethodHandle", "invokeExact"),
            ("findSpecial", "demo/Target", "run",
             "java/lang/invoke/MethodHandle", "invoke"),
            ("findConstructor", "demo/SingleCtor", None,
             "java/lang/invoke/MethodHandle", "invokeExact"),
            ("findGetter", "demo/Target", "value",
             "java/lang/invoke/MethodHandle", "invoke"),
            ("findSetter", "demo/Target", "other",
             "java/lang/invoke/MethodHandle", "invokeExact"),
        )
        for lookup, target, member, terminal_owner, terminal_name in lookup_cases:
            sequence = [("ldc", f"class {target}")]
            if member is not None:
                sequence.append(("ldc", f"String {member}"))
            sequence.extend([
                ("invokevirtual", ref("lookup/Owner", lookup)),
                ("invokevirtual", ref(terminal_owner, terminal_name)),
            ])
            add_sequence(f"lookup-{lookup}", sequence)

        proxy_call = ref("java/lang/reflect/Proxy", "newProxyInstance")
        add_sequence("proxyExact", [
            ("new", "class demo/NotHandler"),
            ("new", "not-a-class-comment"),
            ("checkcast", "class demo/Handler"),
            ("new", "class demo/Handler"),
            ("ldc", "class demo/Api"),
            ("nop", "class demo/Ignored"),
            ("invokestatic", proxy_call),
            ("invokevirtual", ref("demo/Other", "run")),
            ("invokeinterface", ref("demo/Api", "run", interface=True)),
        ])
        add_sequence("proxyPossible", [
            ("new", "class demo/Handler"),
            ("ldc_w", "class demo/Api"),
            ("invokestatic", proxy_call),
            ("invokeinterface", ref("demo/Other", "run", interface=True)),
        ])
        add_sequence("proxyMultiple", [
            ("new", "class demo/MultiHandler"),
            ("ldc", "class demo/Api"),
            ("invokestatic", proxy_call),
            ("invokeinterface", ref("demo/Api", "run", interface=True)),
        ])
        add_sequence("proxyWithoutHandler", [
            ("new", "class demo/NotHandler"),
            ("new", "class java/lang/reflect/InvocationHandler"),
            ("invokestatic", proxy_call),
        ])

        rows = oracle._oracle_runtime_semantic_rows(
            observations, reversed(instructions),
        )
        kinds = {row[0] for row in rows}
        self.assertTrue({
            "reflection_method_invocation",
            "reflection_constructor_invocation",
            "reflection_field_access",
            "method_handle_invocation",
            "method_handle_field_access",
            "dynamic_proxy_callback",
        }.issubset(kinds))
        self.assertEqual({row[-1] for row in rows}, {"exact", "possible"})
        self.assertTrue(any(
            row[0] == "reflection_method_invocation"
            and row[2] == "forNameExact" and row[4] == "demo/Target"
            and row[5] == "run" and row[-1] == "exact"
            for row in rows
        ))
        self.assertTrue(any(
            row[0] == "dynamic_proxy_callback"
            and row[2] == "proxyExact" and row[4] == "demo/Handler"
            and row[-1] == "exact"
            for row in rows
        ))
        self.assertTrue(any(
            row[0] == "dynamic_proxy_callback"
            and row[2] in {"proxyPossible", "proxyMultiple"}
            and row[-1] == "possible"
            for row in rows
        ))

    def test_aop_condition_and_auto_configuration_closed_matrix(self):
        self.assertIsNone(oracle._oracle_aop_pointcut_constraints(""))
        parsed = oracle._oracle_aop_pointcut_constraints(
            "execution(* demo.Service.run(..)) && "
            "@within(demo.ClassMarker) && @annotation(demo.MethodMarker) && "
            "!@annotation(demo.Excluded)"
        )
        self.assertTrue(parsed["complete"])
        self.assertEqual(parsed["executions"], (("demo.Service", "run"),))
        self.assertEqual(parsed["class_annotations"], {"Ldemo/ClassMarker;"})
        self.assertEqual(parsed["method_annotations"], {"Ldemo/MethodMarker;"})
        self.assertEqual(parsed["excluded_method_annotations"], {"Ldemo/Excluded;"})
        for unsupported in (
            "execution(* demo.A.run(..)) || execution(* demo.B.run(..))",
            "execution(* demo.A.run(..)) && within(demo..*)",
            "execution(* demo.A.run(..)) && @target(demo.Marker)",
            "execution(* demo.A.run(..)) && !@within(demo.Marker)",
        ):
            self.assertFalse(
                oracle._oracle_aop_pointcut_constraints(unsupported)["complete"]
            )

        profile_descriptor = "Lorg/springframework/context/annotation/Profile;"
        on_class = "Lx/ConditionalOnClass;"
        on_missing = "Lx/ConditionalOnMissingClass;"
        on_property = "Lx/ConditionalOnProperty;"
        observations = {"demo/Present": {}}

        def condition(
            descriptor, attributes=None, *, active=(), properties=None,
            complete=True,
        ):
            values = {} if attributes is None else {descriptor: attributes}
            return oracle._oracle_condition_status(
                [descriptor], values,
                active_profiles=set(active),
                resolved_properties={} if properties is None else properties,
                configuration_complete=complete,
                observations=observations,
            )

        self.assertEqual(condition(profile_descriptor), "active")
        self.assertEqual(condition(
            profile_descriptor, {"value": {"prod", "", "<unresolved:x>"}},
            active={"dev"},
        ), "inactive")
        self.assertEqual(condition(
            profile_descriptor, {"value": {"dev"}}, active={"dev"},
        ), "active")
        self.assertEqual(condition(on_class), "unproven")
        self.assertEqual(condition(
            on_class, {"value": {"demo.Present", "SimpleName"}},
        ), "active")
        self.assertEqual(condition(
            on_class, {"value": {"demo/Present"}},
        ), "active")
        self.assertEqual(condition(
            on_class, {"value": {"demo.Missing"}},
        ), "inactive")
        self.assertEqual(condition(on_missing), "unproven")
        self.assertEqual(condition(
            on_missing, {"value": {"demo.Missing"}},
        ), "active")
        self.assertEqual(condition(
            on_missing, {"value": {"demo/Missing", "SimpleName"}},
        ), "active")
        self.assertEqual(condition(
            on_missing, {"value": {"demo.Present"}},
        ), "inactive")
        self.assertEqual(condition(on_property), "unproven")
        property_values = {
            "prefix": {"feature"}, "name": {"enabled", ""},
            "value": {"ignored"}, "havingValue": {"on"},
        }
        self.assertEqual(condition(
            on_property, property_values,
            properties={"feature.enabled": "on"},
        ), "active")
        self.assertEqual(condition(
            on_property, property_values,
            properties={"feature.enabled": "off"},
        ), "inactive")
        self.assertEqual(condition(
            on_property, property_values, properties={}, complete=True,
        ), "inactive")
        self.assertEqual(condition(
            on_property, property_values, properties={}, complete=False,
        ), "unproven")
        self.assertEqual(condition(
            on_property,
            {"prefix": {"feature."}, "value": {"enabled"},
             "matchIfMissing": {"true"}},
        ), "active")
        self.assertEqual(condition(
            on_property, {"name": {"enabled"}},
            properties={"enabled": "false"},
        ), "inactive")
        self.assertEqual(condition(
            on_property, {"name": {"enabled"}},
            properties={"enabled": "TRUE"},
        ), "active")
        self.assertEqual(condition(
            "Lorg/springframework/boot/autoconfigure/condition/ConditionalOther;"
        ), "unproven")
        self.assertEqual(condition(
            "Lorg/springframework/context/annotation/Conditional;"
        ), "unproven")
        self.assertEqual(condition("Ldemo/Other;"), "active")

        boot_imports = (
            "META-INF/spring/"
            "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
        )
        selected, callbacks = oracle._oracle_selected_auto_configurations([
            {},
            {"name": boot_imports, "selected": [
                {},
                {"semantic_facts": [
                    ("ordered_entry", "demo.Modern"),
                    ("other", "ignored"),
                ]},
            ]},
            {"name": "META-INF/spring.factories", "selected": [{
                "semantic_facts": [
                    (
                        "property_entry:org.springframework.boot.autoconfigure.EnableAutoConfiguration",
                        "demo.Legacy",
                    ),
                    (
                        "property_entry:org.springframework.context.ApplicationListener",
                        "demo.Listener",
                    ),
                    ("property_entry:unknown.Callback", "demo.Unknown"),
                    ("ordinary", "ignored"),
                ],
            }]},
        ])
        self.assertEqual(selected, {"demo/Modern", "demo/Legacy"})
        self.assertEqual(callbacks, {
            "demo/Listener": {(
                "onApplicationEvent", "spring_application_listener",
            )},
        })

    def test_independent_resource_category_digest_and_fact_matrix(self):
        categories = {
            "config/runtime.xml": "runtime_topology",
            "META-INF/dubbo/demo.Service": "runtime_topology",
            "META-INF/services/demo.Service": "runtime_topology",
            "META-INF/spring.factories": "runtime_topology",
            "META-INF/spring/demo.imports": "runtime_topology",
            "META-INF/SIGNATURE.SF": "operational_security",
            "META-INF/MANIFEST.MF": "distribution_metadata",
            "META-INF/maven/g/a/pom.properties": "build_metadata",
            "native/libdemo.so": "runtime_native",
            "native/demo.DLL": "runtime_native",
            "ordinary.txt": "unknown",
        }
        for name, expected in categories.items():
            self.assertEqual(oracle._independent_resource_category(name), expected)

        content = b"value\r\nnext\r"
        supplied = "f" * 64
        self.assertEqual(
            oracle._independent_resource_digest(
                "ordinary.txt", content, content_sha256=supplied,
            ),
            supplied,
        )
        self.assertEqual(
            oracle._independent_resource_digest("ordinary.txt", content),
            hashlib.sha256(content).hexdigest(),
        )
        self.assertEqual(
            oracle._independent_resource_digest("config.xml", content),
            hashlib.sha256(b"value\nnext\n").hexdigest(),
        )
        service_a = oracle._independent_resource_digest(
            "META-INF/services/demo.Service", b" demo.One # note\n\n",
        )
        service_b = oracle._independent_resource_digest(
            "META-INF/services/demo.Service", b"demo.One\n",
        )
        self.assertEqual(service_a, service_b)

        manifest = oracle._independent_resource_facts(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nMain-Class: demo.\r\n Main\r\nInvalid\r\n",
        )
        self.assertIn(["main-class", "demo.Main"], manifest)
        self.assertEqual(
            oracle._independent_resource_facts(
                "META-INF/MANIFEST.MF", b" orphan-continuation\n"
            ),
            [],
        )
        factories = oracle._independent_resource_facts(
            "META-INF/spring.factories",
            (
                b"# comment\n"
                b"! other\n"
                b"invalid\n"
                b"key = one, \\\n"
                b" two,,three\\\\\n"
                b"empty=\n"
            ),
        )
        self.assertIn(["property_entry:key", "one"], factories)
        self.assertIn(["property_entry:key", "two"], factories)
        self.assertIn(["property_entry:key", "three\\\\"], factories)
        self.assertEqual(
            oracle._independent_resource_facts(
                "META-INF/spring.factories", b"tail=value\\"
            ),
            [["property_entry:tail", "value"]],
        )
        self.assertEqual(
            oracle._independent_resource_facts("ordinary.txt", b"value"), [],
        )
        ordered = oracle._independent_resource_facts(
            "META-INF/services/demo.Service",
            b" demo.One # comment\n\n demo.Two\n",
        )
        self.assertEqual(ordered, [
            ["ordered_entry", "demo.One"],
            ["ordered_entry", "demo.Two"],
        ])
        self.assertEqual(
            oracle._independent_resource_facts(
                "META-INF/dubbo/demo.Service", b"demo.Dubbo\n"
            ),
            [["ordered_entry", "demo.Dubbo"]],
        )
        self.assertEqual(
            oracle._independent_resource_facts(
                "META-INF/spring/demo.imports", b"demo.Import\n"
            ),
            [["ordered_entry", "demo.Import"]],
        )
        self.assertEqual(
            oracle._independent_resource_facts(
                "META-INF/spring/not-imports.txt", b"ignored\n"
            ),
            [],
        )

        self.assertEqual(
            oracle._independent_xml_facts(b"x" * (4 * 1024 * 1024 + 1)),
            [["xml_parse_gap", "resource_too_large"]],
        )
        self.assertEqual(
            oracle._independent_xml_facts(b"<!DOCTYPE x [<!ENTITY y 'z'>]><x/>"),
            [["xml_parse_gap", "doctype_or_entity_rejected"]],
        )
        self.assertEqual(
            oracle._independent_xml_facts(b"<!DOCTYPE x [ ]><x/>"),
            [["xml_parse_gap", "doctype_or_entity_rejected"]],
        )
        self.assertEqual(
            oracle._independent_xml_facts(b"<!DOCTYPE x SYSTEM 'unknown.dtd'><x/>"),
            [["xml_parse_gap", "doctype_or_entity_rejected"]],
        )
        self.assertEqual(
            oracle._independent_xml_facts(b"<broken>"),
            [["xml_parse_gap", "malformed_xml"]],
        )
        allowed_doctype = (
            b'<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" '
            b'"https://mybatis.org/dtd/mybatis-3-mapper.dtd">'
            b"<mapper namespace='demo.Allowed'><select id='ok'/></mapper>"
        )
        self.assertIn(
            ["mybatis_mapper_namespace", "demo.Allowed"],
            oracle._independent_xml_facts(allowed_doctype),
        )
        persistence = oracle._independent_xml_facts(
            b"<persistence><class>demo.Entity</class><class> </class><class/></persistence>"
        )
        self.assertIn(["jpa_managed_class", "demo.Entity"], persistence)
        rich_xml = b"""<?xml version='1.0'?>
        <beans xmlns:context='urn:context' xmlns:mybatis='urn:mybatis'
               xmlns:task='urn:task'>
          <bean id='target' class='demo.Target' primary='true' init-method='init'>
            <property name='dependency' ref='dependency'/>
          </bean>
          <bean name='dependency' class='demo.Dependency'/>
          <bean id='quartz' class='org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean'>
            <property name='targetObject'><ref bean='target'/></property>
            <property name='targetMethod'><value>run</value></property>
          </bean>
          <context:component-scan base-package='demo'/>
          <mybatis:scan base-package='demo.mapper'/>
          <plugin interceptor='demo.Plugin'/>
          <typeHandler javaType='demo.Dto' handler='demo.Handler'/>
          <task:scheduled target='target.tick'/>
          <task:scheduled target='&amp;factory' method='build'/>
          <mapper namespace='demo.Mapper'>
            <select id='find' typeHandler='demo.Handler'/>
            <insert id='save'/><update id='change'/><delete id='remove'/>
          </mapper>
        </beans>"""
        facts = oracle._independent_xml_facts(rich_xml)
        fact_pairs = {tuple(row) for row in facts}
        self.assertTrue({
            ("spring_bean_primary", "target|demo.Target"),
            ("spring_init_method", "target|demo.Target|init"),
            ("spring_component_scan", "demo"),
            ("mybatis_mapper_scan", "demo.mapper"),
            ("mybatis_plugin_registration", "demo.Plugin"),
            ("mybatis_type_handler_registration", "demo.Dto|demo.Handler"),
            ("spring_scheduled_method", "target|demo.Target|tick"),
            ("mybatis_mapper_namespace", "demo.Mapper"),
            ("mybatis_statement_type_handler", "find|demo.Handler"),
            ("spring_bean_property_ref", "target|demo.Target|dependency|dependency|demo.Dependency"),
            ("spring_quartz_method", "target|demo.Target|run"),
        }.issubset(fact_pairs), fact_pairs)

        boundary_xml = b"""<beans>
          <bean class='demo.NoIdentity'/>
          <bean id='noClass'/>
          <bean id='dependency' class='demo.Dependency'/>
          <bean id='properties' class='demo.Properties'>
            <constructor-arg/>
            <property/>
            <property name='directBean' bean='dependency'/>
            <property name='directLocal' local='dependency'/>
            <property name='nestedLocal'><ref local='dependency'/></property>
            <property name='nestedText'><ref>dependency</ref></property>
            <property name='emptyNested'><ref/></property>
            <property name='afterWrong'><wrong/><ref bean='dependency'/></property>
          </bean>
          <bean id='quartzEmpty' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'>
            <constructor-arg/>
            <property name='unknown' value='ignored'/>
            <property name='targetObject' ref='dependency'/>
          </bean>
          <bean id='quartzDirect' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'>
            <property name='targetObject' ref='dependency'/>
            <property name='targetMethod' value='execute'/>
          </bean>
          <bean id='quartzMethodOnly' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'>
            <property name='targetMethod' value='missingReference'/>
          </bean>
          <component-scan/><scan/><plugin/><typeHandler javaType='demo.Dto'/>
          <typeHandler handler='demo.RawHandler'/>
          <scheduled/><scheduled ref='dependency'/><scheduled target='plainTarget'/>
          <scheduled target='&amp;factory.tick' method='factoryMethod'/>
          <scheduled target='dependency.tick' method='override'/>
          <scheduled ref='dependency' method='explicit' target='ignored.tick'/>
          <mapper><select/><insert id='plain'/></mapper>
          <class>not.persistence.Root</class>
        </beans>"""
        boundary_pairs = {
            tuple(row) for row in oracle._independent_xml_facts(boundary_xml)
        }
        self.assertIn(
            ("spring_bean_property_ref", (
                "properties|demo.Properties|nestedText|dependency|demo.Dependency"
            )),
            boundary_pairs,
        )
        self.assertIn(
            ("spring_quartz_method", "dependency|demo.Dependency|execute"),
            boundary_pairs,
        )
        self.assertIn(("mybatis_statement", "plain"), boundary_pairs)

    def test_independent_artifact_security_boundary_ignores_orphan_sf(self):
        orphan_sf = {
            "resources": {
                "META-INF/BOOT.SF": [{"semantic_facts": []}],
                "META-INF/MANIFEST.MF": [{
                    "semantic_facts": [["SHA-256-Digest", "digest"]],
                }],
            },
        }
        self.assertFalse(
            oracle._independent_artifact_security_unsupported(orphan_sf)
        )

        signature_block = {
            "resources": {
                "META-INF/APP.SF": [{"semantic_facts": []}],
                "META-INF/APP.RSA": [{"semantic_facts": []}],
            },
        }
        self.assertTrue(
            oracle._independent_artifact_security_unsupported(signature_block)
        )

        sealed = {
            "resources": {
                "META-INF/MANIFEST.MF": [{
                    "semantic_facts": [["sealed", "true"]],
                }],
            },
        }
        self.assertTrue(
            oracle._independent_artifact_security_unsupported(sealed)
        )


if __name__ == "__main__":
    unittest.main()
