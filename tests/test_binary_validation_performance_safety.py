import copy
import csv
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_validation_oracle as oracle  # noqa: E402
import binary_artifact_diff as production_artifact  # noqa: E402
import final_artifact_edge_oracle as edge_oracle  # noqa: E402
from binary_first_contract import restore_jvm_text, transport_jvm_text  # noqa: E402
from binary_tool_execution import BinaryToolFailure, BinaryToolResult  # noqa: E402


class BinaryValidationPerformanceSafetyTest(unittest.TestCase):
    def test_transient_string_pool_and_projection_cache_are_hard_bounded(self):
        with patch.object(
            oracle, "MAX_VALIDATION_STRING_POOL_ENTRIES", 3,
        ), patch.object(
            oracle, "MAX_VALIDATION_POOLED_STRING_CHARS", 8,
        ):
            pool = {}
            first = oracle._pooled_string("same", pool)
            self.assertIs(oracle._pooled_string("same", pool), first)
            for value in ("two", "three", "four", "five"):
                self.assertEqual(oracle._pooled_string(value, pool), value)
            self.assertEqual(len(pool), 3)
            long_value = "x" * 9
            self.assertEqual(
                oracle._pooled_string(long_value, pool), long_value
            )
            self.assertNotIn(long_value, pool)

        loads = []
        cache = oracle._BoundedProjectionCache(2)

        def load(identities):
            loads.append(identities)
            return {
                identity: identity.upper()
                for identity in identities
                if identity != "missing"
            }

        self.assertEqual(
            cache.resolve(("a", "missing", "a"), load), {"a": "A"}
        )
        self.assertEqual(
            cache.resolve(("a", "missing", "b"), load),
            {"a": "A", "b": "B"},
        )
        self.assertEqual(loads, [("a", "missing"), ("b",)])
        self.assertLessEqual(len(cache.values), 2)

    def test_artifact_truth_identity_uses_bounded_native_fast_path(self):
        rows = [
            ("demo.Caller", "run", "()V", index)
            for index in range(50)
        ]
        expected = oracle.canonical_identity_streaming(
            "artifact-facts", rows, schema_version="1"
        )
        with patch.object(
            oracle,
            "canonical_identity_native_json",
            wraps=oracle.canonical_identity_native_json,
        ) as native, patch.object(
            oracle,
            "canonical_identity_streaming",
            wraps=oracle.canonical_identity_streaming,
        ) as streaming:
            actual = oracle._artifact_truth_identity("artifact-facts", rows)
        self.assertEqual(actual, expected)
        native.assert_called_once()
        streaming.assert_not_called()

        with patch.object(
            oracle, "_NATIVE_ARTIFACT_IDENTITY_MAX_ESTIMATED_BYTES", 1
        ), patch.object(
            oracle,
            "canonical_identity_streaming",
            wraps=oracle.canonical_identity_streaming,
        ) as streaming:
            bounded = oracle._artifact_truth_identity("artifact-facts", rows)
        self.assertEqual(bounded, expected)
        streaming.assert_called_once()

    def test_large_item_progress_is_bounded_but_keeps_boundaries(self):
        events = []
        for current in range(1, 401):
            oracle._notify_counted_progress(
                lambda *event: events.append(event),
                "validation-inventory",
                "working",
                current,
                400,
                f"artifact-{current}",
            )

        self.assertEqual(len(events), 21)
        self.assertEqual(events[0][2:4], (1, 400))
        self.assertEqual(events[-1][2:4], (400, 400))

    def test_closed_world_disk_index_replays_all_transition_domains(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            database = generation / "current_binary_facts.sqlite"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE direct_edges (
                    direct_edge_identity TEXT PRIMARY KEY,
                    caller_member_identity TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    symbolic_owner TEXT NOT NULL,
                    symbolic_name TEXT NOT NULL,
                    symbolic_descriptor TEXT NOT NULL
                );
                CREATE INDEX direct_edges_caller_member
                    ON direct_edges(caller_member_identity);
                CREATE TABLE reconciliation_records (
                    chunk_identity BLOB PRIMARY KEY,
                    record_kind INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    payload_zlib BLOB NOT NULL
                );
                """
            )
            connection.executemany(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?)",
                [
                    ("edge-method", "caller", "method", "demo/B", "run", "()V"),
                    ("edge-type", "caller", "type", "demo/T", "", "Ldemo/T;"),
                    ("edge-init", "caller", "class_init", "demo/I", "", ""),
                ],
            )

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

            add_chunk("member_resolution", [
                {
                    # Deliberately starts after edge-method in rowid order.
                    "direct_edge_identity": "edge-type",
                    "member_resolution_status": "type-placeholder",
                },
                {
                    "direct_edge_identity": "edge-orphan",
                    "member_resolution_status": "orphan-status",
                },
                {
                    # This row is now behind the forward cursor and must take
                    # the exact primary-key fallback without being omitted.
                    "direct_edge_identity": "edge-method",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "target-method",
                },
            ])
            add_chunk("dispatch_resolution", [])
            add_chunk("type_resolution", [{
                "direct_edge_identity": "edge-type",
                "type_resolution_status": "resolved",
            }])
            add_chunk("class_initialization_resolution", [{
                "direct_edge_identity": "edge-init",
                "class_initialization_status": "resolved",
                "initializer_target_identities": ["target-init"],
            }])
            add_chunk("linkage_resolution", [{
                "direct_edge_identity": "edge-method",
                "linkage_status": "linked",
            }])
            connection.commit()
            connection.close()
            (generation / "binary_runtime_semantic_overlay.json").write_text(
                json.dumps({
                    "coverage_gaps": [],
                    "rows": [{
                        "caller_member_identity": "caller",
                        "target_member_identity": "target-semantic",
                        "path_certainty": "possible",
                        "semantic_edge_identity": "edge-semantic",
                    }],
                }),
                encoding="utf-8",
            )
            index = oracle._ClosedWorldGraphIndex(
                generation,
                generation / "index.sqlite",
                paired_artifact_missing_targets=set(),
                unresolved_edge_alias_targets={},
            )
            try:
                transitions = set(index.transitions("caller"))
                resolution_status = index.resolution_status("edge-method")
                out_of_order_status = index.resolution_status("edge-type")
                orphan_status = index.resolution_status("edge-orphan")
                linkage_status = index.linkage_status("edge-method")
                member_columns = {
                    str(row[1]) for row in index.connection.execute(
                        "PRAGMA table_info(member_resolution)"
                    )
                }
                temp_tables = {
                    str(row[0]) for row in index.connection.execute(
                        "SELECT name FROM sqlite_temp_master "
                        "WHERE type='table'"
                    )
                }
            finally:
                index.close()

        self.assertIn(("target-method", "exact", "edge-method"), transitions)
        self.assertIn(("target-init", "exact", "edge-init"), transitions)
        self.assertIn(
            ("target-semantic", "possible", "edge-semantic"), transitions
        )
        self.assertTrue(any(row[2] == "edge-type" for row in transitions))
        self.assertEqual(resolution_status, "resolved")
        self.assertEqual(out_of_order_status, "type-placeholder")
        self.assertEqual(orphan_status, "orphan-status")
        self.assertEqual(linkage_status, "linked")
        self.assertEqual(
            member_columns, {"edge_rowid", "status", "resolved_member"}
        )
        self.assertNotIn("edge_order", temp_tables)

    def test_maven_metadata_duplicate_policy_matches_production_and_oracle(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "duplicate-maven.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr(
                        "META-INF/maven/example/jmxmon/pom.xml", b"first"
                    )
                    archive.writestr(
                        "META-INF/maven/example/jmxmon/pom.xml", b"second"
                    )
            with zipfile.ZipFile(artifact) as archive:
                selected, target_required = (
                    production_artifact.select_runtime_resource_entries(
                        archive, 17
                    )
                )
            inventory = oracle._archive_inventory(artifact, 17)

        self.assertFalse(target_required)
        self.assertNotIn(
            "META-INF/maven/example/jmxmon/pom.xml", selected
        )
        self.assertEqual(inventory["failures"], [])
        self.assertNotIn(
            "META-INF/maven/example/jmxmon/pom.xml",
            inventory["resources"],
        )

    def test_non_maven_resource_duplicates_remain_blocking_in_both_paths(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "duplicate-runtime.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("config/runtime.xml", b"first")
                    archive.writestr("config/runtime.xml", b"second")
            with zipfile.ZipFile(artifact) as archive, self.assertRaises(
                production_artifact.BinaryArtifactDiffError
            ) as caught:
                production_artifact.select_runtime_resource_entries(
                    archive, 17
                )
            inventory = oracle._archive_inventory(artifact, 17)

        self.assertEqual(
            caught.exception.reason_code,
            "ARTIFACT_RUNTIME_RESOURCE_DUPLICATE",
        )
        self.assertEqual(
            inventory["failures"],
            ["duplicate_resource:config/runtime.xml:0"],
        )

    def test_low_memory_preflight_emits_nonblocking_progress_warning(self):
        events = []

        def progress(*event):
            events.append(event)

        with patch.object(
            oracle,
            "system_available_memory_bytes",
            return_value=1024,
        ), patch.object(
            oracle,
            "validate_oracle_tool_execution_policy",
            side_effect=RuntimeError("stop after memory preflight"),
        ), self.assertRaisesRegex(RuntimeError, "stop after memory preflight"):
            oracle.validate_generation(
                {}, Path("unused-generation"), progress_callback=progress
            )

        self.assertEqual(events[0][0], "validation-memory-preflight")
        self.assertEqual(events[0][2], 1024)
        self.assertEqual(
            events[0][3], oracle.LOW_AVAILABLE_MEMORY_WARNING_BYTES
        )

    def test_immutable_sqlite_setup_failure_closes_connection(self):
        class FailingConnection:
            def __init__(self):
                self.closed = False

            def execute(self, _statement):
                raise sqlite3.OperationalError("synthetic pragma failure")

            def close(self):
                self.closed = True

        connection = FailingConnection()
        with patch.object(
            oracle.sqlite3, "connect", return_value=connection
        ), self.assertRaisesRegex(
            sqlite3.OperationalError, "synthetic pragma failure"
        ):
            oracle._open_immutable_sqlite(Path("unused.sqlite"))

        self.assertTrue(connection.closed)

    @unittest.skipUnless(shutil.which("java"), "JDK is required")
    def test_runtime_oracle_json_preserves_unpaired_surrogate_member(self):
        from tests.test_final_artifact_edge_oracle import (
            _minimal_static_edge_class,
        )

        content = _minimal_static_edge_class(
            "SurrogateRuntimeFixture", "\ud800"
        )
        settings = subprocess.run(
            ["java", "-XshowSettings:properties", "-version"],
            capture_output=True,
            text=True,
            check=False,
        )
        home_line = next(
            (
                line for line in settings.stderr.splitlines()
                if line.strip().startswith("java.home = ")
            ),
            "",
        )
        if not home_line:
            self.skipTest("java.home is unavailable")
        jdk_home = Path(home_line.split("=", 1)[1].strip())
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "runtime.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "SurrogateRuntimeFixture.class", content
                )
            observations, _helper_identity = oracle._observe_classes(
                jdk_home,
                [{"path": str(artifact)}],
                ["SurrogateRuntimeFixture"],
            )

        observation = observations["SurrogateRuntimeFixture"]
        member = next(
            value for value in observation["members"]
            if value.startswith("method|") and value.endswith("|()V|9")
        )
        _kind, name, _descriptor, _flags = oracle._member_tuple(member)
        self.assertEqual(name, transport_jvm_text("\ud800"))
        self.assertEqual(restore_jvm_text(name), "\ud800")

    @unittest.skipUnless(
        shutil.which("javac") and shutil.which("javap"), "JDK is required"
    )
    def test_module_info_classes_follow_acc_module_through_validation(self):
        from tests.test_final_artifact_edge_oracle import (
            _minimal_static_edge_class,
        )

        ordinary = _minimal_static_edge_class(
            "module-info", "ordinaryRoot"
        )
        malformed_module = _minimal_static_edge_class(
            "invalid/module-info", "invalidFlag"
        )
        access_marker = b"\x00\x21\x00\x02\x00\x04\x00\x00"
        access_offset = malformed_module.index(access_marker)
        malformed_module = (
            malformed_module[:access_offset]
            + oracle.ACC_MODULE.to_bytes(2, "big")
            + malformed_module[access_offset + 2:]
        )
        self.assertEqual(
            oracle._independent_class_access_flags(malformed_module),
            oracle.ACC_MODULE,
        )
        self.assertFalse(
            oracle._independent_is_valid_module_descriptor(malformed_module)
        )
        self.assertFalse(
            edge_oracle._classfile_is_valid_module_descriptor(malformed_module)
        )

        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            module_source = root / "module-info.java"
            module_source.write_text(
                "module fixture.module { }", encoding="utf-8"
            )
            module_classes = root / "module-classes"
            module_classes.mkdir()
            compiled = subprocess.run(
                ["javac", "-d", str(module_classes), str(module_source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            valid_descriptor = (
                module_classes / "module-info.class"
            ).read_bytes()
            self.assertTrue(
                oracle._independent_is_valid_module_descriptor(
                    valid_descriptor
                )
            )
            self.assertTrue(
                edge_oracle._classfile_is_valid_module_descriptor(
                    valid_descriptor
                )
            )

            artifact_path = root / "module-info-boundaries.jar"
            with zipfile.ZipFile(artifact_path, "w") as archive:
                archive.writestr("module-info.class", ordinary)
                archive.writestr(
                    "invalid/module-info.class", malformed_module
                )
                archive.writestr(
                    "descriptor/module-info.class", valid_descriptor
                )
            artifact_sha = hashlib.sha256(
                artifact_path.read_bytes()
            ).hexdigest()
            artifact = {
                "path": str(artifact_path),
                "sha256": artifact_sha,
                "loader_realm": "application-loader",
                "slot": 0,
            }
            inventory = oracle._archive_inventory(artifact_path, 21)

            self.assertEqual(inventory["failures"], [])
            self.assertEqual(
                inventory["classes"],
                {
                    "module-info": "module-info.class",
                    "invalid/module-info": "invalid/module-info.class",
                },
            )

            connection = self.edge_connection()
            self.addCleanup(connection.close)
            connection.execute(
                "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                ("artifact-1", artifact_sha, "application-loader", 0),
            )
            for index, (owner, member) in enumerate((
                ("module-info", "ordinaryRoot"),
                ("invalid/module-info", "invalidFlag"),
            )):
                member_identity = f"member-{index}"
                connection.execute(
                    "INSERT INTO members VALUES (?,?,?,?)",
                    (member_identity, owner, member, "()V"),
                )
                connection.execute(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        "artifact-1", member_identity, "method",
                        "java/lang/System", "gc", "()V", 184, 0,
                        json.dumps({"interface": False}),
                    ),
                )
                connection.execute(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        "artifact-1", member_identity, "class_init",
                        "java/lang/System", "", "", 184, 0,
                        json.dumps({"trigger_kind": "invokestatic"}),
                    ),
                )

            direct_scan_cache = {}
            direct_issues, direct_truth = oracle._validate_direct_edges(
                connection,
                [artifact],
                javap=str(shutil.which("javap")),
                scan_cache=direct_scan_cache,
            )
            structural_issues, structural_truth = (
                oracle._validate_structural_edges(
                    connection,
                    [artifact],
                    [inventory],
                    javap=str(shutil.which("javap")),
                    direct_scan_cache=direct_scan_cache,
                )
            )

        self.assertEqual(direct_issues, [])
        self.assertEqual(structural_issues, [])
        self.assertEqual(
            set(direct_truth["discovery_classes"]),
            {"java/lang/System"},
        )
        self.assertEqual(
            {
                (row[0], row[1])
                for row in direct_truth["direct_edges"]
            },
            {
                ("module-info", "ordinaryRoot"),
                ("invalid.module-info", "invalidFlag"),
            },
        )
        self.assertEqual(
            {
                (row[0], row[1])
                for row in structural_truth["declared_members"]
            },
            {
                ("module-info", "method"),
                ("invalid/module-info", "method"),
            },
        )

    @unittest.skipUnless(
        shutil.which("java") and shutil.which("javac"), "JDK is required"
    )
    def test_mr_manifest_main_section_and_version_floor_match_all_scanners(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            named_section = root / "named-section.jar"
            with zipfile.ZipFile(named_section, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\n\r\n"
                    "Name: demo/Api.class\r\n"
                    "Multi-Release: true\r\n\r\n",
                )
                archive.writestr("demo/Api.class", b"base")
                archive.writestr(
                    "META-INF/versions/9/demo/Api.class", b"named-section"
                )
            with zipfile.ZipFile(named_section) as archive:
                self.assertFalse(
                    production_artifact._manifest_is_multi_release(archive)
                )
                self.assertFalse(oracle._manifest_multi_release(archive))
                self.assertFalse(edge_oracle._is_multi_release_archive(archive))

            self.assertEqual(
                oracle._archive_inventory(named_section, 21)["classes"],
                {"demo/Api": "demo/Api.class"},
            )

            low_version = root / "low-version.jar"
            with zipfile.ZipFile(low_version, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
                )
                archive.writestr("demo/Api.class", b"base")
                archive.writestr(
                    "META-INF/versions/7/demo/Api.class", b"pre-java8"
                )
                archive.writestr(
                    "META-INF/versions/09/demo/Api.class", b"leading-zero"
                )
                archive.writestr(
                    "META-INF/versions/9/demo//Api.class",
                    b"noncanonical-logical-path",
                )
                archive.writestr(
                    "META-INF/versions/9/demo/../Api.class",
                    b"parent-traversal-logical-path",
                )
                archive.writestr(
                    "META-INF/versions/9/META-INF/Hidden.class",
                    b"prohibited-meta-inf-class",
                )
            self.assertEqual(
                oracle._archive_inventory(low_version, 21)["classes"],
                {"demo/Api": "demo/Api.class"},
            )
            with zipfile.ZipFile(low_version) as archive:
                selected, failures = edge_oracle._select_effective_classes(
                    archive.infolist(), 21, "fixture", True
                )
            self.assertEqual(failures, [])
            self.assertEqual(
                [item.filename for item in selected], ["demo/Api.class"]
            )

            continued = root / "continued-main-attribute.jar"
            with zipfile.ZipFile(continued, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\n"
                    "Multi-Release: tr\r\n ue\r\n\r\n",
                )
            with zipfile.ZipFile(continued) as archive:
                self.assertFalse(
                    production_artifact._manifest_is_multi_release(archive)
                )
                self.assertFalse(oracle._manifest_multi_release(archive))
                self.assertFalse(edge_oracle._is_multi_release_archive(archive))

            for label, attribute in (
                ("leading-space", "Multi-Release:  true"),
                ("trailing-space", "Multi-Release: true "),
                ("missing-space", "Multi-Release:true"),
            ):
                noncanonical = root / f"{label}.jar"
                with zipfile.ZipFile(noncanonical, "w") as archive:
                    archive.writestr(
                        "META-INF/MANIFEST.MF",
                        f"Manifest-Version: 1.0\r\n{attribute}\r\n\r\n",
                    )
                with zipfile.ZipFile(noncanonical) as archive:
                    self.assertFalse(
                        production_artifact._manifest_is_multi_release(archive)
                    )
                    self.assertFalse(oracle._manifest_multi_release(archive))
                    self.assertFalse(
                        edge_oracle._is_multi_release_archive(archive)
                    )

            probe_source = root / "JarManifestProbe.java"
            probe_source.write_text(
                """
                import java.io.File;
                import java.util.jar.JarFile;
                import java.util.zip.ZipFile;
                public class JarManifestProbe {
                  public static void main(String[] args) throws Exception {
                    try (var jar = new JarFile(
                        new File(args[0]), true, ZipFile.OPEN_READ,
                        Runtime.Version.parse("9"))) {
                      var entry = jar.getJarEntry("config/runtime.xml");
                      System.out.print(jar.isMultiRelease());
                      System.out.print("|");
                      System.out.print(entry == null ? "<missing>" : entry.getRealName());
                    }
                  }
                }
                """,
                encoding="utf-8",
            )
            compiled = subprocess.run(
                ["javac", str(probe_source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

            def manifest(value):
                return (
                    "Manifest-Version: 1.0\r\n"
                    f"Multi-Release: {value}\r\n\r\n"
                )

            def jarfile_truth(path):
                completed = subprocess.run(
                    ["java", "-cp", str(root), "JarManifestProbe", str(path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                return completed.stdout

            lowercase_only = root / "lowercase-only-manifest.jar"
            with zipfile.ZipFile(lowercase_only, "w") as archive:
                archive.writestr("meta-inf/manifest.mf", manifest("true"))
                archive.writestr("config/runtime.xml", b"base")
                archive.writestr(
                    "META-INF/versions/9/config/runtime.xml", b"v9"
                )
            self.assertEqual(
                jarfile_truth(lowercase_only),
                "true|META-INF/versions/9/config/runtime.xml",
            )
            with zipfile.ZipFile(lowercase_only) as archive:
                self.assertTrue(
                    production_artifact._manifest_is_multi_release(archive)
                )
                self.assertTrue(oracle._manifest_multi_release(archive))
                self.assertTrue(edge_oracle._is_multi_release_archive(archive))

            duplicate_variants = (
                (
                    "true-then-false",
                    (("META-INF/MANIFEST.MF", "true"),
                     ("meta-inf/manifest.mf", "false")),
                    "false|config/runtime.xml",
                ),
                (
                    "false-then-true",
                    (("meta-inf/manifest.mf", "false"),
                     ("META-INF/MANIFEST.MF", "true")),
                    "true|META-INF/versions/9/config/runtime.xml",
                ),
                (
                    "both-true",
                    (("META-INF/MANIFEST.MF", "true"),
                     ("meta-inf/manifest.mf", "true")),
                    "true|META-INF/versions/9/config/runtime.xml",
                ),
            )
            for label, manifests, expected_truth in duplicate_variants:
                duplicate_manifest = root / f"case-duplicate-{label}.jar"
                with zipfile.ZipFile(duplicate_manifest, "w") as archive:
                    for name, value in manifests:
                        archive.writestr(name, manifest(value))
                    archive.writestr("demo/Api.class", b"base-class")
                    archive.writestr(
                        "META-INF/versions/9/demo/Api.class", b"v9-class"
                    )
                    archive.writestr("config/runtime.xml", b"base")
                    archive.writestr(
                        "META-INF/versions/9/config/runtime.xml", b"v9"
                    )

                # OpenJDK currently uses the last case-insensitive manifest
                # entry. That central-directory-order rule is not portable,
                # so all three independent scanners fail closed instead of
                # silently treating an ambiguous artifact as base-only.
                self.assertEqual(
                    jarfile_truth(duplicate_manifest), expected_truth
                )
                with zipfile.ZipFile(duplicate_manifest) as archive:
                    self.assertFalse(
                        production_artifact._manifest_is_multi_release(archive)
                    )
                    self.assertFalse(oracle._manifest_multi_release(archive))
                    self.assertFalse(
                        edge_oracle._is_multi_release_archive(archive)
                    )
                    with self.assertRaises(
                        production_artifact.BinaryArtifactDiffError
                    ) as raised:
                        production_artifact.select_runtime_resource_entries(
                            archive, 9
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "ARTIFACT_MULTI_RELEASE_MANIFEST_AMBIGUOUS",
                    )
                inventory = oracle._archive_inventory(duplicate_manifest, 9)
                self.assertTrue(any(
                    failure.startswith("ambiguous_multi_release_manifest:")
                    for failure in inventory["failures"]
                ))
                extracted = root / f"extracted-{label}"
                extracted.mkdir()
                classes, failures = edge_oracle._extract_packaged_classes(
                    duplicate_manifest.read_bytes(),
                    extracted,
                    9,
                    defer_writes=True,
                )
                self.assertEqual(classes, [])
                self.assertTrue(any(
                    "ambiguous case-insensitive MR manifest entries" in failure
                    for failure in failures
                ))

    def test_independent_inventory_selects_mr_resources_like_jarfile(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "mr-resources.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
                )
                archive.writestr("demo/Api.class", b"base-class")
                archive.writestr(
                    "META-INF/versions/8/demo/Api.class", b"version8-class"
                )
                archive.writestr("config/runtime.xml", b"base")
                archive.writestr(
                    "META-INF/versions/8/config/runtime.xml", b"v8"
                )
                archive.writestr(
                    "META-INF/versions/8/config/v8-only.xml", b"v8-only"
                )
                archive.writestr(
                    "META-INF/versions/9/config/runtime.xml", b"v9"
                )
                archive.writestr(
                    "META-INF/services/demo.Service", b"demo.Base\n"
                )
                archive.writestr(
                    "META-INF/versions/9/META-INF/services/demo.Service",
                    b"demo.Versioned\n",
                )
                archive.writestr(
                    "META-INF/versions/09/config/ignored.xml", b"ignored"
                )

            jdk8 = oracle._archive_inventory(artifact, 8)
            jdk9 = oracle._archive_inventory(artifact, 9)
            with zipfile.ZipFile(artifact) as archive:
                final_jdk8, failures8 = edge_oracle._select_effective_classes(
                    archive.infolist(), 8, "fixture", True
                )
                final_jdk9, failures9 = edge_oracle._select_effective_classes(
                    archive.infolist(), 9, "fixture", True
                )

        self.assertEqual(jdk8["classes"]["demo/Api"], "demo/Api.class")
        self.assertEqual(
            jdk9["classes"]["demo/Api"],
            "META-INF/versions/8/demo/Api.class",
        )
        self.assertEqual(failures8, [])
        self.assertEqual(failures9, [])
        self.assertEqual(
            [item.filename for item in final_jdk8], ["demo/Api.class"]
        )
        self.assertEqual(
            [item.filename for item in final_jdk9],
            ["META-INF/versions/8/demo/Api.class"],
        )
        self.assertEqual(
            jdk8["resources"]["config/runtime.xml"][0]["sha256"],
            hashlib.sha256(b"base").hexdigest(),
        )
        self.assertEqual(
            jdk9["resources"]["config/runtime.xml"][0]["sha256"],
            hashlib.sha256(b"v9").hexdigest(),
        )
        self.assertEqual(
            jdk9["resources"]["META-INF/services/demo.Service"][0]["sha256"],
            hashlib.sha256(b"demo.Base\n").hexdigest(),
        )
        self.assertNotIn(
            "META-INF/versions/9/META-INF/services/demo.Service",
            jdk9["resources"],
        )
        self.assertNotIn("config/ignored.xml", jdk9["resources"])
        self.assertNotIn("config/v8-only.xml", jdk8["resources"])
        self.assertEqual(
            jdk9["resources"]["config/v8-only.xml"][0]["sha256"],
            hashlib.sha256(b"v8-only").hexdigest(),
        )

    def test_oracle_retry_count_rejects_lossy_float_coercion(self):
        with self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._oracle_tool_execution_policy({
                "tool_execution_policy": {"oracle_max_attempts": 1.9}
            })

        self.assertEqual(
            error.exception.reason_code,
            "BINARY_ORACLE_TOOL_POLICY_INVALID",
        )

    def test_oracle_time_budget_rejects_boolean_coercion(self):
        with self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._oracle_tool_execution_policy({
                "tool_execution_policy": {
                    "oracle_javap_time_budget_seconds": True,
                }
            })

        self.assertEqual(
            error.exception.reason_code,
            "BINARY_ORACLE_TOOL_POLICY_INVALID",
        )

    def test_generation_identity_requires_every_pipeline_sidecar_declaration(self):
        manifest = {
            "schema": "java-upgrade-analyzer.binary-result-generation.v1",
            "authority": "binary_first",
            "analysis_context_identity": "context",
            "trace_result_set_digest": "trace",
            "active_snapshot_identities": {
                layer: f"{layer}-identity"
                for layer in (
                    "decision",
                    "assessment",
                    "formal_projection",
                    "candidate_projection",
                )
            },
            "sidecar_content_identities": {
                name: "a" * 64
                for name in oracle._REQUIRED_PIPELINE_GENERATION_SIDECARS
            },
            "policy_identities": {},
        }

        self.assertIsNotNone(
            oracle._expected_result_generation_identity(manifest)
        )
        manifest["sidecar_content_identities"].pop(
            "binary_runtime_semantic_overlay.json"
        )
        self.assertIsNone(
            oracle._expected_result_generation_identity(manifest)
        )

    def test_source_sidecars_are_bound_to_source_overlay_presence(self):
        required = {
            name: "a" * 64
            for name in oracle._REQUIRED_PIPELINE_GENERATION_SIDECARS
        }
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            missing = oracle._generation_sidecar_declaration_issues(
                {"source_overlay": {"source_sets": []}},
                generation,
                required,
            )
            self.assertEqual(
                {
                    issue["evidence"]["sidecar"]
                    for issue in missing
                    if issue["reason_code"]
                    == "ORACLE_GENERATION_REQUIRED_SOURCE_SIDECAR_UNDECLARED"
                },
                set(oracle._RESERVED_OPTIONAL_GENERATION_SIDECARS),
            )

            injected = generation / "binary_inline_overlay.json"
            injected.write_text("{}\n", encoding="utf-8")
            undeclared = oracle._generation_sidecar_declaration_issues(
                {}, generation, required
            )
            self.assertIn(
                "ORACLE_GENERATION_UNDECLARED_RESERVED_SIDECAR",
                {issue["reason_code"] for issue in undeclared},
            )

            declared = {
                **required,
                **{
                    name: "b" * 64
                    for name in oracle._RESERVED_OPTIONAL_GENERATION_SIDECARS
                },
            }
            unexpected = oracle._generation_sidecar_declaration_issues(
                {}, generation, declared
            )
            self.assertEqual(
                {
                    issue["evidence"]["sidecar"]
                    for issue in unexpected
                    if issue["reason_code"]
                    == "ORACLE_GENERATION_UNEXPECTED_SOURCE_SIDECAR_DECLARED"
                },
                set(oracle._RESERVED_OPTIONAL_GENERATION_SIDECARS),
            )

    def test_unbound_sqlite_wal_is_rejected_and_immutable_reader_ignores_it(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            database = generation / "base_binary_facts.sqlite"
            writer = sqlite3.connect(database)
            self.addCleanup(writer.close)
            self.assertEqual(
                writer.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                "wal",
            )
            writer.execute("PRAGMA wal_autocheckpoint = 0")
            writer.execute("CREATE TABLE authority(value TEXT NOT NULL)")
            writer.execute("INSERT INTO authority VALUES ('bound')")
            writer.commit()
            writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            bound_main_digest = hashlib.sha256(database.read_bytes()).hexdigest()

            # This committed row is authoritative to a normal mode=ro reader,
            # while the content-addressed main database remains unchanged.
            writer.execute("INSERT INTO authority VALUES ('unbound-wal')")
            writer.commit()
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                bound_main_digest,
            )
            ordinary = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
            try:
                self.assertEqual(
                    ordinary.execute("SELECT count(*) FROM authority").fetchone()[0],
                    2,
                )
            finally:
                ordinary.close()
            immutable = oracle._open_immutable_sqlite(database)
            try:
                self.assertEqual(
                    immutable.execute("SELECT count(*) FROM authority").fetchone()[0],
                    1,
                )
            finally:
                immutable.close()

            issues = oracle._generation_sidecar_declaration_issues(
                {},
                generation,
                {
                    name: "a" * 64
                    for name in oracle._REQUIRED_PIPELINE_GENERATION_SIDECARS
                },
            )

        transient_issues = [
            issue for issue in issues
            if issue["reason_code"]
            == "ORACLE_GENERATION_SQLITE_TRANSIENT_SIDECAR_PRESENT"
        ]
        self.assertIn(
            "base_binary_facts.sqlite-wal",
            {issue["evidence"]["sidecar"] for issue in transient_issues},
        )

    def test_cross_version_oracle_covers_fields_but_not_owner_definition_failures(self):
        field_edge = (
            "demo.Caller", "field", "()V", "demo.Api", "value", "I",
            "getfield", 4, "field",
        )
        inherited_edge = (
            "demo.Caller", "inherited", "()V", "demo.Child", "gone", "()V",
            "invokevirtual", 7, "method",
        )
        removed_class_edge = (
            "demo.Caller", "removedClass", "()V", "demo.Gone", "call", "()V",
            "invokevirtual", 10, "method",
        )
        failed_definition_edge = (
            "demo.Caller", "broken", "()V", "demo.Broken", "call", "()V",
            "invokevirtual", 13, "method",
        )

        def ready(*members, super_name="java/lang/Object"):
            return {
                "status": "definition_ready",
                "super_name": super_name,
                "interfaces": [],
                "members": list(members),
            }

        observations = {
            "base": {
                "demo/Api": ready("field|value|I|1"),
                "demo/Child": ready(super_name="demo/Parent"),
                "demo/Parent": ready("method|gone|()V|1"),
                "demo/Gone": ready("method|call|()V|1"),
                "demo/Broken": ready("method|call|()V|1"),
                "java/lang/Object": ready(super_name=""),
            },
            "current": {
                "demo/Api": ready(),
                "demo/Child": ready(super_name="demo/Parent"),
                "demo/Parent": ready(),
                "demo/Gone": {"status": "not_found"},
                "demo/Broken": {
                    "status": "definition_failed",
                    "failure_phase": "superclass_linkage",
                },
                "java/lang/Object": ready(super_name=""),
            },
        }

        def decision(edge, base_owner):
            return {
                "reason_code": "RUNTIME_MEMBER_RESOLUTION_CHANGED",
                "fact_scope": {
                    "class_name": base_owner,
                    "member_name": edge[4],
                    "descriptor": edge[5],
                },
                "evidence": {
                    "semantic_caller_edge": {
                        "caller_class": edge[0].replace(".", "/"),
                        "caller_member": edge[1],
                        "caller_descriptor": edge[2],
                        "bytecode_offset": edge[7],
                    },
                    "base_resolution": {"resolved_owner": base_owner},
                    "current_resolution": {},
                },
            }

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            (generation / "binary_decisions.json").write_text(
                json.dumps({
                    "authoritative_change_facts": [
                        decision(field_edge, "demo/Api"),
                        decision(inherited_edge, "demo/Parent"),
                    ]
                }),
                encoding="utf-8",
            )
            (generation / "binary_formal_results.json").write_text(
                json.dumps({"resource_activation_results": []}),
                encoding="utf-8",
            )
            edges = [
                field_edge, inherited_edge, removed_class_edge,
                failed_definition_edge,
            ]
            truth_parts = {
                "base": {
                    "direct_edges": edges,
                    "resource_selections": [],
                },
                "current": {
                    "direct_edges": edges,
                    "resource_selections": [],
                    "type_edges": [],
                },
            }

            issues, truth = oracle._validate_cross_version_semantics(
                generation, {"current": {}}, truth_parts, observations
            )

        self.assertEqual(issues, [])
        self.assertEqual(len(truth["member_resolution_changes"]), 2)
        self.assertEqual(
            {row[4] for row in truth["member_resolution_changes"]},
            {"demo.Api", "demo.Parent"},
        )

    def test_cross_version_resource_reachability_traverses_only_method_edges(self):
        service_name = "META-INF/services/demo.Service"
        service_load = (
            "demo.Helper", "load", "()V",
            "java.util.ServiceLoader", "load",
            "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
            "invokestatic", 3, "method",
        )
        method_hop = (
            "demo.Main", "entry", "()V",
            "demo.Helper", "load", "()V",
            "invokestatic", 0, "method",
        )
        field_access = (
            "demo.Main", "entry", "()V",
            "demo.Holder", "helper", "Ldemo/Helper;",
            "getstatic", 0, "field",
        )

        def ready(*members):
            return {
                "status": "definition_ready",
                "super_name": "java/lang/Object",
                "interfaces": [],
                "members": list(members),
            }

        side_observations = {
            "demo/Helper": ready("method|load|()V|9"),
            "demo/Holder": ready("field|helper|Ldemo/Helper;|9"),
            "java/util/ServiceLoader": ready(
                "method|load|(Ljava/lang/Class;)Ljava/util/ServiceLoader;|9"
            ),
            "java/lang/Object": {
                "status": "definition_ready",
                "super_name": "",
                "interfaces": [],
                "members": [],
            },
        }
        observations = {
            "base": side_observations,
            "current": json.loads(json.dumps(side_observations)),
        }
        config = {"current": {"runtime_profile": {
            "business_entrypoint_profile": {"methods": [{
                "class_name": "demo/Main",
                "member_name": "entry",
                "descriptor": "()V",
            }]},
        }}}

        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            (generation / "binary_decisions.json").write_text(
                json.dumps({"authoritative_change_facts": []}),
                encoding="utf-8",
            )
            for first_edge, expected_status in (
                (method_hop, "reachable"),
                (field_access, "not_found_in_static_analysis"),
            ):
                (generation / "binary_formal_results.json").write_text(
                    json.dumps({"resource_activation_results": [{
                        "resource_name": service_name,
                        "activation_status": expected_status,
                    }]}),
                    encoding="utf-8",
                )
                edges = [first_edge, service_load]
                selections = [{
                    "realm": "application-loader",
                    "name": service_name,
                    "mechanism": "service_loader",
                    "selected": ["demo.Provider"],
                }]
                truth_parts = {
                    "base": {
                        "direct_edges": edges,
                        "resource_selections": [{
                            **selections[0],
                            "selected": ["demo.OldProvider"],
                        }],
                    },
                    "current": {
                        "direct_edges": edges,
                        "resource_selections": selections,
                        "type_edges": [[
                            "demo/Helper", "load", "()V", 1,
                            "demo/Service", "class_literal",
                        ]],
                    },
                }

                with self.subTest(first_edge=first_edge[6]):
                    issues, truth = oracle._validate_cross_version_semantics(
                        generation, config, truth_parts, observations
                    )

                    self.assertEqual(issues, [])
                    self.assertEqual(
                        truth["resource_activation_status"][service_name],
                        expected_status,
                    )

    def test_parent_first_oracle_artifacts_follow_effective_loader_order(self):
        artifacts = [
            {"path": "/fixture/child-2.jar", "loader_realm": "child", "slot": 2},
            {"path": "/fixture/parent.jar", "loader_realm": "parent", "slot": 0},
            {"path": "/fixture/child-1.jar", "loader_realm": "child", "slot": 1},
        ]
        topology = {
            "realms": [
                {"identity": "platform", "kind": "platform"},
                {
                    "identity": "parent", "kind": "url",
                    "parent": "platform", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
                {
                    "identity": "child", "kind": "url",
                    "parent": "parent", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ]
        }

        selected = oracle._oracle_artifacts_for_entrypoint_realms(
            artifacts, topology, ["child"]
        )

        self.assertEqual(
            [item["path"] for item in selected],
            [
                "/fixture/parent.jar",
                "/fixture/child-1.jar",
                "/fixture/child-2.jar",
            ],
        )

    def test_oracle_loader_flattening_fails_closed_on_ambiguous_realms(self):
        artifacts = [
            {"path": "/fixture/a.jar", "loader_realm": "a", "slot": 0},
            {"path": "/fixture/b.jar", "loader_realm": "b", "slot": 0},
        ]
        topology = {
            "realms": [
                {"identity": "platform", "kind": "platform"},
                {
                    "identity": "a", "kind": "url", "parent": "platform",
                    "delegation": "parent_first", "module_mode": "unnamed",
                },
                {
                    "identity": "b", "kind": "url", "parent": "platform",
                    "delegation": "parent_first", "module_mode": "unnamed",
                },
            ]
        }

        with self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._oracle_artifacts_for_entrypoint_realms(
                artifacts, topology, ["a", "b"]
            )

        self.assertEqual(
            error.exception.reason_code,
            "BINARY_ORACLE_ENTRYPOINT_REALM_ORDER_AMBIGUOUS",
        )

    @staticmethod
    def edge_connection():
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL,
                loader_realm_identity TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL
            );
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
                symbolic_owner TEXT,
                symbolic_name TEXT,
                symbolic_descriptor TEXT,
                opcode INTEGER,
                bytecode_offset INTEGER NOT NULL,
                edge_json TEXT NOT NULL
            );
            """
        )
        return connection

    @staticmethod
    def runtime_connection():
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL,
                loader_realm_identity TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL
            );
            CREATE TABLE members (
                member_identity TEXT PRIMARY KEY,
                class_name TEXT NOT NULL,
                member_name TEXT NOT NULL,
                descriptor TEXT NOT NULL
            );
            CREATE TABLE direct_edges (
                direct_edge_identity TEXT PRIMARY KEY,
                edge_kind TEXT NOT NULL,
                symbolic_owner TEXT,
                symbolic_name TEXT,
                symbolic_descriptor TEXT,
                opcode INTEGER
            );
            """
        )
        return connection

    @staticmethod
    def completed_for(names):
        rows = [
            {
                "class_name": name.replace(".", "/"),
                "status": "definition_failed",
                "failure_phase": "class_load",
                "failure_kind": "fixture",
            }
            for name in names
        ]
        return SimpleNamespace(
            succeeded=True,
            stdout="\n".join(json.dumps(row) for row in rows) + "\n",
            failure=None,
        )

    def test_runtime_oracle_batches_every_class_without_sampling(self):
        observed_batches = []
        progress_events = []

        def execute(command, **_kwargs):
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            observed_batches.append(names)
            return self.completed_for(names)

        classes = [f"demo/C{index}" for index in range(5)]
        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 2
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(oracle, "execute_binary_tool", side_effect=execute):
            observations, helper_identity = oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                classes,
                progress_callback=lambda *event: progress_events.append(event),
                progress_label="current",
            )

        self.assertEqual([len(batch) for batch in observed_batches], [2, 2, 1])
        self.assertEqual(
            observed_batches,
            [
                ["demo.C0", "demo.C1"],
                ["demo.C2", "demo.C3"],
                ["demo.C4"],
            ],
        )
        self.assertEqual(
            {name for batch in observed_batches for name in batch},
            {name.replace("/", ".") for name in classes},
        )
        self.assertEqual(set(observations), set(classes))
        self.assertEqual(helper_identity, "helper-identity")
        self.assertEqual(
            [event[2] for event in progress_events], [2, 4, 5]
        )
        self.assertTrue(
            all(event[0] == "validation-runtime" for event in progress_events)
        )

    def test_runtime_oracle_concurrent_batches_preserve_complete_closure(self):
        barrier = threading.Barrier(3)
        initial_threads = set()
        calls = []
        lock = threading.Lock()

        def execute(command, **_kwargs):
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            with lock:
                calls.append(tuple(names))
            if names != ["demo.Parent"]:
                initial_threads.add(threading.current_thread().name)
                barrier.wait(timeout=2)
            rows = []
            for name in names:
                rows.append({
                    "class_name": name.replace(".", "/"),
                    "status": "definition_ready",
                    "super_name": "" if name == "demo.Parent" else "demo/Parent",
                    "interfaces": [],
                })
            return SimpleNamespace(
                succeeded=True,
                stdout="\n".join(json.dumps(row) for row in rows) + "\n",
                failure=None,
            )

        initial = [f"demo/C{index}" for index in range(6)]
        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 2
        ), patch.object(
            oracle, "MIN_CLASSES_FOR_CONCURRENT_RUNTIME_ORACLE", 0
        ), patch.object(
            oracle.os, "cpu_count", return_value=3
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(oracle, "execute_binary_tool", side_effect=execute):
            observations, _helper = oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                initial,
            )

        self.assertEqual(len(initial_threads), 3)
        self.assertEqual(len(calls), 4)
        self.assertEqual(
            set(observations),
            {name.replace(".", "/") for name in [*initial, "demo.Parent"]},
        )

    def test_runtime_oracle_fails_closed_on_incomplete_batch_output(self):
        calls = []

        def incomplete(command, **_kwargs):
            calls.append(command)
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            return self.completed_for(names[:-1])

        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 2
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(
            oracle, "execute_binary_tool", side_effect=incomplete
        ), self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                ["demo/A", "demo/B"],
                max_attempts=3,
            )

        self.assertEqual(
            error.exception.reason_code, "BINARY_ORACLE_OUTPUT_INCOMPLETE"
        )
        self.assertEqual(len(calls), 1)

    def test_runtime_oracle_retries_a_transient_timeout_once(self):
        calls = []

        def execute(command, **_kwargs):
            calls.append(command)
            if len(calls) == 1:
                failure = BinaryToolFailure(
                    stage="binary_oracle.runtime_observation",
                    reason_code="BINARY_ORACLE_EXECUTION_TIMEOUT",
                    failure_kind="timeout",
                    command=tuple(command),
                    timeout_seconds=1,
                    returncode=None,
                    stderr="timed out",
                )
                return BinaryToolResult("", "", -1, failure)
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            return self.completed_for(names)

        with patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(oracle, "execute_binary_tool", side_effect=execute):
            observations, _helper = oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                ["demo/A"],
                max_attempts=2,
            )

        self.assertEqual(len(calls), 2)
        self.assertIn("demo/A", observations)

    def test_runtime_oracle_budget_is_shared_across_all_batches(self):
        calls = []

        def slow_execute(command, **kwargs):
            calls.append(kwargs["timeout_seconds"])
            time.sleep(0.03)
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            return self.completed_for(names)

        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 1
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(
            oracle, "execute_binary_tool", side_effect=slow_execute
        ), self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                ["demo/A", "demo/B"],
                runtime_timeout_seconds=300,
                phase_time_budget_seconds=0.02,
            )

        self.assertEqual(
            error.exception.reason_code,
            "BINARY_ORACLE_RUNTIME_PHASE_TIME_BUDGET_EXCEEDED",
        )
        self.assertEqual(len(calls), 1)
        self.assertLessEqual(calls[0], 0.02)

    def test_compressed_javap_cache_round_trips_all_evidence(self):
        evidence = {
            "complete": True,
            "artifact_sha256": "a" * 64,
            "edges": [{
                "caller_owner": "demo.A",
                "callee_owner": "demo.B",
                "instruction_offset": 7,
            }],
            "structural_facts": {
                "class_names": ["demo/A", "demo/B"],
                "type_edges": [["demo/A", "m", "()V", 7, "demo/B", "new"]],
            },
            "failures": [],
        }

        packed = oracle._pack_oracle_scan(evidence)

        self.assertIsInstance(packed, bytes)
        self.assertEqual(oracle._unpack_oracle_scan(packed), evidence)

    def test_normalized_javap_evidence_preserves_both_validator_views(self):
        evidence = {
            "complete": True,
            "artifact_sha256": "a" * 64,
            "edges": [{
                "caller_owner": "demo.A",
                "caller_member": "run",
                "caller_descriptor": "()V",
                "callee_owner": "demo.B",
                "callee_member": "value",
                "callee_descriptor": "()I",
                "opcode_family": "invokevirtual",
                "instruction_offset": 7,
                "reference_kind": "method",
                "reference_interface": False,
            }],
            "structural_facts": {
                "class_names": ["demo/A"],
                "type_edges": [["demo/A", "run", "()V", 7, "demo/B", "new"]],
                "class_init_edges": [],
                "clinit_classes": [],
                "semantic_instructions": [[
                    "demo/A", "run", "()V", 7, "new", "class demo/B"
                ]],
                "declared_members": [["demo/A", "method", "run", "()V", 1]],
            },
            "failures": [],
        }

        normalized = oracle._normalize_oracle_scan(
            oracle._pack_oracle_scan(evidence), {}
        )

        self.assertEqual(normalized.artifact_sha256, "a" * 64)
        self.assertEqual(normalized.structural_class_names, {"demo/A"})
        self.assertIn(
            (
                "demo.A", "run", "()V", "demo.B", "value", "()I",
                "invokevirtual", 7, "method",
            ),
            normalized.direct_truth.direct_edges,
        )
        self.assertIn(
            ("demo/A", "run", "()V", 7, "demo/B", "new"),
            normalized.structural_truth.type_edges,
        )
        self.assertIs(oracle._normalize_oracle_scan(normalized, {}), normalized)

    def test_normalized_javap_evidence_matches_surrogate_fact_transport(self):
        raw_member = json.loads('"\\ud800"')
        evidence = {
            "complete": True,
            "artifact_sha256": "f" * 64,
            "edges": [{
                "caller_owner": "demo.Caller",
                "caller_member": raw_member,
                "caller_descriptor": "()V",
                "callee_owner": "demo.Target",
                "callee_member": raw_member,
                "callee_descriptor": "()V",
                "opcode_family": "invokevirtual",
                "instruction_offset": 1,
                "reference_kind": "method",
                "reference_interface": False,
            }],
            "structural_facts": {
                "class_names": ["demo/Caller"],
                "type_edges": [],
                "class_init_edges": [],
                "clinit_classes": [],
                "semantic_instructions": [],
                "declared_members": [[
                    "demo/Caller", "method", raw_member, "()V", 1
                ]],
            },
            "failures": [],
        }

        normalized = oracle._normalize_oracle_scan(
            oracle._pack_oracle_scan(evidence), {}
        )
        transported = transport_jvm_text(raw_member)

        self.assertIn(
            (
                "demo.Caller", transported, "()V", "demo.Target",
                transported, "()V", "invokevirtual", 1, "method",
            ),
            normalized.direct_truth.direct_edges,
        )
        self.assertIn(
            ("demo/Caller", "method", transported, "()V", 1),
            normalized.structural_truth.declared_members,
        )

    def test_incomplete_javap_evidence_is_rejected_before_row_projection(self):
        normalized = oracle._normalize_oracle_scan({
            "complete": False,
            "artifact_sha256": "b" * 64,
            "edges": [{"malformed": "partial row must not be consumed"}],
            "failures": ["oracle_parse_incomplete"],
        })

        self.assertFalse(normalized.complete)
        self.assertEqual(normalized.failures, ("oracle_parse_incomplete",))
        self.assertEqual(normalized.direct_truth.direct_edges, frozenset())

    def test_legacy_dynamic_evidence_without_reference_kind_fails_closed(self):
        normalized = oracle._normalize_oracle_scan({
            "complete": True,
            "artifact_sha256": "c" * 64,
            "edges": [{
                "caller_owner": "demo.Caller",
                "caller_member": "run",
                "caller_descriptor": "()V",
                "callee_owner": "demo.Target",
                "callee_member": "call",
                "callee_descriptor": "()V",
                "opcode_family": "invokedynamic",
                "instruction_offset": 0,
            }],
            "failures": [],
        })

        self.assertFalse(normalized.complete)
        self.assertIn(
            "oracle_dynamic_reference_kind_missing_or_invalid",
            normalized.failures,
        )
        self.assertEqual(
            normalized.direct_truth.dynamic_handle_edges, frozenset()
        )

    def test_legacy_direct_evidence_without_reference_kind_fails_closed(self):
        normalized = oracle._normalize_oracle_scan({
            "complete": True,
            "artifact_sha256": "d" * 64,
            "edges": [{
                "caller_owner": "demo.Caller",
                "caller_member": "run",
                "caller_descriptor": "()V",
                "callee_owner": "demo.Target",
                "callee_member": "call",
                "callee_descriptor": "()V",
                "opcode_family": "invokestatic",
                "instruction_offset": 0,
            }],
            "failures": [],
        })

        self.assertFalse(normalized.complete)
        self.assertIn(
            "oracle_direct_reference_kind_missing_or_invalid",
            normalized.failures,
        )
        self.assertEqual(normalized.direct_truth.direct_edges, frozenset())

    def test_equal_observation_sharing_preserves_type_exact_json_evidence(self):
        reference = {
            "demo/A": {
                "status": "definition_ready",
                "provider_url": "file:/same.jar",
                "declared_members": ["method|run|()V|1"],
                "flags": [1, True],
            },
            "demo/B": {
                "status": "definition_ready",
                "provider_url": "file:/base.jar",
                "declared_members": ["method|run|()V|1"],
            },
            "demo/C": {"flags": [1]},
        }
        candidate = copy.deepcopy(reference)
        candidate["demo/B"]["provider_url"] = "file:/current.jar"
        candidate["demo/C"]["flags"] = [True]
        before = json.dumps(
            candidate, sort_keys=True, separators=(",", ":")
        )

        shared_rows, shared_values = oracle._share_equal_observation_values(
            reference, candidate
        )

        self.assertEqual(
            json.dumps(candidate, sort_keys=True, separators=(",", ":")),
            before,
        )
        self.assertEqual(shared_rows, 1)
        self.assertGreaterEqual(shared_values, 3)
        self.assertIs(candidate["demo/A"], reference["demo/A"])
        self.assertIsNot(candidate["demo/B"], reference["demo/B"])
        self.assertIs(
            candidate["demo/B"]["declared_members"],
            reference["demo/B"]["declared_members"],
        )
        self.assertIsNot(
            candidate["demo/C"]["flags"], reference["demo/C"]["flags"]
        )

    def test_compact_observations_preserve_canonical_truth_exactly(self):
        repeated = "method|run|()V|1"
        observations = {
            "demo/A": {
                "class_name": "demo/A",
                "status": "definition_ready",
                "interfaces": ["demo/Api"],
                "members": [repeated],
                "unknown_future_field": [repeated, True, 1],
            },
            "demo/B": {
                "class_name": "demo/B",
                "status": "definition_ready",
                "interfaces": ["demo/Api"],
                "members": [repeated],
            },
        }
        before = oracle.canonical_identity_streaming(
            "fixture", observations, schema_version="1"
        )

        compacted = oracle._compact_observations(
            copy.deepcopy(observations), {}
        )
        after = oracle.canonical_identity_streaming(
            "fixture", compacted, schema_version="1"
        )

        self.assertEqual(after, before)
        self.assertIsInstance(compacted["demo/A"], oracle._CompactObservation)
        self.assertEqual(
            compacted["demo/A"]["unknown_future_field"],
            (repeated, True, 1),
        )
        self.assertIs(
            compacted["demo/A"]["members"][0],
            compacted["demo/B"]["members"][0],
        )

    def test_javap_member_fallback_uses_only_selected_provider_artifact(self):
        first = Path("/fixture/first.jar")
        second = Path("/fixture/second.jar")
        artifacts = [
            {
                "path": str(first),
                "_expected_artifact_instance_identity": "first-instance",
            },
            {
                "path": str(second),
                "_expected_artifact_instance_identity": "second-instance",
            },
        ]
        edge_truth = {
            "declared_members_by_artifact": [
                {
                    "artifact_instance_identity": "first-instance",
                    "members": [[
                        "demo/X", "method", "selected", "()V", 1,
                    ]],
                },
                {
                    "artifact_instance_identity": "second-instance",
                    "members": [[
                        "demo/X", "method", "shadowOnly", "()V", 1,
                    ]],
                },
            ],
            "declared_members": [
                ["demo/X", "method", "selected", "()V", 1],
                ["demo/X", "method", "shadowOnly", "()V", 1],
            ],
        }
        observations = {
            "demo/X": {
                "status": "definition_ready",
                "provider_resource_url": (
                    f"jar:{first.as_uri()}!/demo/X.class"
                ),
            }
        }

        oracle._attach_provider_declared_members(
            artifacts, edge_truth, observations, {}
        )

        self.assertEqual(
            observations["demo/X"]["javap_declared_members"],
            ("method|selected|()V|1",),
        )

    def test_direct_truth_cache_reuses_only_oracle_facts_and_rechecks_database(self):
        artifact_sha = "a" * 64
        artifact = {
            "path": "/fixture/app.jar", "sha256": artifact_sha,
            "loader_realm": "application-loader", "slot": 0,
        }
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [{
                "caller_owner": "demo.A", "caller_member": "run",
                "caller_descriptor": "()V", "callee_owner": "demo.B",
                "callee_member": "value", "callee_descriptor": "()I",
                "opcode_family": "invokevirtual", "instruction_offset": 7,
                "reference_kind": "method", "reference_interface": False,
            }],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            ("artifact-1", artifact_sha, "application-loader", 0),
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("member-1", "demo/A", "run", "()V"),
        )
        connection.execute(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "artifact-1", "member-1", "method", "demo/B", "value",
                "()I", 182, 7, json.dumps({"interface": False}),
            ),
        )
        scan_cache = {}
        truth_cache = {}
        projection_cache = {}
        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ) as scan:
            first_issues, first_truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache=scan_cache, truth_cache=truth_cache,
                validated_projection_cache=projection_cache,
            )
            cached_issues, cached_truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache=scan_cache, truth_cache=truth_cache,
                validated_projection_cache=projection_cache,
            )
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact-1", "member-1", "method", "demo/C", "extra",
                    "()V", 184, 8, json.dumps({"interface": False}),
                ),
            )
            second_issues, second_truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache=scan_cache, truth_cache=truth_cache,
                validated_projection_cache=projection_cache,
            )

        scan.assert_called_once()
        self.assertEqual(first_issues, [])
        self.assertEqual(cached_issues, [])
        self.assertEqual(first_truth, cached_truth)
        self.assertEqual(first_truth, second_truth)
        self.assertIn(
            "ORACLE_DIRECT_EDGE_EXTRA",
            {item["reason_code"] for item in second_issues},
        )

    def test_production_method_reference_interface_flag_must_be_boolean(self):
        artifact_sha = "e" * 64
        artifact = {
            "path": "/fixture/app.jar", "sha256": artifact_sha,
            "loader_realm": "application-loader", "slot": 0,
        }
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [{
                "caller_owner": "demo.A", "caller_member": "run",
                "caller_descriptor": "()V", "callee_owner": "demo.Api",
                "callee_member": "call", "callee_descriptor": "()V",
                "opcode_family": "invokestatic", "instruction_offset": 0,
                "reference_kind": "interface_method",
                "reference_interface": True,
            }],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            ("artifact-1", artifact_sha, "application-loader", 0),
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("member-1", "demo/A", "run", "()V"),
        )
        connection.execute(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "artifact-1", "member-1", "method", "demo/Api", "call",
                "()V", 184, 0, json.dumps({"interface": "true"}),
            ),
        )

        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ):
            issues, _truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache={}, truth_cache={},
            )

        self.assertIn(
            "ORACLE_PRODUCTION_DIRECT_REFERENCE_KIND_INVALID",
            {item["reason_code"] for item in issues},
        )

    def test_direct_edge_javap_budget_is_shared_across_the_whole_phase(self):
        artifacts = [
            {
                "path": f"/fixture/{index}.jar",
                "sha256": f"{index + 1:064x}",
                "loader_realm": "application-loader",
                "slot": index,
            }
            for index in range(4)
        ]
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.executemany(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            [
                (
                    f"artifact-{index}", artifact["sha256"],
                    "application-loader", index,
                )
                for index, artifact in enumerate(artifacts)
            ],
        )

        def slow_scan(path, **_kwargs):
            time.sleep(0.03)
            artifact = next(
                item for item in artifacts if item["path"] == str(path)
            )
            return {
                "complete": True,
                "artifact_sha256": artifact["sha256"],
                "edges": [],
                "failures": [],
            }

        # Use a deterministic phase clock. Runtime call/branch observation can
        # add more than the deliberately tiny 10 ms budget before the executor
        # submits its first task; wall-clock coupling would then test profiler
        # overhead instead of the shared-deadline contract. The main thread
        # sees time expire immediately after its initial submission while the
        # worker still receives a positive remaining budget.
        main_thread = threading.current_thread()
        main_clock_calls = 0
        clock_lock = threading.Lock()

        def phase_clock():
            nonlocal main_clock_calls
            if threading.current_thread() is not main_thread:
                return 0.0
            with clock_lock:
                main_clock_calls += 1
                return 0.0 if main_clock_calls <= 2 else 0.02

        with patch.object(oracle.os, "cpu_count", return_value=1), patch.object(
            oracle, "scan_final_artifact", side_effect=slow_scan
        ) as scan, patch.object(oracle.time, "perf_counter", side_effect=phase_clock):
            issues, _truth = oracle._validate_direct_edges(
                connection,
                artifacts,
                javap="javap",
                time_budget_seconds=0.01,
            )

        self.assertEqual(scan.call_count, 1)
        self.assertEqual(
            [item["reason_code"] for item in issues].count(
                "ORACLE_JAVAP_INVENTORY_INCOMPLETE"
            ),
            3,
        )

    def test_structural_truth_cache_rechecks_database_without_redecoding(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact_path = Path(temp_text) / "app.jar"
            artifact_path.write_bytes(b"immutable-fixture")
            artifact_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            artifact = {
                "path": str(artifact_path), "sha256": artifact_sha,
                "loader_realm": "application-loader", "slot": 0,
            }
            inventory = {"classes": {"demo/A": "demo/A.class"}}
            direct_result = {
                "complete": True,
                "artifact_sha256": artifact_sha,
                "edges": [],
                "failures": [],
                "structural_facts": {
                    "class_names": ["demo/A"],
                    "type_edges": [["demo/A", "run", "()V", 7, "demo/B", "new"]],
                    "class_init_edges": [],
                    "clinit_classes": [],
                    "semantic_instructions": [],
                    "declared_members": [],
                },
            }
            connection = self.edge_connection()
            self.addCleanup(connection.close)
            connection.execute(
                "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                ("artifact-1", artifact_sha, "application-loader", 0),
            )
            connection.execute(
                "INSERT INTO members VALUES (?,?,?,?)",
                ("member-1", "demo/A", "run", "()V"),
            )
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact-1", "member-1", "type", "demo/B", "", "",
                    187, 7, json.dumps({"type_use_kind": "new"}),
                ),
            )
            direct_cache = {
                (artifact_sha, "javap"): oracle._pack_oracle_scan(direct_result)
            }
            structural_cache = {}
            original_unpack = oracle._unpack_oracle_scan
            with patch.object(
                oracle, "_unpack_oracle_scan", wraps=original_unpack
            ) as unpack:
                first_issues, first_truth = oracle._validate_structural_edges(
                    connection, [artifact], [inventory], javap="javap",
                    scan_cache=structural_cache,
                    direct_scan_cache=direct_cache,
                )
                connection.execute(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        "artifact-1", "member-1", "type", "demo/C", "", "",
                        187, 8, json.dumps({"type_use_kind": "new"}),
                    ),
                )
                second_issues, second_truth = oracle._validate_structural_edges(
                    connection, [artifact], [inventory], javap="javap",
                    scan_cache=structural_cache,
                    direct_scan_cache=direct_cache,
                )

        self.assertEqual(unpack.call_count, 1)
        self.assertEqual(first_issues, [])
        self.assertEqual(first_truth, second_truth)
        self.assertIn(
            "ORACLE_TYPE_EDGE_EXTRA",
            {item["reason_code"] for item in second_issues},
        )

    def test_incomplete_shared_javap_scan_never_starts_structural_fallback(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact_path = Path(temp_text) / "app.jar"
            artifact_path.write_bytes(b"immutable-fixture")
            artifact_sha = hashlib.sha256(
                artifact_path.read_bytes()
            ).hexdigest()
            artifact = {
                "path": str(artifact_path),
                "sha256": artifact_sha,
                "loader_realm": "application-loader",
                "slot": 0,
            }
            connection = self.edge_connection()
            self.addCleanup(connection.close)
            connection.execute(
                "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                ("artifact-1", artifact_sha, "application-loader", 0),
            )
            direct_cache = {
                (artifact_sha, "javap"): oracle._pack_oracle_scan({
                    "complete": False,
                    "artifact_sha256": artifact_sha,
                    "edges": [],
                    "failures": [
                        "oracle_javap_phase_time_budget_exceeded"
                    ],
                })
            }

            with patch.object(
                oracle,
                "_scan_structural_edges",
                side_effect=AssertionError(
                    "incomplete shared scan must fail closed"
                ),
            ) as fallback:
                issues, _truth = oracle._validate_structural_edges(
                    connection,
                    [artifact],
                    [{"classes": {"demo/A": "demo/A.class"}}],
                    javap="javap",
                    direct_scan_cache=direct_cache,
                )

        fallback.assert_not_called()
        self.assertIn(
            "ORACLE_STRUCTURAL_SCAN_INCOMPLETE",
            {item["reason_code"] for item in issues},
        )

    def test_structural_fallback_uses_raw_bound_stable_javap_scan(self):
        from tests.test_final_artifact_edge_oracle import (
            _minimal_static_edge_class,
        )

        raw_owner = 'odd/Fallback"line\nbreak'
        raw_member = 'call"line\nbreak'
        raw_descriptor = '(Lodd/Type"line\nbreak;)V'
        content = _minimal_static_edge_class(
            raw_owner, raw_member, raw_descriptor
        )
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "fallback.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("fallback.class", content)
            inventory = {"classes": {raw_owner: "fallback.class"}}

            with patch.object(
                edge_oracle,
                "javap_command",
                wraps=edge_oracle.javap_command,
            ) as stable_command:
                scanned = oracle._scan_structural_edges(
                    artifact, inventory, "javap"
                )

        self.assertEqual(scanned["failures"], [])
        self.assertIn(
            (raw_owner, "method", raw_member, raw_descriptor, 0x0009),
            scanned["declared_members"],
        )
        self.assertIn(
            (
                raw_owner, raw_member, raw_descriptor, 0,
                "java/lang/System", "invokestatic",
            ),
            scanned["class_init_edges"],
        )
        self.assertGreaterEqual(stable_command.call_count, 2)

    def test_direct_edges_bind_same_content_and_slot_to_exact_realm_instance(self):
        artifact_sha = "d" * 64
        artifacts = [
            {
                "path": "/fixture/parent.jar", "sha256": artifact_sha,
                "loader_realm": "parent", "slot": 0,
            },
            {
                "path": "/fixture/child.jar", "sha256": artifact_sha,
                "loader_realm": "child", "slot": 0,
            },
        ]
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [{
                "caller_owner": "demo.A", "caller_member": "run",
                "caller_descriptor": "()V", "callee_owner": "demo.B",
                "callee_member": "value", "callee_descriptor": "()I",
                "opcode_family": "invokevirtual", "instruction_offset": 7,
                "reference_kind": "method", "reference_interface": False,
            }],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.executemany(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            [
                ("parent-instance", artifact_sha, "parent", 0),
                ("child-instance", artifact_sha, "child", 0),
            ],
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("member-1", "demo/A", "run", "()V"),
        )
        # Only the child instance contains the matching production edge. A
        # content+slot alias incorrectly maps both configs to this row and
        # hides the missing parent edge.
        connection.execute(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "child-instance", "member-1", "method", "demo/B", "value",
                "()I", 182, 7, json.dumps({"interface": False}),
            ),
        )

        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ) as scan:
            issues, _truth = oracle._validate_direct_edges(
                connection, artifacts, javap="javap",
                scan_cache={}, truth_cache={},
            )

        scan.assert_called_once()
        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_DIRECT_EDGE_MISSING"],
        )

    def test_direct_edge_parity_includes_constant_dynamic_linkage(self):
        artifact_sha = "f" * 64
        artifact = {
            "path": "/fixture/condy.jar",
            "sha256": artifact_sha,
            "loader_realm": "application-loader",
            "slot": 0,
        }
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [
                {
                    "caller_owner": "demo.Caller",
                    "caller_member": "load",
                    "caller_descriptor": "()Ljava/lang/Object;",
                    "callee_owner": "demo.Bootstrap",
                    "callee_member": "bootstrap",
                    "callee_descriptor": "()Ljava/lang/Object;",
                    "reference_kind": "REF_invokeStatic",
                    "reference_interface": False,
                    "opcode_family": "ldc_constant_dynamic_bootstrap",
                    "instruction_offset": 0,
                },
                {
                    "caller_owner": "demo.Caller",
                    "caller_member": "load",
                    "caller_descriptor": "()Ljava/lang/Object;",
                    "callee_owner": "demo.Target",
                    "callee_member": "VALUE",
                    "callee_descriptor": "I",
                    "reference_kind": "REF_getStatic",
                    "reference_interface": False,
                    "opcode_family": "ldc_bootstrap_handle",
                    "instruction_offset": 0,
                },
            ],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            ("artifact-1", artifact_sha, "application-loader", 0),
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            (
                "member-1", "demo/Caller", "load",
                "()Ljava/lang/Object;",
            ),
        )
        connection.executemany(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    "artifact-1", "member-1",
                    "ldc_constant_dynamic_bootstrap", "demo/Bootstrap",
                    "bootstrap", "()Ljava/lang/Object;", 18, 0,
                    json.dumps({"tag": 6, "interface": False}),
                ),
                (
                    "artifact-1", "member-1", "ldc_bootstrap_handle_0",
                    "demo/Target", "VALUE", "I", 18, 0,
                    json.dumps({"tag": 2, "interface": False}),
                ),
            ],
        )

        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ):
            issues, truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap"
            )

        self.assertEqual(issues, [])
        self.assertEqual(len(truth["dynamic_handle_edges"]), 2)

    def test_dynamic_linkage_kind_mismatch_fails_closed(self):
        artifact_sha = "1" * 64
        artifact = {
            "path": "/fixture/handle.jar",
            "sha256": artifact_sha,
            "loader_realm": "application-loader",
            "slot": 0,
        }
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [{
                "caller_owner": "demo.Caller",
                "caller_member": "load",
                "caller_descriptor": "()Ljava/lang/Object;",
                "callee_owner": "demo.Target",
                "callee_member": "factory",
                "callee_descriptor": "()Ljava/lang/Object;",
                "reference_kind": "REF_invokeStatic",
                "reference_interface": False,
                "opcode_family": "ldc_handle",
                "instruction_offset": 0,
            }],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            ("artifact-1", artifact_sha, "application-loader", 0),
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            (
                "member-1", "demo/Caller", "load",
                "()Ljava/lang/Object;",
            ),
        )
        # Same caller, target and BCI, but a ConstantDynamic bootstrap is not
        # the direct ldc MethodHandle independently observed by javap.
        connection.execute(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "artifact-1", "member-1",
                "ldc_constant_dynamic_bootstrap", "demo/Target", "factory",
                "()Ljava/lang/Object;", 18, 0,
                json.dumps({"tag": 6, "interface": False}),
            ),
        )

        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ):
            issues, _truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap"
            )

        self.assertEqual(
            {item["reason_code"] for item in issues},
            {"ORACLE_DYNAMIC_HANDLE_MISSING", "ORACLE_DYNAMIC_HANDLE_EXTRA"},
        )

    def test_dynamic_reference_tag_mutation_fails_closed(self):
        cases = (
            ("REF_getStatic", False, 4, False, "VALUE", "I"),
            ("REF_invokeVirtual", False, 7, False, "call", "()V"),
            ("REF_invokeStatic", True, 6, False, "call", "()V"),
        )
        for (
            expected_kind,
            expected_interface,
            production_tag,
            production_interface,
            member,
            descriptor,
        ) in cases:
            with self.subTest(
                expected_kind=expected_kind,
                production_tag=production_tag,
            ):
                artifact_sha = "2" * 64
                artifact = {
                    "path": "/fixture/handle-tag.jar",
                    "sha256": artifact_sha,
                    "loader_realm": "application-loader",
                    "slot": 0,
                }
                scan_result = {
                    "complete": True,
                    "artifact_sha256": artifact_sha,
                    "edges": [{
                        "caller_owner": "demo.Caller",
                        "caller_member": "run",
                        "caller_descriptor": "()V",
                        "callee_owner": "demo.Target",
                        "callee_member": member,
                        "callee_descriptor": descriptor,
                        "reference_kind": expected_kind,
                        "reference_interface": expected_interface,
                        "opcode_family": "invokedynamic",
                        "instruction_offset": 0,
                    }],
                    "failures": [],
                }
                connection = self.edge_connection()
                self.addCleanup(connection.close)
                connection.execute(
                    "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                    ("artifact-1", artifact_sha, "application-loader", 0),
                )
                connection.execute(
                    "INSERT INTO members VALUES (?,?,?,?)",
                    ("member-1", "demo/Caller", "run", "()V"),
                )
                connection.execute(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        "artifact-1", "member-1", "invokedynamic_handle_0",
                        "demo/Target", member, descriptor, 186, 0,
                        json.dumps({
                            "tag": production_tag,
                            "interface": production_interface,
                        }),
                    ),
                )

                with patch.object(
                    oracle, "scan_final_artifact", return_value=scan_result
                ):
                    issues, _truth = oracle._validate_direct_edges(
                        connection, [artifact], javap="javap"
                    )

                self.assertEqual(
                    {item["reason_code"] for item in issues},
                    {
                        "ORACLE_DYNAMIC_HANDLE_MISSING",
                        "ORACLE_DYNAMIC_HANDLE_EXTRA",
                    },
                )

    def test_artifact_binding_rejects_wrong_identity_payload(self):
        expected_payload = {
            "outer_artifact_sha256": "a" * 64,
            "container_entry": "<artifact>",
            "content_sha256": "b" * 64,
            "runtime_profile_identity": "c" * 64,
            "path_owner_loader_realm_identity": "application-loader",
            "runtime_path_kind": "classpath",
            "runtime_classpath_index": 0,
            "container_loader_policy_version": "flat-parent-first-v1",
            "runtime_code_source_origin_identity": "d" * 64,
        }
        actual_payload = {
            **expected_payload,
            "container_entry": "BOOT-INF/classes/",
        }
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute(
            """
            CREATE TABLE artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                coord TEXT NOT NULL,
                outer_artifact_sha256 TEXT NOT NULL,
                container_entry TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                runtime_profile_identity TEXT NOT NULL,
                loader_realm_identity TEXT NOT NULL,
                runtime_path_kind TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL,
                container_loader_policy_version TEXT NOT NULL,
                runtime_code_source_origin_identity TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                oracle._identity(
                    "artifact_instance_identity", actual_payload
                ),
                "com.acme:app:1",
                actual_payload["outer_artifact_sha256"],
                actual_payload["container_entry"],
                actual_payload["content_sha256"],
                actual_payload["runtime_profile_identity"],
                actual_payload["path_owner_loader_realm_identity"],
                actual_payload["runtime_path_kind"],
                actual_payload["runtime_classpath_index"],
                actual_payload["container_loader_policy_version"],
                actual_payload["runtime_code_source_origin_identity"],
            ),
        )
        artifact = {
            "path": "/fixture/app.jar",
            "sha256": expected_payload["content_sha256"],
            "loader_realm": "application-loader",
            "slot": 0,
            "coord": "com.acme:app:1",
            "_expected_artifact_instance_payload": expected_payload,
            "_expected_artifact_instance_identity": oracle._identity(
                "artifact_instance_identity", expected_payload
            ),
        }

        bindings, issues = oracle._artifact_instance_bindings(
            connection, [artifact], domain="direct_edge"
        )

        self.assertEqual(bindings, {})
        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISMATCH"],
        )
        self.assertIn("container_entry", issues[0]["evidence"]["field_mismatches"])

    def test_artifact_binding_recomputes_database_identity(self):
        payload = {
            "outer_artifact_sha256": "a" * 64,
            "container_entry": "<artifact>",
            "content_sha256": "b" * 64,
            "runtime_profile_identity": "c" * 64,
            "path_owner_loader_realm_identity": "application-loader",
            "runtime_path_kind": "classpath",
            "runtime_classpath_index": 0,
            "container_loader_policy_version": "flat-parent-first-v1",
            "runtime_code_source_origin_identity": "d" * 64,
        }
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute(
            """
            CREATE TABLE artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                coord TEXT NOT NULL,
                outer_artifact_sha256 TEXT NOT NULL,
                container_entry TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                runtime_profile_identity TEXT NOT NULL,
                loader_realm_identity TEXT NOT NULL,
                runtime_path_kind TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL,
                container_loader_policy_version TEXT NOT NULL,
                runtime_code_source_origin_identity TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "e" * 64,
                "com.acme:app:1",
                payload["outer_artifact_sha256"],
                payload["container_entry"],
                payload["content_sha256"],
                payload["runtime_profile_identity"],
                payload["path_owner_loader_realm_identity"],
                payload["runtime_path_kind"],
                payload["runtime_classpath_index"],
                payload["container_loader_policy_version"],
                payload["runtime_code_source_origin_identity"],
            ),
        )
        artifact = {
            "path": "/fixture/app.jar",
            "sha256": payload["content_sha256"],
            "loader_realm": "application-loader",
            "slot": 0,
            "coord": "com.acme:app:1",
            "_expected_artifact_instance_payload": payload,
            "_expected_artifact_instance_identity": oracle._identity(
                "artifact_instance_identity", payload
            ),
        }

        bindings, issues = oracle._artifact_instance_bindings(
            connection, [artifact], domain="direct_edge"
        )

        self.assertEqual(bindings, {})
        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_ARTIFACT_INSTANCE_IDENTITY_MISMATCH"],
        )

    def test_final_artifact_stability_detects_runtime_oracle_toctou(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact_path = Path(temp_text) / "app.jar"
            artifact_path.write_bytes(b"initial")
            expected_sha256 = hashlib.sha256(b"initial").hexdigest()
            artifact = {
                "path": str(artifact_path),
                "sha256": expected_sha256,
                "loader_realm": "application-loader",
                "slot": 0,
            }
            artifact_path.write_bytes(b"changed-during-runtime-observation")

            issues, truth = oracle._final_artifact_stability((
                ("current", [artifact]),
            ))

        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_ARTIFACT_CHANGED_DURING_VALIDATION"],
        )
        self.assertNotEqual(
            truth[0]["expected_sha256"], truth[0]["actual_sha256"]
        )

    def test_structural_edges_bind_same_content_and_slot_to_exact_realm_instance(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact_path = Path(temp_text) / "same.jar"
            artifact_path.write_bytes(b"same-content-in-two-loader-realms")
            artifact_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            artifacts = [
                {
                    "path": str(artifact_path), "sha256": artifact_sha,
                    "loader_realm": "parent", "slot": 0,
                },
                {
                    "path": str(artifact_path), "sha256": artifact_sha,
                    "loader_realm": "child", "slot": 0,
                },
            ]
            inventories = [
                {"classes": {"demo/A": "demo/A.class"}},
                {"classes": {"demo/A": "demo/A.class"}},
            ]
            direct_result = {
                "complete": True,
                "artifact_sha256": artifact_sha,
                "edges": [],
                "failures": [],
                "structural_facts": {
                    "class_names": ["demo/A"],
                    "type_edges": [[
                        "demo/A", "run", "()V", 7, "demo/B", "new"
                    ]],
                    "class_init_edges": [],
                    "clinit_classes": [],
                    "semantic_instructions": [],
                    "declared_members": [],
                },
            }
            connection = self.edge_connection()
            self.addCleanup(connection.close)
            connection.executemany(
                "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                [
                    ("parent-instance", artifact_sha, "parent", 0),
                    ("child-instance", artifact_sha, "child", 0),
                ],
            )
            connection.execute(
                "INSERT INTO members VALUES (?,?,?,?)",
                ("member-1", "demo/A", "run", "()V"),
            )
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "child-instance", "member-1", "type", "demo/B", "", "",
                    187, 7, json.dumps({"type_use_kind": "new"}),
                ),
            )
            direct_cache = {
                (artifact_sha, "javap"): oracle._pack_oracle_scan(direct_result)
            }

            issues, _truth = oracle._validate_structural_edges(
                connection, artifacts, inventories, javap="javap",
                scan_cache={}, direct_scan_cache=direct_cache,
            )

        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_TYPE_EDGE_MISSING"],
        )

    def test_artifact_binding_rejects_database_only_runtime_instance(self):
        artifact_sha = "e" * 64
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.executemany(
            "INSERT INTO artifact_instances VALUES (?,?,?,?)",
            [
                ("expected-instance", artifact_sha, "application-loader", 0),
                ("database-only-instance", artifact_sha, "shadow-loader", 0),
            ],
        )

        bindings, issues = oracle._artifact_instance_bindings(
            connection,
            [{
                "path": "/fixture/app.jar", "sha256": artifact_sha,
                "loader_realm": "application-loader", "slot": 0,
            }],
            domain="direct_edge",
        )

        self.assertEqual(
            bindings, {("application-loader", 0): "expected-instance"}
        )
        self.assertEqual(
            [item["reason_code"] for item in issues],
            ["ORACLE_ARTIFACT_INSTANCE_UNEXPECTED"],
        )
        self.assertEqual(issues[0]["evidence"]["loader_realm"], "shadow-loader")

    def test_resource_selection_uses_parent_first_effective_loader_order(self):
        parent_only = "fixture/parent-only.txt"
        service_name = "META-INF/services/demo.Service"
        parent_origin = "origin-parent"
        child_origin = "origin-child"
        parent_service_facts = [["service_provider", "demo.ParentImpl"]]
        child_service_facts = [["service_provider", "demo.ChildImpl"]]
        artifacts = [
            {
                "path": "/fixture/parent.jar", "loader_realm": "parent",
                "slot": 7,
                "runtime_code_source_origin_identity": parent_origin,
            },
            {
                "path": "/fixture/child.jar", "loader_realm": "child",
                "slot": 0,
                "runtime_code_source_origin_identity": child_origin,
            },
        ]
        inventories = [
            {"resources": {
                parent_only: [{
                    "sha256": "parent-only-sha",
                    "semantic_digest": "parent-only-semantic",
                    "semantic_facts": [],
                }],
                service_name: [{
                    "sha256": "parent-service-sha",
                    "semantic_digest": "parent-service-semantic",
                    "semantic_facts": parent_service_facts,
                }],
            }},
            {"resources": {
                service_name: [{
                    "sha256": "child-service-sha",
                    "semantic_digest": "child-service-semantic",
                    "semantic_facts": child_service_facts,
                }],
            }},
        ]
        topology = {
            "realms": [
                {"identity": "platform", "kind": "platform"},
                {
                    "identity": "parent", "kind": "url",
                    "parent": "platform", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
                {
                    "identity": "child", "kind": "url",
                    "parent": "parent", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ]
        }
        production = [
            {
                "initiating_loader_realm_identity": "child",
                "resource_name": parent_only,
                "resource_mechanism": "classloader_first",
                "selected_resources": [{
                    "runtime_classpath_index": 7,
                    "runtime_code_source_origin_identity": parent_origin,
                    "content_sha256": "parent-only-sha",
                    "normalized_resource_digest": "parent-only-semantic",
                    "resource_semantic_facts": [],
                }],
            },
            {
                "initiating_loader_realm_identity": "child",
                "resource_name": service_name,
                "resource_mechanism": "ordered_all",
                "selected_resources": [
                    {
                        "runtime_classpath_index": 7,
                        "runtime_code_source_origin_identity": parent_origin,
                        "content_sha256": "parent-service-sha",
                        "normalized_resource_digest": "parent-service-semantic",
                        "resource_semantic_facts": parent_service_facts,
                    },
                    {
                        "runtime_classpath_index": 0,
                        "runtime_code_source_origin_identity": child_origin,
                        "content_sha256": "child-service-sha",
                        "normalized_resource_digest": "child-service-semantic",
                        "resource_semantic_facts": child_service_facts,
                    },
                ],
            },
        ]
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)

        with patch.object(
            oracle, "_reconciliation", return_value=production
        ):
            issues, truth = oracle._validate_resource_selections(
                connection, artifacts, inventories, ["child"], topology
            )

        self.assertEqual(issues, [])
        selected_by_name = {
            item["name"]: item["selected"]
            for item in truth["resource_selections"]
        }
        self.assertEqual(
            [item["origin"] for item in selected_by_name[parent_only]],
            [parent_origin],
        )
        # Realm delegation outranks the raw classpath slot: the parent slot 7
        # must precede child slot 0 for ClassLoader.getResources semantics.
        self.assertEqual(
            [item["origin"] for item in selected_by_name[service_name]],
            [parent_origin, child_origin],
        )

    def test_runtime_truth_retains_only_observation_digest_and_count(self):
        connection = self.runtime_connection()
        self.addCleanup(connection.close)
        first_observations = {
            "demo/A": {
                "class_name": "demo/A", "status": "definition_failed",
                "failure_phase": "class_load", "failure_kind": "fixture-a",
            }
        }
        second_observations = copy.deepcopy(first_observations)
        second_observations["demo/A"]["failure_kind"] = "fixture-b"

        with tempfile.TemporaryDirectory() as temp_text:
            jdk_home = Path(temp_text)
            (jdk_home / "release").write_text(
                'JAVA_VERSION="17.0.1"\n', encoding="utf-8"
            )
            with patch.object(
                oracle, "_iter_reconciliation",
                side_effect=lambda _connection, _kind: iter(()),
            ):
                first_issues, first_truth = oracle._validate_runtime_outcomes(
                    connection, [], [], [], first_observations,
                    [], [], "platform", jdk_home,
                )
                second_issues, second_truth = oracle._validate_runtime_outcomes(
                    connection, [], [], [], second_observations,
                    [], [], "platform", jdk_home,
                )

        self.assertEqual(first_issues, [])
        self.assertEqual(second_issues, [])
        self.assertNotIn("runtime_observations", first_truth)
        self.assertEqual(first_truth["runtime_observation_count"], 1)
        self.assertRegex(
            first_truth["runtime_observation_set_identity"], r"^[0-9a-f]{64}$"
        )
        self.assertNotEqual(
            first_truth["runtime_observation_set_identity"],
            second_truth["runtime_observation_set_identity"],
        )

    def test_provider_validation_rejects_wrong_same_content_instance(self):
        connection = self.runtime_connection()
        self.addCleanup(connection.close)
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            parent_path = root / "parent.jar"
            child_path = root / "child.jar"
            parent_path.write_bytes(b"identical-artifact-content")
            child_path.write_bytes(parent_path.read_bytes())
            artifact_sha = hashlib.sha256(parent_path.read_bytes()).hexdigest()
            artifacts = [
                {
                    "path": str(parent_path), "sha256": artifact_sha,
                    "loader_realm": "parent", "slot": 0,
                },
                {
                    "path": str(child_path), "sha256": artifact_sha,
                    "loader_realm": "child", "slot": 0,
                },
            ]
            connection.executemany(
                "INSERT INTO artifact_instances VALUES (?,?,?,?)",
                [
                    ("parent-instance", artifact_sha, "parent", 0),
                    ("child-instance", artifact_sha, "child", 0),
                ],
            )
            records = {
                "provider_binding": [{
                    "initiating_loader_realm_identity": "child",
                    "class_name": "demo/A",
                    "class_provider_status": "resolved",
                    # Same content hash, but this is the wrong loader instance.
                    "selected_artifact_instance_identity": "parent-instance",
                }],
                "class_definition": [{
                    "initiating_loader_realm_identity": "child",
                    "class_name": "demo/A",
                    "class_definition_status": "definition_ready",
                    "class_load_status": "ready",
                }],
                "member_resolution": [],
                "dispatch_resolution": [],
            }
            observations = {
                "demo/A": {
                    "class_name": "demo/A",
                    "status": "definition_ready",
                    "provider_url": child_path.as_uri(),
                    "provider_resource_url": (
                        f"jar:{child_path.as_uri()}!/demo/A.class"
                    ),
                    "super_name": "",
                    "interfaces": [],
                    "members": [],
                    "modifiers": 1,
                }
            }
            inventories = [
                {"classes": {}},
                {"classes": {"demo/A": "demo/A.class"}},
            ]
            jdk_home = root / "jdk"
            jdk_home.mkdir()
            (jdk_home / "release").write_text(
                'JAVA_VERSION="17.0.1"\n', encoding="utf-8"
            )

            with patch.object(
                oracle, "_iter_reconciliation",
                side_effect=lambda _connection, kind: iter(records[kind]),
            ):
                issues, _truth = oracle._validate_runtime_outcomes(
                    connection, artifacts, artifacts, inventories,
                    observations, ["child"], ["demo/A"], "platform", jdk_home,
                )

        self.assertIn(
            "ORACLE_ARTIFACT_PROVIDER_MISMATCH",
            {item["reason_code"] for item in issues},
        )

    def test_entrypoint_oracle_rejects_dropped_declared_coverage_gap(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            (generation / "binary_entrypoints.json").write_text(
                json.dumps({
                    "records": [],
                    "coverage_status": "complete",
                    "coverage_gaps": [],
                }),
                encoding="utf-8",
            )
            issues, _truth = oracle._validate_entrypoint_discovery(
                generation,
                {
                    "runtime_profile": {
                        "business_entrypoint_profile": {
                            "coverage_status": "partial",
                            "coverage_gaps": [
                                "packaged_main_class_manifest_missing"
                            ],
                        },
                        "entrypoint_discovery_coverage_gaps": [
                            "packaged_main_class_manifest_missing"
                        ],
                        "loader_topology": {
                            "entrypoint_realms": [], "realms": []
                        },
                    }
                },
                [],
                {},
                [],
                [],
                [],
            )

        self.assertIn(
            "ORACLE_ENTRYPOINT_DECLARED_COVERAGE_GAP_MISSING",
            {item["reason_code"] for item in issues},
        )

    def test_entrypoint_oracle_does_not_accept_falsey_non_object_profile(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            (generation / "binary_entrypoints.json").write_text(
                json.dumps({
                    "records": [],
                    "coverage_status": "complete",
                    "coverage_gaps": [],
                }),
                encoding="utf-8",
            )
            issues, _truth = oracle._validate_entrypoint_discovery(
                generation,
                {
                    "runtime_profile": {
                        "business_entrypoint_profile": [],
                        "loader_topology": {
                            "entrypoint_realms": [], "realms": []
                        },
                    }
                },
                [],
                {},
                [],
                [],
                [],
            )

        self.assertIn(
            "ORACLE_ENTRYPOINT_DECLARED_COVERAGE_GAP_MISSING",
            {item["reason_code"] for item in issues},
        )

    @staticmethod
    def _write_closed_world_fixture(
        generation,
        *,
        entrypoint_gaps=(),
        trace_gaps=(),
        result_overrides=None,
        reported_overrides=None,
    ):
        generation = Path(generation)
        analysis_context = "analysis-context"
        runtime_profile = "runtime-profile"
        decision = {
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "fact_kind": "method",
            "fact_scope": {
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "demo/Api",
                "member_kind": "method",
                "member_name": "changed",
                "descriptor": "()V",
            },
            "coverage_gaps": [],
            "dependency_artifacts": [],
        }
        assessment = {
            "projection_assessment_identity": "assessment-1",
            "decision_identity": decision["decision_identity"],
        }
        projection = {
            "projection_identity": "projection-1",
            "projection_assessment_identity": assessment[
                "projection_assessment_identity"
            ],
        }
        complete = not trace_gaps
        status = (
            "not_found_in_static_analysis" if complete else "not_analyzed"
        )
        result = {
            "projection_identity": projection["projection_identity"],
            "decision_identity": decision["decision_identity"],
            "change_fact_identity": decision["change_fact_identity"],
            "projection_assessment_identity": assessment[
                "projection_assessment_identity"
            ],
            "analysis_context_identity": analysis_context,
            "runtime_profile_identity": runtime_profile,
            "target_nodes": ["target-member"],
            "paths": [],
            "exact_path_exists": False,
            "possible_path_exists": False,
            "path_set_complete": complete,
            "trace_coverage_gaps": list(trace_gaps),
            "result_channel": "formal",
            "batch_graph_identity": "batch-graph",
            "static_linkage_status": "compatible_or_not_applicable",
            "member_resolution_statuses": [],
            "linkage_resolution_statuses": [],
            "change_fact_status": "confirmed",
            "reachability_status": status,
            "analysis_status": status,
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "decision_bucket": "inconclusive",
            "runtime_verification_status": "undetermined",
            "runtime_verification_executed_by_system": False,
            "runtime_verification_evidence": [],
            "best_path_certainty": "none",
            "existence_proven": False,
        }
        result.update(result_overrides or {})
        result["trace_result_identity"] = oracle._identity(
            "binary_trace_result_identity",
            {
                key: value for key, value in result.items()
                if key != "trace_result_identity"
            },
        )
        reported_api_identity = oracle._identity("reported_api_identity", {
            "analysis_context_identity": analysis_context,
            "current_runtime_profile_identity": runtime_profile,
            "class_name": "demo/Api",
            "member_kind": "method",
            "member_name": "changed",
            "descriptor": "()V",
            "grouping_rule_version": "binary-reported-api-v2",
        })
        reported_api = {
            "reported_api_identity": reported_api_identity,
            "display_owner": "demo/Api",
            "display_member": "changed",
            "display_descriptor": "()V",
            "display_member_kind": "method",
            "initiating_loader_realms": ["application-loader"],
            "reachability_status": status,
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "runtime_verification_status": "undetermined",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": complete,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "contributing_projection_ids": [projection["projection_identity"]],
            "contributing_change_fact_ids": [decision["change_fact_identity"]],
            "base_dependency_coords": [],
            "current_dependency_coords": [],
        }
        reported_api.update(reported_overrides or {})
        payloads = {
            "binary_decisions.json": {
                "analysis_context_identity": analysis_context,
                "authoritative_change_facts": [decision],
                "diagnostic_candidate_facts": [],
            },
            "binary_projections.json": {
                "authoritative_projection_assessments": [assessment],
                "formal_projections": [projection],
            },
            "binary_formal_results.json": {
                "results": [result], "by_api": [reported_api],
            },
            "binary_entrypoints.json": {
                "records": [], "coverage_gaps": list(entrypoint_gaps),
            },
            "binary_runtime_semantic_overlay.json": {
                "rows": [], "coverage_gaps": [],
            },
            "binary_coverage.json": {
                "trace_coverage_gaps": list(trace_gaps),
            },
            "binary_summary.json": {
                "authoritative_change_fact_count": 1,
                "formal_projection_count": 1,
                "formal_trace_result_count": 1,
                "unique_reported_api_total": 1,
                "reachable_total": 0,
                "uncertain_total": 0,
                "not_found_in_static_analysis_total": int(complete),
                "not_analyzed_total": int(not complete),
                "probable_impact_total": 0,
            },
        }
        for name, payload in payloads.items():
            (generation / name).write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        with (generation / "binary_formal_results.csv").open(
            "w", encoding="utf-8-sig", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "reported_api_identity", "display_owner", "display_member",
                "display_descriptor", "reachability_status",
                "impact_conclusion", "runtime_verification_status",
            ])
            writer.writeheader()
            writer.writerow({key: reported_api.get(key, "") for key in writer.fieldnames})
        return result

    @staticmethod
    def _empty_entrypoint_truth():
        return {
            "exact_entrypoint_count": 0,
            "oracle_candidate_entrypoint_count": 0,
            "production_candidate_entrypoint_count": 0,
            "candidate_activation_gaps": [],
        }

    def test_closed_world_skips_graph_only_for_independently_verified_empty_roots(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(generation)
            with patch.object(
                oracle,
                "_load_closed_world_graph",
                side_effect=AssertionError("validated empty roots must not load graph"),
            ):
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"],
            "not_required_validated_empty_entrypoint_set",
        )
        self.assertTrue(truth["formal_identity_set_closed"])

    def test_closed_world_falls_back_when_empty_roots_are_not_verified(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(generation)
            empty_graph = ({}, {}, {}, {})
            with patch.object(
                oracle, "_load_closed_world_graph", return_value=empty_graph
            ) as load_graph:
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_validation_issues=[{"reason_code": "unverified"}],
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        load_graph.assert_called_once()
        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"], "completed_full_graph"
        )

    def test_closed_world_no_roots_with_coverage_gap_stays_not_analyzed(self):
        gap = "declared_entrypoint_coverage_incomplete"
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, entrypoint_gaps=[gap], trace_gaps=[gap]
            )
            with patch.object(
                oracle, "_load_closed_world_graph", return_value=({}, {}, {}, {})
            ) as load_graph:
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        load_graph.assert_called_once()
        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"], "completed_full_graph"
        )

    def test_closed_world_empty_root_fast_path_still_rejects_tampered_state(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, result_overrides={"path_set_complete": False}
            )
            issues, _truth = oracle._validate_closed_world_results(
                generation,
                entrypoint_truth=self._empty_entrypoint_truth(),
            )

        self.assertIn(
            "ORACLE_FORMAL_STATE_MISMATCH",
            {item["reason_code"] for item in issues},
        )

    def test_closed_world_rejects_reachable_runtime_requirement_on_unreachable_api(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation,
                reported_overrides={
                    "runtime_verification_status": "required_not_executed"
                },
            )
            issues, _truth = oracle._validate_closed_world_results(
                generation,
                entrypoint_truth=self._empty_entrypoint_truth(),
            )

        self.assertIn(
            "ORACLE_API_AGGREGATION_MISMATCH",
            {item["reason_code"] for item in issues},
        )

    def test_closed_world_rejects_path_root_not_in_entrypoint_set(self):
        fake_path = {
            "entrypoint_member_identity": "forged-root",
            "entrypoint_records": [],
            "edges": [],
            "path_certainty": "exact",
        }
        fake_path["path_identity"] = oracle._identity(
            "binary_trace_path_identity",
            {
                "entrypoint_member_identity": "forged-root",
                "entrypoint_record_identities": [],
                "target_nodes": ["target-member"],
                "edge_identities": [],
                "path_certainty": "exact",
            },
        )
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, result_overrides={"paths": [fake_path]}
            )
            issues, _truth = oracle._validate_closed_world_results(
                generation,
                entrypoint_truth=self._empty_entrypoint_truth(),
            )

        self.assertIn(
            "ORACLE_TRACE_PATH_ENTRYPOINT_MISMATCH",
            {item["reason_code"] for item in issues},
        )

    def test_projected_scan_spool_round_trips_and_reads_only_requested_field(self):
        key = ("a" * 64, "javap")
        raw = {
            "artifact_sha256": key[0],
            "complete": True,
            "failures": [],
            "edges": [{
                "caller_owner": "demo.A",
                "caller_member": "run",
                "caller_descriptor": "()V",
                "callee_owner": "demo.B",
                "callee_member": "value",
                "callee_descriptor": "()I",
                "opcode_family": "invokevirtual",
                "instruction_offset": 7,
                "reference_kind": "method",
                "reference_interface": False,
            }],
            "structural_facts": {
                "class_names": ["demo/A"],
                "type_edges": [[
                    "demo/A", "run", "()V", 7, "demo/B", "new",
                ]],
                "class_init_edges": [],
                "clinit_classes": [],
                "semantic_instructions": [[
                    "demo/A", "run", "()V", 7, "new", "class demo/B",
                ]],
                "declared_members": [[
                    "demo/A", "method", "run", "()V", 1,
                ]],
            },
        }
        cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=1)
        self.addCleanup(cache.clear)
        cache.put_result(key, raw)
        first = cache.get_evidence(key, {})

        with patch.object(
            cache, "_projection", wraps=cache._projection
        ) as projection:
            semantic = cache.get_projection(
                key, "semantic_instructions", {}
            )

        self.assertEqual(
            semantic,
            {("demo/A", "run", "()V", 7, "new", "class demo/B")},
        )
        self.assertEqual(
            [call.args[1] for call in projection.call_args_list],
            ["semantic_instructions"],
        )
        self.assertEqual(cache.get_evidence(key, {}), first)
        self.assertTrue(cache._entries[key]._rolled)

    def test_projected_scan_spool_direct_view_skips_structural_fields(self):
        key = ("b" * 64, "javap")
        raw = {
            "artifact_sha256": key[0],
            "complete": True,
            "failures": [],
            "edges": [{
                "caller_owner": "demo.A",
                "caller_member": "run\ud800",
                "caller_descriptor": "()V",
                "callee_owner": "demo.B",
                "callee_member": "value",
                "callee_descriptor": "()I",
                "opcode_family": "invokevirtual",
                "instruction_offset": 7,
                "reference_kind": "method",
                "reference_interface": False,
            }],
            "structural_facts": {
                "class_names": ["demo/A"],
                "type_edges": [],
                "class_init_edges": [],
                "clinit_classes": [],
                "semantic_instructions": [[
                    "demo/A", "run\ud800", "()V", 7, "return", "",
                ]],
                "declared_members": [],
            },
        }
        cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=1)
        self.addCleanup(cache.clear)
        cache.put_result(key, raw)
        cache.get_evidence(key, {})

        with patch.object(
            cache, "_projection", wraps=cache._projection
        ) as projection:
            direct = cache.get_direct_evidence(key, {})

        self.assertEqual(
            next(iter(direct.direct_truth.direct_edges))[1],
            transport_jvm_text("run\ud800"),
        )
        self.assertEqual(
            [call.args[1] for call in projection.call_args_list],
            [
                "metadata", "direct_edges", "dynamic_handle_edges",
                "discovery_classes",
            ],
        )

    def test_fused_production_projection_matches_independent_legacy_views(self):
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("caller", "demo/Caller", "run", "()V"),
        )
        rows = [
            (
                "artifact", "caller", "method", "demo/Api", "call", "()V",
                184, 1, json.dumps({
                    "interface": False,
                    "loading_constraint_type_owners": ["demo/Arg"],
                }),
            ),
            (
                "artifact", "caller", "type", "demo/Type", "", "", 187, 2,
                json.dumps({"type_use_kind": "new"}),
            ),
            (
                "artifact", "caller", "class_init", "demo/Init", "", "",
                178, 3, json.dumps({"trigger_kind": "getstatic"}),
            ),
            (
                "artifact", "caller", "ldc_handle", "demo/Handle", "apply",
                "()V", 18, 4, json.dumps({
                    "tag": 6,
                    "interface": False,
                    "loading_constraint_type_owners": ["demo/HandleArg"],
                }),
            ),
        ]
        connection.executemany(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)", rows
        )
        direct_issues = []
        direct, dynamic = oracle._production_direct_truth_for_artifact(
            connection, "artifact", direct_issues
        )
        structural_issues = []
        type_edges, init_edges = (
            oracle._production_structural_truth_for_artifact(
                connection, "artifact", structural_issues
            )
        )
        fused_issues = []
        fused = oracle._production_direct_truth_for_artifact(
            connection,
            "artifact",
            fused_issues,
            include_structural=True,
        )

        self.assertEqual(fused, (direct, dynamic, type_edges, init_edges))
        self.assertEqual(direct_issues, [])
        self.assertEqual(structural_issues, [])
        self.assertEqual(fused_issues, [])

    def test_resolution_affected_owner_closure_is_conservative_and_bounded(self):
        ready = {
            "status": "definition_ready",
            "modifiers": 1,
            "interfaces": (),
            "members": (),
            "javap_declared_members": (),
        }
        base = {
            "demo/Parent": {**ready, "super_name": "java/lang/Object"},
            "demo/Child": {**ready, "super_name": "demo/Parent"},
            "demo/Unrelated": {**ready, "super_name": "java/lang/Object"},
        }
        current = copy.deepcopy(base)
        current["demo/Parent"]["members"] = ("method|changed|()V|1",)

        affected = oracle._resolution_affected_owners({
            "base": base, "current": current,
        })

        self.assertEqual(affected, {"demo/Parent", "demo/Child"})

    def test_common_edge_intersection_prunes_only_unaffected_targets(self):
        def build_database(path, rows):
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE members (
                    member_identity TEXT PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    member_name TEXT NOT NULL,
                    descriptor TEXT NOT NULL
                );
                CREATE TABLE direct_edges (
                    caller_member_identity TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    symbolic_owner TEXT NOT NULL,
                    symbolic_name TEXT NOT NULL,
                    symbolic_descriptor TEXT NOT NULL,
                    opcode INTEGER NOT NULL,
                    bytecode_offset INTEGER NOT NULL,
                    edge_json TEXT NOT NULL
                );
                CREATE INDEX direct_edges_symbolic_target ON direct_edges(
                    symbolic_owner,symbolic_name,symbolic_descriptor
                );
                """
            )
            connection.execute(
                "INSERT INTO members VALUES (?,?,?,?)",
                ("caller", "demo/Caller", "run", "()V"),
            )
            connection.executemany(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?)", rows
            )
            connection.commit()
            connection.close()

        common_changed = (
            "caller", "method", "demo/Changed", "call", "()V", 184, 1,
            '{"interface":false}',
        )
        common_unrelated = (
            "caller", "field", "demo/Unrelated", "value", "I", 178, 2,
            "{}",
        )
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            base = root / "base.sqlite"
            current = root / "current.sqlite"
            build_database(base, [common_changed, common_unrelated])
            build_database(current, [
                common_changed,
                common_unrelated,
                (
                    "caller", "method", "demo/CurrentOnly", "call", "()V",
                    184, 3, '{"interface":false}',
                ),
            ])

            unfiltered = list(oracle._iter_common_validated_direct_edges(
                base, current
            ))
            filtered = list(oracle._iter_common_validated_direct_edges(
                base, current, {"demo.Changed"}
            ))
            empty = list(oracle._iter_common_validated_direct_edges(
                base, current, set()
            ))

        self.assertEqual(len(unfiltered), 2)
        self.assertEqual(filtered, [(
            "demo.Caller", "run", "()V", "demo.Changed", "call", "()V",
            "invokestatic", 1, "method",
        )])
        self.assertEqual(empty, [])

    def test_sqlite_logical_equality_ignores_only_normalized_header_fields(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            left = root / "left.sqlite"
            right = root / "right.sqlite"
            connection = sqlite3.connect(left)
            connection.execute("CREATE TABLE facts(value TEXT NOT NULL)")
            connection.execute("INSERT INTO facts VALUES ('same')")
            connection.commit()
            connection.close()
            shutil.copyfile(left, right)

            content = bytearray(right.read_bytes())
            for offset, value in ((24, 7), (40, 11), (92, 13)):
                content[offset:offset + 4] = value.to_bytes(4, "big")
            right.write_bytes(content)
            self.assertTrue(
                oracle._sqlite_logical_contents_equal(left, right)
            )

            content[-1] ^= 1
            right.write_bytes(content)
            self.assertFalse(
                oracle._sqlite_logical_contents_equal(left, right)
            )

    def test_artifact_scan_concurrency_adapts_to_memory_headroom(self):
        gib = 1024 * 1024 * 1024
        with patch.object(oracle.os, "cpu_count", return_value=16):
            for available, expected in (
                (1 * gib, 1), (3 * gib, 2), (6 * gib, 4), (12 * gib, 8),
            ):
                with self.subTest(available=available), patch.object(
                    oracle,
                    "system_available_memory_bytes",
                    return_value=available,
                ):
                    self.assertEqual(
                        oracle._artifact_scan_worker_count(100),
                        (expected, available),
                    )

    def test_archive_inventory_does_not_materialize_ordinary_class_body(self):
        from tests.test_final_artifact_edge_oracle import (
            _minimal_static_edge_class,
        )

        content = _minimal_static_edge_class("demo/Ordinary", "run")
        with tempfile.TemporaryDirectory() as temp_text:
            artifact = Path(temp_text) / "ordinary.jar"
            with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("demo/Ordinary.class", content)
            original_read = zipfile.ZipFile.read
            full_reads = []

            def tracking_read(archive, name, *args, **kwargs):
                full_reads.append(str(getattr(name, "filename", name)))
                return original_read(archive, name, *args, **kwargs)

            with patch.object(zipfile.ZipFile, "read", new=tracking_read):
                inventory = oracle._archive_inventory(artifact, 17)

        self.assertEqual(
            inventory["classes"],
            {"demo/Ordinary": "demo/Ordinary.class"},
        )
        self.assertEqual(full_reads, [])


if __name__ == "__main__":
    unittest.main()
