from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff as diff  # noqa: E402


class BinaryArtifactDiffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("JDK java/javac is required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_source_identity_ignores_ctime_only_changes(self):
        common = {
            "st_dev": 1,
            "st_ino": 2,
            "st_mode": 0o100644,
            "st_nlink": 1,
            "st_size": 42,
            "st_mtime_ns": 123456789,
        }
        before = mock.Mock(**common, st_ctime_ns=10)
        after = mock.Mock(**common, st_ctime_ns=20)

        before_identity = diff._archive_source_identity(before)
        after_identity = diff._archive_source_identity(after)

        self.assertEqual(before_identity, after_identity)
        self.assertFalse(hasattr(before_identity, "changed_nanoseconds"))

    def compile_class(self, variant, body, *, debug="-g", class_name="Api"):
        source = self.root / variant / "src" / "demo" / f"{class_name}.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            f"package demo; public class {class_name} {{ {body} }}",
            encoding="utf-8",
        )
        classes = self.root / variant / "classes"
        classes.mkdir(parents=True)
        completed = subprocess.run(
            ["javac", debug, "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return classes / "demo" / f"{class_name}.class", source

    def jar(self, name, entries, *, timestamp=(2024, 1, 1, 0, 0, 0)):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry_name, content in entries:
                info = zipfile.ZipInfo(entry_name, timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)
        return path

    @staticmethod
    def empty_fact_run(inputs, **_kwargs):
        inputs = tuple(inputs)
        if inputs:
            raise AssertionError(f"expected a resource-only archive, got {inputs!r}")
        return binary_asm_helper.BinaryFactRun(
            parser_identity="test-parser",
            helper_sha256="1" * 64,
            asm_jar_sha256="2" * 64,
            records=(),
            input_record_count=0,
            fact_record_count=0,
            failure_record_count=0,
            class_input_digest="3" * 64,
            fact_output_digest="4" * 64,
            coverage_status="complete",
            stderr="",
        )

    def compare(self, base, current):
        return diff.compare_archives(
            base,
            current,
            base_artifact_instance_identity="base-instance",
            current_artifact_instance_identity="current-instance",
            base_expected_sha256=diff._sha256_file(base),
            current_expected_sha256=diff._sha256_file(current),
            comparison_or_runtime_scope={"pairing": "pair-1"},
            asm_jar=self.asm_jar,
        )

    def test_unknown_attribute_is_scoped_not_global_class_fact_loss(self):
        snapshot = diff.ArtifactSnapshot(
            artifact_instance_identity="artifact",
            artifact_content_sha256="a" * 64,
            artifact_byte_length=1,
            archive_comment_sha256="b" * 64,
            entries=(),
            class_records=(),
            class_payloads=(),
            safety_reason_codes=(),
            parse_failure_count=0,
            unknown_attribute_scopes=(
                "demo/Aspect.class:class:org.aspectj.weaver.WeaverState",
            ),
            unknown_resource_scopes=(),
            inventory_digest="c" * 64,
            parser_identity="d" * 64,
            comparison_coverage_status="partial",
        )

        self.assertEqual(snapshot.class_fact_coverage_status, "complete")
        self.assertEqual(snapshot.comparison_coverage_status, "partial")

    def test_multi_release_jar_parses_only_target_jvm_effective_class(self):
        base_class, _ = self.compile_class(
            "mr-base", "public int value(){ return 8; }"
        )
        java8_class, _ = self.compile_class(
            "mr-version-8", "public int value(){ return 80; }"
        )
        java21_class, _ = self.compile_class(
            "mr-21", "public int value(){ return 21; }"
        )
        artifact = self.jar("multi-release.jar", [
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nMulti-Release: true\n\n"),
            ("demo/Api.class", base_class.read_bytes()),
            ("META-INF/versions/8/demo/Api.class", java8_class.read_bytes()),
            ("META-INF/versions/21/demo/Api.class", java21_class.read_bytes()),
        ])
        sha = diff._sha256_file(artifact)

        with self.assertRaises(diff.BinaryArtifactDiffError) as raised:
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="missing-target",
                expected_sha256=sha,
                asm_jar=self.asm_jar,
            )
        self.assertEqual(
            raised.exception.reason_code, "ARTIFACT_TARGET_JVM_MAJOR_REQUIRED"
        )

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="jdk21",
            expected_sha256=sha,
            asm_jar=self.asm_jar,
            target_jvm_major=21,
        )
        self.assertEqual(len(snapshot.class_records), 1)
        self.assertEqual(
            snapshot.class_records[0]["class_entry"],
            "META-INF/versions/21/demo/Api.class#occurrence=0",
        )
        effective = {
            item.name: item.runtime_effective
            for item in snapshot.entries if item.kind == "class"
        }
        self.assertEqual(effective, {
            "demo/Api.class": False,
            "META-INF/versions/8/demo/Api.class": False,
            "META-INF/versions/21/demo/Api.class": True,
        })
        self.assertEqual(
            snapshot.runtime_semantics_diagnostic_codes,
            ("NONSTANDARD_MULTI_RELEASE_VERSION_8_PRESENT",),
        )

        jdk8 = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="jdk8-base-view",
            expected_sha256=sha,
            asm_jar=self.asm_jar,
            target_jvm_major=8,
        )
        jdk9 = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="jdk9-base-view",
            expected_sha256=sha,
            asm_jar=self.asm_jar,
            target_jvm_major=9,
        )
        self.assertEqual(
            jdk8.class_records[0]["class_entry"],
            "demo/Api.class#occurrence=0",
        )
        self.assertEqual(
            jdk9.class_records[0]["class_entry"],
            "META-INF/versions/8/demo/Api.class#occurrence=0",
        )
        self.assertEqual(
            jdk8.runtime_semantics_diagnostic_codes,
            ("NONSTANDARD_MULTI_RELEASE_VERSION_8_PRESENT",),
        )
        self.assertEqual(
            jdk9.runtime_semantics_diagnostic_codes,
            (
                "NONSTANDARD_MULTI_RELEASE_VERSION_8_PRESENT",
                "NONSTANDARD_MULTI_RELEASE_VERSION_8_RUNTIME_SELECTED",
            ),
        )

        _, _, comparison = diff.compare_archives(
            artifact,
            artifact,
            base_artifact_instance_identity="base-jdk8",
            current_artifact_instance_identity="current-jdk21",
            base_expected_sha256=sha,
            current_expected_sha256=sha,
            comparison_or_runtime_scope={"pairing": "mr-target-change"},
            asm_jar=self.asm_jar,
            base_target_jvm_major=8,
            current_target_jvm_major=21,
        )
        effective_deltas = [
            row for row in comparison["entry_deltas"]
            if row.get("runtime_effective_analysis") is True
        ]
        self.assertEqual(len(effective_deltas), 1)
        self.assertEqual(
            effective_deltas[0]["entry_scope"]["logical_class_entry"],
            "demo/Api.class",
        )

    def test_pre_java8_and_malformed_version_directories_are_never_effective(self):
        base_class, _ = self.compile_class(
            "mr-floor-base", "public int value(){ return 8; }"
        )
        ignored_class, _ = self.compile_class(
            "mr-floor-ignored", "public int value(){ return 7; }"
        )
        artifact = self.jar("multi-release-floor.jar", [
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\nMulti-Release: true\n\n",
            ),
            ("demo/Api.class", base_class.read_bytes()),
            (
                "META-INF/versions/7/demo/Api.class",
                ignored_class.read_bytes(),
            ),
            (
                "META-INF/versions/07/demo/Api.class",
                ignored_class.read_bytes(),
            ),
            (
                "META-INF/versions/not-a-version/demo/Api.class",
                ignored_class.read_bytes(),
            ),
            (
                "META-INF/versions/9/demo//Api.class",
                ignored_class.read_bytes(),
            ),
            (
                "META-INF/versions/9/META-INF/Hidden.class",
                ignored_class.read_bytes(),
            ),
            ("META-INF/Hidden.class", ignored_class.read_bytes()),
        ])

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="jdk21-floor",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
            target_jvm_major=21,
        )

        self.assertEqual(
            [record["class_entry"] for record in snapshot.class_records],
            ["demo/Api.class#occurrence=0"],
        )
        effective = {
            item.name: item.runtime_effective
            for item in snapshot.entries if item.kind == "class"
        }
        self.assertEqual(effective, {
            "demo/Api.class": True,
            "META-INF/versions/7/demo/Api.class": False,
            "META-INF/versions/07/demo/Api.class": False,
            "META-INF/versions/not-a-version/demo/Api.class": False,
            "META-INF/versions/9/demo//Api.class": False,
            "META-INF/versions/9/META-INF/Hidden.class": False,
            "META-INF/Hidden.class": False,
        })
        self.assertEqual(
            diff._mr_class_scope(
                "META-INF/versions/9/demo/../Api.class"
            )[1],
            -1,
        )

    def test_mr_resources_use_logical_names_and_never_overlay_meta_inf(self):
        artifact = self.jar("multi-release-resources.jar", [
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
            ),
            ("config/runtime.xml", b"base"),
            ("META-INF/versions/8/config/runtime.xml", b"v8"),
            ("META-INF/versions/9/config/runtime.xml", b"v9"),
            ("config/eight-only.xml", b"base-eight"),
            ("META-INF/versions/8/config/eight-only.xml", b"v8-only"),
            ("META-INF/services/demo.Service", b"demo.Base\n"),
            (
                "META-INF/versions/9/META-INF/services/demo.Service",
                b"demo.Versioned\n",
            ),
        ])
        sha = diff._sha256_file(artifact)

        with self.assertRaises(diff.BinaryArtifactDiffError) as raised:
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="missing-resource-target",
                expected_sha256=sha,
                asm_jar=self.asm_jar,
            )
        self.assertEqual(
            raised.exception.reason_code, "ARTIFACT_TARGET_JVM_MAJOR_REQUIRED"
        )

        def selected(target):
            snapshot = diff.snapshot_archive(
                artifact,
                artifact_instance_identity=f"resource-jdk-{target}",
                expected_sha256=sha,
                asm_jar=self.asm_jar,
                target_jvm_major=target,
            )
            return snapshot, {
                item.logical_resource_entry: item.name
                for item in snapshot.entries
                if item.kind == "resource" and item.runtime_effective
            }

        jdk8, selected8 = selected(8)
        jdk9, selected9 = selected(9)
        self.assertEqual(selected8["config/runtime.xml"], "config/runtime.xml")
        self.assertEqual(
            selected8["config/eight-only.xml"], "config/eight-only.xml"
        )
        self.assertEqual(
            selected9["config/runtime.xml"],
            "META-INF/versions/9/config/runtime.xml",
        )
        self.assertEqual(
            selected9["config/eight-only.xml"],
            "META-INF/versions/8/config/eight-only.xml",
        )
        self.assertEqual(
            selected9["META-INF/services/demo.Service"],
            "META-INF/services/demo.Service",
        )
        prohibited = next(
            item for item in jdk9.entries
            if item.name
            == "META-INF/versions/9/META-INF/services/demo.Service"
        )
        self.assertFalse(prohibited.runtime_effective)
        self.assertEqual(prohibited.logical_resource_entry, "")
        self.assertEqual(
            diff._mr_resource_scope(
                "META-INF/versions/9/config/../ignored.xml"
            )[1],
            -1,
        )
        self.assertTrue(all(
            item.runtime_effective
            for item in jdk8.entries
            if item.kind == "resource"
            and not item.name.startswith("META-INF/versions/")
        ))

    def test_mr_resource_selection_matches_real_jarfile_views(self):
        v8_only_class, _ = self.compile_class(
            "jarfile-v8-only",
            "public int value(){ return 8; }",
            class_name="EightOnly",
        )
        artifact = self.jar("jarfile-resource-truth.jar", [
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
            ),
            ("config/runtime.xml", b"base"),
            ("META-INF/versions/8/config/runtime.xml", b"v8"),
            ("META-INF/versions/9/config/runtime.xml", b"v9"),
            ("META-INF/versions/8/config/v8-only.xml", b"v8-only"),
            (
                "META-INF/versions/8/demo/EightOnly.class",
                v8_only_class.read_bytes(),
            ),
            ("META-INF/services/demo.Service", b"base-service"),
            (
                "META-INF/versions/9/META-INF/services/demo.Service",
                b"versioned-service",
            ),
        ])
        probe = self.root / "JarFileResourceProbe.java"
        probe.write_text(
            """
            import java.io.File;
            import java.net.URLClassLoader;
            import java.util.jar.JarFile;
            import java.util.zip.ZipFile;
            public class JarFileResourceProbe {
              private static String locate(JarFile jar, String name) throws Exception {
                var entry = jar.getJarEntry(name);
                if (entry == null) return "<missing>";
                return entry.getRealName();
              }
              private static String locate(URLClassLoader loader, String name) {
                var resource = loader.getResource(name);
                if (resource == null) return "<missing>";
                var external = resource.toExternalForm();
                int marker = external.lastIndexOf("!/");
                return marker < 0 ? external : external.substring(marker + 2);
              }
              public static void main(String[] args) throws Exception {
                if (args[1].equals("runtime")) {
                  try (var loader = new URLClassLoader(
                      new java.net.URL[] {new File(args[0]).toURI().toURL()}, null)) {
                    for (int i = 2; i < args.length; i++) {
                      if (i > 2) System.out.print("|");
                      System.out.print(locate(loader, args[i]));
                    }
                  }
                  return;
                }
                try (var jar = new JarFile(
                    new File(args[0]), true, ZipFile.OPEN_READ,
                    Runtime.Version.parse(args[1]))) {
                  for (int i = 2; i < args.length; i++) {
                    if (i > 2) System.out.print("|");
                    System.out.print(locate(jar, args[i]));
                  }
                }
              }
            }
            """,
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["javac", str(probe)], capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        def actual(view):
            result = subprocess.run(
                [
                    "java", "-cp", str(self.root), "JarFileResourceProbe",
                    str(artifact), str(view),
                    "config/runtime.xml",
                    "META-INF/services/demo.Service",
                    "config/v8-only.xml",
                    "demo/EightOnly.class",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        self.assertEqual(
            actual(8),
            "config/runtime.xml|META-INF/services/demo.Service|<missing>|<missing>",
        )
        # This is deliberately different from JEP 238's prose constraint
        # n > 8: OpenJDK JarFile accepts versions/8 and selects it whenever
        # the configured runtime view is 9 or later.  getRealName proves the
        # physical member behind each logical lookup, including v8-only names.
        self.assertEqual(
            actual(9),
            "META-INF/versions/9/config/runtime.xml|"
            "META-INF/services/demo.Service|"
            "META-INF/versions/8/config/v8-only.xml|"
            "META-INF/versions/8/demo/EightOnly.class",
        )
        self.assertEqual(
            actual("runtime"),
            "META-INF/versions/9/config/runtime.xml|"
            "META-INF/services/demo.Service|"
            "META-INF/versions/8/config/v8-only.xml|"
            "META-INF/versions/8/demo/EightOnly.class",
        )

        javap = subprocess.run(
            ["javap", "-classpath", str(artifact), "-c", "demo.EightOnly"],
            capture_output=True,
            text=True,
            check=False,
        )
        # javap's class-path resolver follows the JAR-spec floor and cannot
        # find this v8-only class, while JarFile/URLClassLoader above do expose
        # it.  The independent edge oracle therefore selects with JarFile
        # runtime semantics first and invokes javap on extracted class bytes.
        self.assertNotEqual(javap.returncode, 0)
        extracted_class = self.root / "selected-EightOnly.class"
        extracted_class.write_bytes(v8_only_class.read_bytes())
        extracted_javap = subprocess.run(
            ["javap", "-c", str(extracted_class)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            extracted_javap.returncode, 0, extracted_javap.stderr
        )
        self.assertIn("public class demo.EightOnly", extracted_javap.stdout)

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="jarfile-truth-jdk9",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
            target_jvm_major=9,
        )
        selected = {
            item.logical_resource_entry: item.content_sha256
            for item in snapshot.entries
            if item.kind == "resource" and item.runtime_effective
        }
        self.assertEqual(
            selected["config/runtime.xml"], diff._sha256_bytes(b"v9")
        )
        self.assertEqual(
            selected["META-INF/services/demo.Service"],
            diff._sha256_bytes(b"base-service"),
        )
        self.assertEqual(
            selected["config/v8-only.xml"], diff._sha256_bytes(b"v8-only")
        )
        self.assertEqual(
            snapshot.runtime_semantics_diagnostic_codes,
            (
                "NONSTANDARD_MULTI_RELEASE_VERSION_8_PRESENT",
                "NONSTANDARD_MULTI_RELEASE_VERSION_8_RUNTIME_SELECTED",
            ),
        )
        physical_v8 = {
            item.name: item.runtime_effective
            for item in snapshot.entries
            if item.name.startswith("META-INF/versions/8/")
        }
        self.assertEqual(
            physical_v8,
            {
                "META-INF/versions/8/config/runtime.xml": False,
                "META-INF/versions/8/config/v8-only.xml": True,
                "META-INF/versions/8/demo/EightOnly.class": True,
            },
        )

    def test_same_payload_different_zip_metadata_is_packaging_noise_only(self):
        class_file, _ = self.compile_class("same", "public int value(){ return 1; }")
        content = class_file.read_bytes()
        base = self.jar("base.jar", [("demo/Api.class", content)], timestamp=(2024, 1, 1, 0, 0, 0))
        current = self.jar("current.jar", [("demo/Api.class", content)], timestamp=(2025, 1, 1, 0, 0, 0))

        _, _, result = self.compare(base, current)

        self.assertEqual(result["container_diff_status"], "packaging_noise_only")
        self.assertEqual(result["class_diff_status"], "none")
        self.assertEqual(result["resource_diff_status"], "none")
        self.assertEqual(result["entry_delta_count"], 0)

    def test_method_body_change_is_implementation_not_contract_change(self):
        old_class, old_source = self.compile_class("old", "public int value(){ return 1; }")
        new_class, new_source = self.compile_class("new", "public int value(){ return 2; }")
        base = self.jar("base.jar", [("demo/Api.class", old_class.read_bytes())])
        current = self.jar("current.jar", [("demo/Api.class", new_class.read_bytes())])
        old_source.unlink()
        new_source.unlink()

        _, _, result = self.compare(base, current)

        self.assertEqual(result["class_diff_status"], "implementation_changed")
        self.assertEqual(result["comparison_coverage_status"], "complete")
        self.assertEqual(result["runtime_effective_diff_summary"], "unknown")
        self.assertEqual(result["authority"], "artifact_local_observation_only")
        self.assertEqual(len(result["entry_deltas"][0]["observed_delta_identity"]), 64)

    def test_member_addition_is_contract_change(self):
        old_class, _ = self.compile_class("old", "public int value(){ return 1; }")
        new_class, _ = self.compile_class(
            "new", "public int value(){ return 1; } public void added(){}"
        )
        base = self.jar("base.jar", [("demo/Api.class", old_class.read_bytes())])
        current = self.jar("current.jar", [("demo/Api.class", new_class.read_bytes())])

        _, _, result = self.compare(base, current)

        self.assertEqual(result["class_diff_status"], "contract_changed")

    def test_removed_class_enumerates_all_removed_members(self):
        old_class, _ = self.compile_class(
            "removed", "public int value(){ return 1; } public String name(){ return \"x\"; }"
        )
        base = self.jar("removed-base.jar", [("demo/Api.class", old_class.read_bytes())])
        current = self.jar("removed-current.jar", [])

        _, _, result = self.compare(base, current)
        effective = next(
            row for row in result["entry_deltas"]
            if row.get("runtime_effective_analysis") is True
        )
        removed = {
            (
                row["member_scope"]["member_kind"],
                row["member_scope"]["member_name"],
                row["member_scope"]["descriptor"],
            )
            for row in effective["member_deltas"]
            if row["member_change_kind"] == "removed"
        }
        self.assertIn(("method", "value", "()I"), removed)
        self.assertIn(("method", "name", "()Ljava/lang/String;"), removed)
        self.assertIn(("method", "<init>", "()V"), removed)
        self.assertEqual(result["class_comparison_coverage_status"], "complete")

    def test_added_class_enumerates_all_added_members(self):
        new_class, _ = self.compile_class(
            "added-class", "public int value(){ return 2; } public long count;"
        )
        base = self.jar("added-base.jar", [])
        current = self.jar("added-current.jar", [("demo/Api.class", new_class.read_bytes())])

        _, _, result = self.compare(base, current)
        effective = next(
            row for row in result["entry_deltas"]
            if row.get("runtime_effective_analysis") is True
        )
        added = {
            (
                row["member_scope"]["member_kind"],
                row["member_scope"]["member_name"],
                row["member_scope"]["descriptor"],
            )
            for row in effective["member_deltas"]
            if row["member_change_kind"] == "added"
        }
        self.assertIn(("method", "value", "()I"), added)
        self.assertIn(("field", "count", "J"), added)
        self.assertEqual(result["class_comparison_coverage_status"], "complete")

    def test_debug_table_change_is_diagnostic_metadata_only(self):
        debug_class, _ = self.compile_class("debug", "public int value(){ return 1; }", debug="-g")
        stripped_class, _ = self.compile_class("stripped", "public int value(){ return 1; }", debug="-g:none")
        base = self.jar("base.jar", [("demo/Api.class", debug_class.read_bytes())])
        current = self.jar("current.jar", [("demo/Api.class", stripped_class.read_bytes())])

        _, _, result = self.compare(base, current)

        self.assertEqual(result["class_diff_status"], "runtime_diagnostic_metadata_changed")

    def test_service_descriptor_change_is_runtime_topology_observation(self):
        base = self.jar("base.jar", [("META-INF/services/demo.Service", b"demo.Old\n")])
        current = self.jar("current.jar", [("META-INF/services/demo.Service", b"demo.New\n")])

        _, _, result = self.compare(base, current)

        self.assertEqual(result["resource_diff_status"], "runtime_topology_changed")
        self.assertEqual(result["comparison_coverage_status"], "complete")

    def test_spring_factories_preserves_each_auto_configuration_class(self):
        artifact = self.jar("spring-factories.jar", [(
            "META-INF/spring.factories",
            (
                b"org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n"
                b"  vendor.FirstConfig,\\\n"
                b"  vendor.SecondConfig\n"
            ),
        )])

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="artifact-1",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
        )

        resource = next(
            item for item in snapshot.entries
            if item.name == "META-INF/spring.factories"
        )
        self.assertEqual(
            resource.resource_semantic_facts,
            (
                (
                    "property_entry:org.springframework.boot.autoconfigure.EnableAutoConfiguration",
                    "vendor.FirstConfig",
                ),
                (
                    "property_entry:org.springframework.boot.autoconfigure.EnableAutoConfiguration",
                    "vendor.SecondConfig",
                ),
            ),
        )

    def test_spring_and_mybatis_xml_registration_facts_are_preserved(self):
        artifact = self.jar("framework-xml.jar", [(
            "config/runtime.xml",
            b"""<beans xmlns:task='urn:test'>
              <bean id='job' class='vendor.ScheduledConfig' init-method='initialize' primary='true'/>
              <bean id='consumer' class='vendor.Consumer'>
                <property name='job'><ref bean='job'/></property>
              </bean>
              <bean id='quartz' class='org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean'>
                <property name='targetObject'><ref bean='job'/></property>
                <property name='targetMethod'><value>tick</value></property>
              </bean>
              <task:scheduled-tasks><task:scheduled target='job.tick'/></task:scheduled-tasks>
              <mapper namespace='vendor.Mapper'><select id='findOne'>select 1</select></mapper>
            </beans>""",
        )])

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="artifact-xml",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
        )

        resource = next(item for item in snapshot.entries if item.name == "config/runtime.xml")
        self.assertEqual(resource.resource_category, "runtime_topology")
        self.assertIn(
            ("spring_scheduled_method", "job|vendor.ScheduledConfig|tick"),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            ("spring_init_method", "job|vendor.ScheduledConfig|initialize"),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            ("spring_bean_primary", "job|vendor.ScheduledConfig"),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            ("spring_quartz_method", "job|vendor.ScheduledConfig|tick"),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            (
                "spring_bean_property_ref",
                "consumer|vendor.Consumer|job|job|vendor.ScheduledConfig",
            ),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            ("mybatis_mapper_namespace", "vendor.Mapper"),
            resource.resource_semantic_facts,
        )
        self.assertIn(
            ("mybatis_statement", "findOne"),
            resource.resource_semantic_facts,
        )

    def test_xml_with_external_entity_is_not_parsed_and_scope_is_explicit(self):
        artifact = self.jar("unsafe-xml.jar", [(
            "config/runtime.xml",
            b"<!DOCTYPE beans [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><beans/>",
        )])

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="artifact-unsafe-xml",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
        )

        resource = next(item for item in snapshot.entries if item.name == "config/runtime.xml")
        self.assertEqual(
            resource.resource_semantic_facts,
            (("xml_parse_gap", "doctype_or_entity_rejected"),),
        )

    def test_known_mybatis_external_dtd_is_parsed_without_network_resolution(self):
        artifact = self.jar("mybatis-dtd.jar", [(
            "mapper/CityMapper.xml",
            b'''<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "https://mybatis.org/dtd/mybatis-3-mapper.dtd">
            <mapper namespace="sample.CityMapper"><select id="find">select 1</select></mapper>''',
        )])

        snapshot = diff.snapshot_archive(
            artifact,
            artifact_instance_identity="artifact-mybatis-dtd",
            expected_sha256=diff._sha256_file(artifact),
            asm_jar=self.asm_jar,
        )

        resource = next(
            item for item in snapshot.entries
            if item.name == "mapper/CityMapper.xml"
        )
        self.assertIn(
            ("mybatis_mapper_namespace", "sample.CityMapper"),
            resource.resource_semantic_facts,
        )
        self.assertNotIn(
            ("xml_parse_gap", "doctype_or_entity_rejected"),
            resource.resource_semantic_facts,
        )

    def test_unknown_changed_resource_makes_only_that_comparison_scope_partial(self):
        base = self.jar("base.jar", [("config/custom.bin", b"old")])
        current = self.jar("current.jar", [("config/custom.bin", b"new")])

        base_snapshot, current_snapshot, result = self.compare(base, current)

        self.assertEqual(base_snapshot.comparison_coverage_status, "partial")
        self.assertEqual(current_snapshot.comparison_coverage_status, "partial")
        self.assertEqual(result["resource_diff_status"], "unknown")
        self.assertEqual(result["comparison_coverage_status"], "partial")
        self.assertEqual(result["class_comparison_coverage_status"], "complete")
        self.assertIn("unknown_resource:config/custom.bin#0", result["coverage_gaps"])

    def test_unsupported_class_major_is_explicit_incomplete_class_scope(self):
        class_file, _ = self.compile_class("major", "public int value(){ return 1; }")
        old_bytes = class_file.read_bytes()
        new_bytes = bytearray(old_bytes)
        new_bytes[6:8] = (binary_asm_helper.MAX_SUPPORTED_CLASS_MAJOR + 1).to_bytes(2, "big")
        base = self.jar("base.jar", [("demo/Api.class", old_bytes)])
        current = self.jar("current.jar", [("demo/Api.class", bytes(new_bytes))])

        _, current_snapshot, result = self.compare(base, current)

        self.assertEqual(current_snapshot.parse_failure_count, 1)
        self.assertEqual(result["class_diff_status"], "incomplete")
        self.assertEqual(result["comparison_coverage_status"], "partial")

    def test_snapshot_streams_source_once_and_cleans_private_copy_after_success(self):
        artifact = self.jar("single-read.jar", [("safe.txt", b"content")])
        expected_sha256 = diff._sha256_file(artifact)
        real_make_short_temp_dir = diff.make_short_temp_dir
        real_path_open = Path.open
        created = []
        source_opens = []
        source_read_sizes = []

        class RecordingSource:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                self.handle.__enter__()
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def read(self, size=-1):
                source_read_sizes.append(size)
                return self.handle.read(size)

        def recording_make_short_temp_dir(*args, **kwargs):
            path = real_make_short_temp_dir(*args, **kwargs)
            created.append(path)
            return path

        def recording_path_open(path, *args, **kwargs):
            if Path(path) == artifact:
                source_opens.append((args, kwargs))
                return RecordingSource(real_path_open(path, *args, **kwargs))
            return real_path_open(path, *args, **kwargs)

        with (
            mock.patch.object(
                diff,
                "make_short_temp_dir",
                side_effect=recording_make_short_temp_dir,
            ),
            mock.patch.object(Path, "open", new=recording_path_open),
            mock.patch.object(
                diff,
                "_sha256_file",
                side_effect=AssertionError("snapshot_archive reread the source"),
            ),
            mock.patch.object(
                diff, "extract_class_facts", side_effect=self.empty_fact_run
            ),
        ):
            snapshot = diff.snapshot_archive(
                artifact,
                artifact_instance_identity="single-read",
                expected_sha256=expected_sha256,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(snapshot.artifact_content_sha256, expected_sha256)
        self.assertEqual(snapshot.artifact_byte_length, artifact.stat().st_size)
        self.assertEqual(len(source_opens), 1)
        self.assertGreaterEqual(len(source_read_sizes), 2)
        self.assertEqual(set(source_read_sizes), {1024 * 1024})
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_snapshot_cleans_private_copy_when_parser_raises(self):
        artifact = self.jar("parser-error.jar", [("safe.txt", b"content")])
        expected_sha256 = diff._sha256_file(artifact)
        real_make_short_temp_dir = diff.make_short_temp_dir
        created = []
        primary = RuntimeError("safety parser failed")

        def recording_make_short_temp_dir(*args, **kwargs):
            path = real_make_short_temp_dir(*args, **kwargs)
            created.append(path)
            return path

        with (
            mock.patch.object(
                diff,
                "make_short_temp_dir",
                side_effect=recording_make_short_temp_dir,
            ),
            mock.patch.object(diff, "inspect_archive", side_effect=primary),
            self.assertRaises(RuntimeError) as raised,
        ):
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="parser-error",
                expected_sha256=expected_sha256,
                asm_jar=self.asm_jar,
            )

        self.assertIs(raised.exception, primary)
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_snapshot_cleanup_failure_does_not_mask_parser_failure(self):
        artifact = self.jar("cleanup-error.jar", [("safe.txt", b"content")])
        expected_sha256 = diff._sha256_file(artifact)
        real_make_short_temp_dir = diff.make_short_temp_dir
        real_rmtree = shutil.rmtree
        created = []
        primary = RuntimeError("primary parser failure")

        def recording_make_short_temp_dir(*args, **kwargs):
            path = real_make_short_temp_dir(*args, **kwargs)
            created.append(path)
            return path

        try:
            with (
                mock.patch.object(
                    diff,
                    "make_short_temp_dir",
                    side_effect=recording_make_short_temp_dir,
                ),
                mock.patch.object(diff, "inspect_archive", side_effect=primary),
                mock.patch.object(
                    diff.shutil,
                    "rmtree",
                    side_effect=OSError("cleanup denied"),
                ),
                self.assertRaises(RuntimeError) as raised,
            ):
                diff.snapshot_archive(
                    artifact,
                    artifact_instance_identity="cleanup-error",
                    expected_sha256=expected_sha256,
                    asm_jar=self.asm_jar,
                )
        finally:
            for path in created:
                real_rmtree(path, ignore_errors=True)

        self.assertIs(raised.exception, primary)
        self.assertIn(
            "artifact snapshot cleanup failed: OSError: cleanup denied",
            "\n".join(getattr(raised.exception, "__notes__", ()) or ()),
        )

    def test_snapshot_rejects_real_safe_unsafe_safe_path_aba(self):
        artifact = self.jar("aba.jar", [("safe.txt", b"safe")])
        safe_bytes = artifact.read_bytes()
        expected_sha256 = diff._sha256_bytes(safe_bytes)
        unsafe = self.jar("aba-unsafe.jar", [("../Evil.class", b"unsafe")])
        safe_replacement = self.root / "aba-safe-replacement.jar"
        safe_replacement.write_bytes(safe_bytes)
        real_inspect_archive = diff.inspect_archive
        private_entries = []
        observed_class_inputs = []

        def inspect_then_replace_source(private_path, **kwargs):
            result = real_inspect_archive(private_path, **kwargs)
            with zipfile.ZipFile(private_path) as archive:
                private_entries.extend(archive.namelist())
            os.replace(unsafe, artifact)
            return result

        def restore_source_before_final_binding_check(inputs, **kwargs):
            observed_class_inputs.extend(inputs)
            os.replace(safe_replacement, artifact)
            return self.empty_fact_run(inputs, **kwargs)

        with (
            mock.patch.object(
                diff,
                "inspect_archive",
                side_effect=inspect_then_replace_source,
            ),
            mock.patch.object(
                diff,
                "extract_class_facts",
                side_effect=restore_source_before_final_binding_check,
            ),
            self.assertRaises(diff.BinaryArtifactDiffError) as raised,
        ):
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="aba",
                expected_sha256=expected_sha256,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(
            raised.exception.reason_code, "ARTIFACT_CHANGED_DURING_SNAPSHOT"
        )
        self.assertEqual(private_entries, ["safe.txt"])
        self.assertEqual(observed_class_inputs, [])
        self.assertEqual(artifact.read_bytes(), safe_bytes)

    def test_snapshot_rejects_in_place_change_even_when_bytes_are_restored(self):
        artifact = self.jar("in-place.jar", [("safe.txt", b"safe")])
        safe_bytes = artifact.read_bytes()
        expected_sha256 = diff._sha256_bytes(safe_bytes)
        original_metadata = artifact.stat()
        real_inspect_archive = diff.inspect_archive

        def inspect_then_mutate_source(private_path, **kwargs):
            result = real_inspect_archive(private_path, **kwargs)
            with artifact.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"X")
                handle.flush()
                os.fsync(handle.fileno())
            return result

        def restore_source_before_final_binding_check(inputs, **kwargs):
            with artifact.open("r+b") as handle:
                handle.seek(0)
                handle.write(safe_bytes)
                handle.truncate()
                handle.flush()
                os.fsync(handle.fileno())
            os.utime(
                artifact,
                ns=(
                    int(original_metadata.st_atime_ns),
                    int(original_metadata.st_mtime_ns) + 2_000_000_000,
                ),
            )
            return self.empty_fact_run(inputs, **kwargs)

        with (
            mock.patch.object(
                diff,
                "inspect_archive",
                side_effect=inspect_then_mutate_source,
            ),
            mock.patch.object(
                diff,
                "extract_class_facts",
                side_effect=restore_source_before_final_binding_check,
            ),
            self.assertRaises(diff.BinaryArtifactDiffError) as raised,
        ):
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="in-place",
                expected_sha256=expected_sha256,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(
            raised.exception.reason_code, "ARTIFACT_CHANGED_DURING_SNAPSHOT"
        )
        self.assertEqual(artifact.read_bytes(), safe_bytes)

    def test_concurrent_snapshots_use_unique_cleaned_private_directories(self):
        artifact = self.jar("concurrent.jar", [("safe.txt", b"content")])
        expected_sha256 = diff._sha256_file(artifact)
        real_make_short_temp_dir = diff.make_short_temp_dir
        worker_count = 4
        ready = threading.Barrier(worker_count)
        release = threading.Barrier(worker_count)
        lock = threading.Lock()
        created = []
        concurrent_directory_counts = []

        def recording_make_short_temp_dir(*args, **kwargs):
            path = real_make_short_temp_dir(*args, **kwargs)
            with lock:
                created.append(path)
            return path

        def synchronized_empty_fact_run(inputs, **kwargs):
            ready.wait(timeout=10)
            with lock:
                concurrent_directory_counts.append(
                    sum(path.exists() for path in created)
                )
            release.wait(timeout=10)
            return self.empty_fact_run(inputs, **kwargs)

        def run_snapshot(index):
            return diff.snapshot_archive(
                artifact,
                artifact_instance_identity=f"concurrent-{index}",
                expected_sha256=expected_sha256,
                asm_jar=self.asm_jar,
            )

        with (
            mock.patch.object(
                diff,
                "make_short_temp_dir",
                side_effect=recording_make_short_temp_dir,
            ),
            mock.patch.object(
                diff,
                "extract_class_facts",
                side_effect=synchronized_empty_fact_run,
            ),
            ThreadPoolExecutor(max_workers=worker_count) as executor,
        ):
            snapshots = list(executor.map(run_snapshot, range(worker_count)))

        self.assertEqual(len(snapshots), worker_count)
        self.assertEqual(len(created), worker_count)
        self.assertEqual(len(set(created)), worker_count)
        self.assertEqual(
            concurrent_directory_counts, [worker_count] * worker_count
        )
        self.assertTrue(all(not path.exists() for path in created))

    def test_snapshot_rejects_bytes_not_matching_step1_sha(self):
        artifact = self.jar("api.jar", [("readme.txt", b"content")])

        with self.assertRaises(diff.BinaryArtifactDiffError) as error:
            diff.snapshot_archive(
                artifact,
                artifact_instance_identity="artifact-1",
                expected_sha256="0" * 64,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(error.exception.reason_code, "ARTIFACT_SHA256_MISMATCH")


if __name__ == "__main__":
    unittest.main()
