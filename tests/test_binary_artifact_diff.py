import shutil
import subprocess
import sys
import tempfile
import unittest
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

    def compile_class(self, variant, body, *, debug="-g"):
        source = self.root / variant / "src" / "demo" / "Api.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            f"package demo; public class Api {{ {body} }}",
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
        return classes / "demo" / "Api.class", source

    def jar(self, name, entries, *, timestamp=(2024, 1, 1, 0, 0, 0)):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry_name, content in entries:
                info = zipfile.ZipInfo(entry_name, timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)
        return path

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
        java21_class, _ = self.compile_class(
            "mr-21", "public int value(){ return 21; }"
        )
        artifact = self.jar("multi-release.jar", [
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nMulti-Release: true\n\n"),
            ("demo/Api.class", base_class.read_bytes()),
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
            "META-INF/versions/21/demo/Api.class": True,
        })

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
