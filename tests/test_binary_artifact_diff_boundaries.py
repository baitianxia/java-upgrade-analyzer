from __future__ import annotations

import io
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_artifact_diff as diff  # noqa: E402


class _LegacyNoteError(Exception):
    add_note = None


class _BrokenAddNoteError(Exception):
    def add_note(self, _note: str) -> None:
        raise RuntimeError("add_note unavailable")


class _RejectAllNotesError(Exception):
    add_note = None

    def __setattr__(self, name, value):
        if name == "__notes__":
            raise RuntimeError("notes are immutable")
        super().__setattr__(name, value)


class BinaryArtifactDiffBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._archive_number = 0

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, entries, *, comment=b"") -> Path:
        self._archive_number += 1
        path = self.root / f"archive-{self._archive_number}.jar"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                archive.comment = comment
                for name, content in entries:
                    archive.writestr(name, content)
        return path

    def open_archive(self, entries):
        path = self.archive(entries)
        return zipfile.ZipFile(path)

    @staticmethod
    def entry(
        name: str,
        *,
        digest: str = "a",
        kind: str = "resource",
        runtime_effective: bool = True,
        category: str = "runtime_topology",
        normalized_digest: str | None = None,
        logical_class: str | None = None,
        logical_resource: str | None = None,
        name_ordinal: int = 0,
        archive_ordinal: int = 0,
        timestamp=(2024, 1, 1, 0, 0, 0),
        **overrides,
    ) -> diff.ArchiveEntryFact:
        content_digest = digest * 64 if len(digest) == 1 else digest
        return diff.ArchiveEntryFact(
            physical_entry_identity=f"physical:{name}:{name_ordinal}:{content_digest}",
            name=name,
            name_ordinal=name_ordinal,
            archive_ordinal=archive_ordinal,
            kind=kind,
            content_sha256=content_digest,
            byte_length=1,
            crc32=1,
            compression_method=0,
            compressed_size=1,
            timestamp=timestamp,
            external_attributes=0,
            extra_sha256="extra",
            comment_sha256="comment",
            logical_resource_entry=(
                logical_resource
                if logical_resource is not None
                else (name if kind == "resource" else "")
            ),
            logical_class_entry=(
                logical_class
                if logical_class is not None
                else (name if kind == "class" else "")
            ),
            runtime_effective=runtime_effective,
            resource_category=category if kind == "resource" else "",
            normalized_resource_digest=(
                normalized_digest
                if normalized_digest is not None
                else content_digest
            ) if kind == "resource" else "",
            **overrides,
        )

    @staticmethod
    def snapshot(
        entries=(),
        *,
        records=(),
        artifact_sha="a",
        safety=(),
        parse_failures=0,
        diagnostics=(),
        identity="snapshot",
        unknown_attributes=(),
        unknown_resources=(),
    ) -> diff.ArtifactSnapshot:
        sha = artifact_sha * 64 if len(artifact_sha) == 1 else artifact_sha
        return diff.ArtifactSnapshot(
            artifact_instance_identity=identity,
            artifact_content_sha256=sha,
            artifact_byte_length=1,
            archive_comment_sha256="c" * 64,
            entries=tuple(entries),
            class_records=tuple(records),
            class_payloads=(),
            safety_reason_codes=tuple(safety),
            parse_failure_count=parse_failures,
            unknown_attribute_scopes=tuple(unknown_attributes),
            unknown_resource_scopes=tuple(unknown_resources),
            inventory_digest=f"inventory:{identity}",
            parser_identity="parser",
            comparison_coverage_status=(
                "partial"
                if safety or parse_failures or unknown_attributes or unknown_resources
                else "complete"
            ),
            runtime_semantics_diagnostic_codes=tuple(diagnostics),
        )

    @staticmethod
    def class_record(
        entry: str,
        *,
        contract="contract",
        methods=(),
        fields=(),
        attributes=(),
        frame_type="class_fact",
    ):
        return {
            "frame_type": frame_type,
            "class_entry": entry,
            "class_contract_digest": contract,
            "methods": list(methods),
            "fields": list(fields),
            "attribute_inventory": list(attributes),
        }

    @staticmethod
    def method(name="run", descriptor="()V", implementation="impl", **contract):
        return {
            "contract": {
                "name": name,
                "descriptor": descriptor,
                **contract,
            },
            "implementation_digest": implementation,
        }

    def compare(self, base, current):
        return diff.compare_artifact_snapshots(
            base,
            current,
            comparison_or_runtime_scope={"runtime_major": 17},
        )

    def test_stat_fallback_cleanup_notes_and_non_regular_source(self):
        legacy_stat = SimpleNamespace(st_mtime=1.25)
        self.assertEqual(diff._stat_nanoseconds(legacy_stat, "st_mtime"), 1_250_000_000)

        legacy = _LegacyNoteError("legacy")
        diff._add_snapshot_cleanup_note(legacy, "first")
        diff._add_snapshot_cleanup_note(legacy, "second")
        self.assertEqual(legacy.__notes__, ["first", "second"])

        broken = _BrokenAddNoteError("broken")
        diff._add_snapshot_cleanup_note(broken, "fallback")
        self.assertEqual(broken.__notes__, ["fallback"])

        rejected = _RejectAllNotesError("rejected")
        diff._add_snapshot_cleanup_note(rejected, "ignored")
        self.assertFalse(hasattr(rejected, "__notes__"))

        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        handle.fileno.return_value = 7
        directory_identity = diff._ArchiveSourceIdentity(
            device=1,
            inode=2,
            mode=stat.S_IFDIR | 0o755,
            link_count=1,
            byte_length=0,
            modified_nanoseconds=1,
        )
        with mock.patch.object(Path, "open", return_value=handle), mock.patch.object(
            diff.os, "fstat", return_value=SimpleNamespace()
        ), mock.patch.object(
            diff, "_archive_source_identity", return_value=directory_identity
        ), self.assertRaises(diff.BinaryArtifactDiffError) as raised:
            with diff._private_archive_snapshot(Path("not-regular"), "0" * 64):
                self.fail("a non-regular source must not be yielded")
        self.assertEqual(raised.exception.reason_code, "ARTIFACT_FILE_MISSING")

    def test_cleanup_failure_after_success_is_reported(self):
        source = self.root / "source.jar"
        source.write_bytes(b"source")
        snapshot_dir = self.root / "private-snapshot"
        snapshot_dir.mkdir()
        real_rmtree = shutil.rmtree
        try:
            with mock.patch.object(
                diff, "make_short_temp_dir", return_value=snapshot_dir
            ), mock.patch.object(
                diff.shutil, "rmtree", side_effect=PermissionError("busy")
            ), self.assertRaises(diff.BinaryArtifactDiffError) as raised:
                with diff._private_archive_snapshot(
                    source, diff._sha256_file(source)
                ) as captured:
                    self.assertEqual(captured.path.read_bytes(), b"source")
            self.assertEqual(
                raised.exception.reason_code,
                "ARTIFACT_SNAPSHOT_CLEANUP_FAILED",
            )
        finally:
            real_rmtree(snapshot_dir, ignore_errors=True)

    def test_snapshot_properties_records_and_sha_validation_matrix(self):
        complete = self.snapshot(records=[{"class_entry": "A"}, {}])
        self.assertEqual(complete.class_fact_coverage_status, "complete")
        self.assertEqual(complete.class_records_by_entry(), {
            "A": {"class_entry": "A"},
            "": {},
        })
        self.assertEqual(
            self.snapshot(safety=["unsafe"]).class_fact_coverage_status,
            "partial",
        )
        self.assertEqual(
            self.snapshot(parse_failures=1).class_fact_coverage_status,
            "partial",
        )

        uppercase = "ABCDEF" * 10 + "ABCD"
        self.assertEqual(diff._validate_expected_sha(f"  {uppercase}  "), uppercase.lower())
        for invalid in (None, "", "a" * 63, "g" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(
                diff.BinaryArtifactDiffError
            ) as raised:
                diff._validate_expected_sha(invalid)
            self.assertEqual(
                raised.exception.reason_code,
                "ARTIFACT_EXPECTED_SHA256_INVALID",
            )

    def test_multi_release_path_scope_matrix(self):
        self.assertEqual(
            diff._mr_entry_scope("META-INF/versions/9"),
            ("META-INF/versions/9", -1),
        )
        huge_version = "9" * 5000
        huge_name = f"META-INF/versions/{huge_version}/A.class"
        self.assertEqual(diff._mr_entry_scope(huge_name), (huge_name, -1))
        self.assertEqual(diff._mr_entry_scope("plain.txt"), ("plain.txt", 0))
        self.assertEqual(
            diff._mr_class_scope("META-INF/data.txt"),
            ("META-INF/data.txt", -1),
        )
        self.assertEqual(diff._mr_class_scope("demo/A.class"), ("demo/A.class", 0))
        self.assertEqual(
            diff._mr_resource_scope(
                "META-INF/versions/9/META-INF/services/demo.Service"
            )[1],
            -1,
        )

    def test_manifest_parser_rejects_noncanonical_and_ambiguous_forms(self):
        cases = (
            ([], False),
            ([('META-INF/MANIFEST.MF', b'\nMulti-Release: true\n')], False),
            ([('META-INF/MANIFEST.MF', b' continuation-without-header\nMulti-Release: true\n')], True),
            ([('META-INF/MANIFEST.MF', b'Multi-Release: tr\n ue\n')], False),
            ([('META-INF/MANIFEST.MF', b'No-Separator\nMulti-Release: true\n')], True),
            ([('META-INF/MANIFEST.MF', b': true\nMulti-Release: true\n')], True),
            ([('META-INF/MANIFEST.MF', b' Multi-Release: true\n')], False),
            ([('META-INF/MANIFEST.MF', b'Multi-Release:true\n')], False),
            ([('meta-inf/manifest.mf', b'MULTI-RELEASE: TRUE\r')], True),
            ([('META-INF/MANIFEST.MF', b'Multi-Release: true')], True),
        )
        for entries, expected in cases:
            with self.subTest(entries=entries):
                archive_entries = [("META-INF/", b"")] + list(entries)
                with self.open_archive(archive_entries) as archive:
                    self.assertEqual(diff._manifest_is_multi_release(archive), expected)

        two_manifests = [
            ("META-INF/MANIFEST.MF", b"Multi-Release: true\n"),
            ("meta-inf/manifest.mf", b"Multi-Release: true\n"),
        ]
        with self.open_archive(two_manifests) as archive:
            self.assertFalse(diff._manifest_is_multi_release(archive))
            diff._reject_ambiguous_multi_release_manifest(archive)

        with self.open_archive(two_manifests + [
            ("META-INF/versions/9/", b""),
        ]) as archive:
            diff._reject_ambiguous_multi_release_manifest(archive)

        with self.open_archive(two_manifests + [
            ("META-INF/versions/9/config.txt", b"v9"),
        ]) as archive, self.assertRaises(diff.BinaryArtifactDiffError) as raised:
            diff._reject_ambiguous_multi_release_manifest(archive)
        self.assertEqual(
            raised.exception.reason_code,
            "ARTIFACT_MULTI_RELEASE_MANIFEST_AMBIGUOUS",
        )

    def test_runtime_resource_selection_boundaries_and_duplicates(self):
        with self.open_archive([
            ("META-INF/", b""),
            ("demo/A.class", b"class"),
            ("META-INF/versions/7/config.txt", b"invalid"),
            ("META-INF/versions/9/only.txt", b"v9"),
        ]) as archive:
            selected, target_required = diff.select_runtime_resource_entries(
                archive, 8
            )
        self.assertEqual(selected, {})
        self.assertFalse(target_required)

        with self.open_archive([
            ("META-INF/MANIFEST.MF", b"Multi-Release: true\n"),
            ("META-INF/versions/9/only.txt", b"v9"),
        ]) as archive:
            selected, target_required = diff.select_runtime_resource_entries(
                archive, None
            )
        self.assertEqual(selected, {"META-INF/MANIFEST.MF": "META-INF/MANIFEST.MF"})
        self.assertTrue(target_required)

        with self.open_archive([
            ("config.xml", b"one"),
            ("config.xml", b"two"),
        ]) as archive, self.assertRaises(diff.BinaryArtifactDiffError) as raised:
            diff.select_runtime_resource_entries(archive, 17)
        self.assertEqual(
            raised.exception.reason_code,
            "ARTIFACT_RUNTIME_RESOURCE_DUPLICATE",
        )

        with self.open_archive([
            ("META-INF/maven/g/a/pom.xml", b"one"),
            ("META-INF/maven/g/a/pom.xml", b"two"),
        ]) as archive:
            selected, target_required = diff.select_runtime_resource_entries(
                archive, 17
            )
        self.assertEqual(selected, {})
        self.assertFalse(target_required)

    def test_resource_classification_and_digest_matrix(self):
        cases = {
            "folder/": "directory",
            "config/app.xml": "runtime_topology",
            "META-INF/services/demo.Service": "runtime_topology",
            "META-INF/spring/demo.imports": "runtime_topology",
            "META-INF/dubbo/demo.Service": "runtime_topology",
            "META-INF/DEMO.SF": "operational_security",
            "meta-inf/manifest.mf": "distribution_metadata",
            "META-INF/maven/group/artifact/pom.properties": "build_metadata",
            "native/LIB.DLL": "runtime_native",
            "README.txt": "unknown",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(diff._classify_resource(name), expected)

        opaque = b"a\r\nb\r"
        self.assertEqual(
            diff._normalized_resource_digest("README", "unknown", opaque),
            diff._sha256_bytes(opaque),
        )
        expected_lines = diff._identity(
            "ordered_runtime_resource_lines", {"lines": ["A", "B"]}
        )
        for name in (
            "META-INF/services/demo.Service",
            "META-INF/spring/demo.imports",
            "META-INF/dubbo/demo.Service",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    diff._normalized_resource_digest(
                        name, "runtime_topology", b" A # comment\r\n\rB\n# ignored\n"
                    ),
                    expected_lines,
                )
        normalized_xml = b"<root>\n</root>\n"
        self.assertEqual(
            diff._normalized_resource_digest(
                "config.xml", "runtime_topology", b"<root>\r\n</root>\r"
            ),
            diff._sha256_bytes(normalized_xml),
        )

    def test_java_properties_full_line_and_escape_matrix(self):
        content = (
            b"  # ignored\r\n"
            b"! ignored too\r"
            b"plain\n"
            b"escaped\\ key\\:part = value\\tX\\nY\\rZ\\fQ\\=\\:\\ \\x\n"
            b"continued=left\\\n \t right\n"
            b"even=slash\\\\\n"
            b"unicode=\\u0041\n"
            b"short=\\u12\n"
            b"bad=\\uZZZZ\n"
            b"colon:value\n"
            b"space value\n"
            b"tab\tvalue\n"
            b"form\fvalue\n"
            b"trailing=tail\\"
        )
        self.assertEqual(
            diff._java_properties_entries(content),
            (
                ("plain", ""),
                ("escaped key:part", "value\tX\nY\rZ\fQ=: x"),
                ("continued", "leftright"),
                ("even", "slash\\"),
                ("unicode", "A"),
                ("short", "u12"),
                ("bad", "uZZZZ"),
                ("colon", "value"),
                ("space", "value"),
                ("tab", "value"),
                ("form", "value"),
                ("trailing", "tail"),
            ),
        )

    def test_resource_semantic_facts_manifest_properties_and_registrations(self):
        self.assertEqual(diff._resource_semantic_facts("README", "unknown", b"x"), ())
        self.assertEqual(
            diff._resource_semantic_facts(
                "META-INF/MANIFEST.MF",
                "distribution_metadata",
                b"Manifest-Version: 1.0\r\n Name: demo\r\nBad line\r\n\r\n",
            ),
            (("manifest-version", "1.0Name: demo"),),
        )
        self.assertEqual(
            diff._resource_semantic_facts(
                "META-INF/MANIFEST.MF",
                "distribution_metadata",
                b" orphan-continuation\nName: value\n",
            ),
            (("name", "value"),),
        )
        factories = diff._resource_semantic_facts(
            "META-INF/spring.factories",
            "runtime_topology",
            b"a=A,, B\nempty=,\n",
        )
        self.assertEqual(factories, (
            ("property_entry:a", "A"),
            ("property_entry:a", "B"),
        ))
        for name in (
            "META-INF/services/demo.Service",
            "META-INF/spring/demo.imports",
            "META-INF/dubbo/demo.Service",
        ):
            self.assertEqual(
                diff._resource_semantic_facts(
                    name,
                    "runtime_topology",
                    b" A # comment\n\n# ignored\nB\n",
                ),
                (("ordered_entry", "A"), ("ordered_entry", "B")),
            )
        self.assertEqual(
            diff._resource_semantic_facts(
                "META-INF/other.txt", "distribution_metadata", b"anything"
            ),
            (),
        )

    def test_xml_rejection_and_registration_matrix(self):
        self.assertEqual(
            diff._xml_runtime_semantic_facts(b"x" * (4 * 1024 * 1024 + 1)),
            (("xml_parse_gap", "resource_too_large"),),
        )
        for content in (
            b"<!DOCTYPE root [<!ENTITY x 'value'>]><root/>",
            b"<!ENTITY x 'value'><root/>",
            b"<!DOCTYPE root [<!ELEMENT root EMPTY>]><root/>",
            b"<!DOCTYPE root SYSTEM 'https://example.invalid/root.dtd'><root/>",
        ):
            with self.subTest(content=content[:40]):
                self.assertEqual(
                    diff._xml_runtime_semantic_facts(content),
                    (("xml_parse_gap", "doctype_or_entity_rejected"),),
                )
        self.assertEqual(
            diff._xml_runtime_semantic_facts(b"<root>"),
            (("xml_parse_gap", "malformed_xml"),),
        )

        xml = b"""<?xml version='1.0'?>
<p:persistence xmlns:p='urn:p' xmlns:ctx='urn:c'>
  <p:class> demo.Managed </p:class><p:class> </p:class><p:class/>
  <ctx:component-scan base-package='demo.components'/>
  <ctx:component-scan/>
  <scan base-package='demo.mappers'/><scan/>
  <plugin interceptor='demo.Interceptor'/><plugin/>
  <typeHandler javaType='java.lang.String' handler='demo.Handler'/>
  <typeHandler handler='demo.HandlerWithoutType'/>
  <typeHandler javaType='ignored'/>
  <mapper namespace='demo.Mapper'>
    <select id='find' typeHandler='demo.StatementHandler'/>
    <insert/><update id='update'/><delete id='delete'/>
  </mapper>
  <mapper/>
  <bean id='service' class='demo.Service' primary='true' init-method='start'>
    <property name='direct' ref='dependency'/>
    <property name='beanAttr' bean='dependency'/>
    <property name='localAttr' local='dependency'/>
    <property name='childAttr'><ref bean='dependency'/></property>
    <property name='childText'><ref> dependency </ref></property>
    <property name='missingRef'/><property ref='dependency'/>
    <ignored name='notProperty'/>
  </bean>
  <bean name='dependency' class='demo.Dependency'/>
  <bean id='missingClass'/><bean class='missing.Id'/>
  <scheduled ref='service' method='run'/>
  <scheduled target='service.targetMethod'/>
  <scheduled target='service.explicitTarget' method='explicitMethod'/>
  <scheduled target='service'/>
  <scheduled target='&amp;factory'/>
  <scheduled target='&amp;factory.run'/>
  <scheduled/>
  <bean id='quartz' class='org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean'>
    <property name='targetObject'><ref local='service'/></property>
    <property name='targetMethod'><value>quartzRun</value></property>
    <property name='ignored'/><ignored/>
  </bean>
  <bean id='quartzIncomplete' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'>
    <property name='targetObject' ref='service'/>
  </bean>
  <bean id='quartzMethodOnly' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'>
    <property name='targetMethod' value='run'/><property/><property name='targetObject'><ref/></property><property name='targetObject'><ref> </ref></property>
  </bean>
  <bean id='quartzEmpty' class='org.springframework.scheduling.quartz.JobDetailFactoryBean'/>
</p:persistence>"""
        facts = diff._xml_runtime_semantic_facts(xml)
        expected_subset = {
            ("xml_root", "persistence"),
            ("jpa_managed_class", "demo.Managed"),
            ("spring_component_scan", "demo.components"),
            ("mybatis_mapper_scan", "demo.mappers"),
            ("mybatis_plugin_registration", "demo.Interceptor"),
            (
                "mybatis_type_handler_registration",
                "java.lang.String|demo.Handler",
            ),
            (
                "mybatis_type_handler_registration",
                "|demo.HandlerWithoutType",
            ),
            ("mybatis_mapper_namespace", "demo.Mapper"),
            ("mybatis_statement", "find"),
            (
                "mybatis_statement_type_handler",
                "find|demo.StatementHandler",
            ),
            ("mybatis_statement", "update"),
            ("mybatis_statement", "delete"),
            ("spring_bean_class", "service|demo.Service"),
            ("spring_bean_primary", "service|demo.Service"),
            ("spring_init_method", "service|demo.Service|start"),
            ("spring_scheduled_method", "service|demo.Service|run"),
            (
                "spring_scheduled_method",
                "service|demo.Service|targetMethod",
            ),
            (
                "spring_scheduled_method",
                "service|demo.Service|explicitMethod",
            ),
            (
                "spring_quartz_method",
                "service|demo.Service|quartzRun",
            ),
        }
        self.assertTrue(expected_subset <= set(facts), expected_subset - set(facts))
        property_facts = [fact for fact in facts if fact[0] == "spring_bean_property_ref"]
        self.assertEqual(len(property_facts), 7)

        non_persistence = diff._xml_runtime_semantic_facts(
            b"<root><class>ignored.Managed</class><class/><bean id='x' class='X'/></root>"
        )
        self.assertNotIn(("jpa_managed_class", "ignored.Managed"), non_persistence)

    def test_private_archive_inventory_covers_physical_and_runtime_entry_shapes(self):
        path = self.root / "rich.jar"
        with zipfile.ZipFile(path, "w") as archive:
            archive.comment = b"archive-comment"
            directory = zipfile.ZipInfo("config/")
            directory.comment = b"directory-comment"
            directory.extra = b"\x01\x00\x00\x00"
            archive.writestr(directory, b"")
            archive.writestr(
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\nMulti-Release: true\n\n",
            )
            archive.writestr("demo/A.class", b"base-class")
            archive.writestr("demo/B.class", b"second-base-class")
            archive.writestr(
                "META-INF/versions/8/demo/A.class", b"version-eight"
            )
            versioned = zipfile.ZipInfo("META-INF/versions/17/demo/A.class")
            versioned.comment = b"class-comment"
            versioned.extra = b"\x02\x00\x00\x00"
            archive.writestr(versioned, b"version-seventeen")
            archive.writestr(
                "META-INF/versions/21/demo/Future.class", b"future"
            )
            archive.writestr("config/app.xml", b"<root/>")
            archive.writestr(
                "META-INF/versions/17/config/app.xml", b"<root><scan/></root>"
            )
            archive.writestr(
                "META-INF/versions/17/META-INF/services/demo.Service",
                b"ignored.MetaInfOverlay\n",
            )
            archive.writestr("unknown.bin", b"unknown")

        safety = SimpleNamespace(reason_codes=())
        observed_inputs = []

        def fake_extract(inputs, **kwargs):
            observed_inputs.extend(inputs)
            records = [{
                "frame_type": "diagnostic",
                "attribute_inventory": (),
            }]
            for index, item in enumerate(observed_inputs):
                records.append(self.class_record(
                    item.class_entry,
                    attributes=(
                        [{
                            "level": None,
                            "owner": None,
                            "name": "VendorAttribute",
                            "sha256": "vendor",
                        }]
                        if index == 0
                        else []
                    ),
                ))
            return diff.BinaryFactRun(
                parser_identity="test-parser",
                helper_sha256="1" * 64,
                asm_jar_sha256="2" * 64,
                records=tuple(records),
                input_record_count=len(observed_inputs),
                fact_record_count=len(observed_inputs),
                failure_record_count=0,
                class_input_digest="3" * 64,
                fact_output_digest="4" * 64,
                coverage_status="complete",
                stderr="",
            )

        with mock.patch.object(
            diff, "inspect_archive", return_value=safety
        ), mock.patch.object(
            diff, "extract_class_facts", side_effect=fake_extract
        ) as extract:
            snapshot = diff._snapshot_private_archive(
                path,
                source_path=path,
                artifact_instance_identity="rich",
                artifact_content_sha256=diff._sha256_file(path),
                artifact_byte_length=path.stat().st_size,
                target_jvm_major=17,
                safety_policy={"max_class_bytes": 1024},
            )

        extract.assert_called_once()
        self.assertEqual(
            [item.class_entry for item in observed_inputs],
            [
                "demo/B.class#occurrence=0",
                "META-INF/versions/17/demo/A.class#occurrence=0",
            ],
        )
        by_name = {item.name: item for item in snapshot.entries}
        self.assertEqual(by_name["config/"].kind, "directory")
        self.assertTrue(
            by_name["META-INF/versions/17/demo/A.class"].runtime_effective
        )
        self.assertFalse(
            by_name["META-INF/versions/21/demo/Future.class"].runtime_effective
        )
        self.assertTrue(
            by_name["META-INF/versions/17/config/app.xml"].runtime_effective
        )
        self.assertFalse(
            by_name[
                "META-INF/versions/17/META-INF/services/demo.Service"
            ].runtime_effective
        )
        self.assertEqual(
            snapshot.archive_comment_sha256,
            diff._sha256_bytes(b"archive-comment"),
        )
        self.assertEqual(
            snapshot.runtime_semantics_diagnostic_codes,
            (
                "NONSTANDARD_MULTI_RELEASE_VERSION_8_PRESENT",
            ),
        )
        self.assertTrue(snapshot.unknown_attribute_scopes)
        self.assertEqual(snapshot.unknown_resource_scopes, ("unknown.bin",))
        self.assertEqual(snapshot.comparison_coverage_status, "partial")

    def test_member_fact_maps_and_all_delta_kinds(self):
        old_record = self.class_record(
            "A#occurrence=0",
            fields=[
                {"name": None, "descriptor": None, "access": 1},
                {"name": "removed", "descriptor": "I", "access": 1},
                {"name": "contract", "descriptor": "I", "access": 1},
            ],
            methods=[
                {"contract": None, "implementation_digest": None},
                self.method("body", implementation="old"),
                self.method("same", implementation="same"),
            ],
            attributes=[
                {"level": "class", "owner": None, "name": "StackMapTable", "sha256": None},
                {"level": "class", "owner": "A", "name": "Unknown", "sha256": "x"},
            ],
        )
        new_record = self.class_record(
            "A#occurrence=0",
            fields=[
                {"name": "added", "descriptor": "J", "access": 1},
                {"name": "contract", "descriptor": "I", "access": 2},
            ],
            methods=[
                self.method("body", implementation="new"),
                self.method("same", implementation="same"),
            ],
        )
        self.assertEqual(
            diff._attribute_digest_map(old_record, {"StackMapTable"}),
            {("class", None, "StackMapTable"): ("",)},
        )
        method_map = diff._method_digest_map(old_record)
        self.assertEqual(method_map[("", "")], "")
        self.assertEqual(method_map[("body", "()V")], "old")
        member_map = diff._member_fact_map(old_record)
        self.assertIn(("field", "", ""), member_map)
        self.assertIn(("method", "", ""), member_map)

        deltas = diff._member_deltas(
            old_record,
            new_record,
            entry_scope={"entry_name": "A.class"},
            comparison_or_runtime_scope={"runtime": 17},
        )
        kinds = {row["member_scope"]["member_name"]: row["member_change_kind"] for row in deltas}
        self.assertEqual(kinds["added"], "added")
        self.assertEqual(kinds["removed"], "removed")
        self.assertEqual(kinds["contract"], "contract_changed")
        self.assertEqual(kinds["body"], "implementation_changed")
        self.assertNotIn("same", kinds)

    def test_runtime_effective_class_delta_complete_incomplete_and_metadata_matrix(self):
        old = self.entry("old/A.class", kind="class", logical_class="A.class", digest="a")
        new = self.entry("new/A.class", kind="class", logical_class="A.class", digest="b")
        old_key = "old/A.class#occurrence=0"
        new_key = "new/A.class#occurrence=0"
        scope = {"runtime": 17}

        delta, category, gaps = diff._runtime_effective_class_delta(
            None,
            new,
            base_records={},
            current_records={new_key: self.class_record(new_key, fields=[{"name": "x", "descriptor": "I"}])},
            comparison_or_runtime_scope=scope,
        )
        self.assertEqual(category, "contract_changed")
        self.assertEqual(delta["entry_scope"]["base_physical_entry"], "ABSENT")
        self.assertTrue(delta["member_deltas"])
        self.assertEqual(gaps, set())

        _, category, gaps = diff._runtime_effective_class_delta(
            old,
            None,
            base_records={old_key: {"frame_type": "class_failure"}},
            current_records={},
            comparison_or_runtime_scope=scope,
        )
        self.assertEqual(category, "incomplete")
        self.assertEqual(gaps, {"class_parse:A.class"})

        _, category, gaps = diff._runtime_effective_class_delta(
            old,
            new,
            base_records={old_key: self.class_record(old_key)},
            current_records={},
            comparison_or_runtime_scope=scope,
        )
        self.assertEqual(category, "incomplete")
        self.assertEqual(gaps, {"class_parse:A.class"})

        cases = (
            ({}, {}, "incomplete"),
            (
                {old_key: self.class_record(old_key, frame_type="class_failure")},
                {new_key: self.class_record(new_key)},
                "incomplete",
            ),
            (
                {old_key: self.class_record(old_key, attributes=[{"name": "OldUnknown"}])},
                {new_key: self.class_record(new_key, attributes=[{"name": "NewUnknown"}])},
                "incomplete",
            ),
            (
                {old_key: self.class_record(old_key)},
                {new_key: self.class_record(new_key, attributes=[{"name": "NewUnknown"}])},
                "incomplete",
            ),
            (
                {old_key: self.class_record(old_key, contract="old")},
                {new_key: self.class_record(new_key, contract="new")},
                "contract_changed",
            ),
            (
                {old_key: self.class_record(old_key, methods=[self.method(implementation="old")])},
                {new_key: self.class_record(new_key, methods=[self.method(implementation="new")])},
                "implementation_changed",
            ),
            (
                {old_key: self.class_record(old_key, attributes=[{"level": "method", "owner": "run", "name": "StackMapTable", "sha256": "old"}])},
                {new_key: self.class_record(new_key, attributes=[{"level": "method", "owner": "run", "name": "StackMapTable", "sha256": "new"}])},
                "runtime_metadata_changed",
            ),
            (
                {old_key: self.class_record(old_key, attributes=[{"level": "class", "owner": "A", "name": "SourceFile", "sha256": "old"}])},
                {new_key: self.class_record(new_key, attributes=[{"level": "class", "owner": "A", "name": "SourceFile", "sha256": "new"}])},
                "runtime_diagnostic_metadata_changed",
            ),
            (
                {old_key: self.class_record(old_key)},
                {new_key: self.class_record(new_key)},
                "classfile_noise_only",
            ),
        )
        for base_records, current_records, expected in cases:
            with self.subTest(expected=expected):
                delta, category, gaps = diff._runtime_effective_class_delta(
                    old,
                    new,
                    base_records=base_records,
                    current_records=current_records,
                    comparison_or_runtime_scope=scope,
                )
                self.assertEqual(category, expected)
                self.assertEqual(delta["class_change_category"], expected)
                self.assertEqual(bool(gaps), expected == "incomplete")

    def test_compare_snapshot_class_resource_container_and_status_matrix(self):
        unchanged = self.entry("same.txt", digest="a")
        inactive_old = self.entry(
            "META-INF/versions/9/A.class",
            kind="class",
            logical_class="A.class",
            runtime_effective=False,
            digest="a",
        )
        inactive_new = self.entry(
            "META-INF/versions/9/A.class",
            kind="class",
            logical_class="A.class",
            runtime_effective=False,
            digest="b",
        )
        deferred_old = self.entry(
            "B.class", kind="class", runtime_effective=True, digest="a"
        )
        deferred_new = self.entry(
            "B.class", kind="class", runtime_effective=False, digest="b"
        )
        unknown_old = self.entry("unknown.bin", digest="a", category="unknown")
        unknown_new = self.entry("unknown.bin", digest="b", category="unknown")
        mixed_old = self.entry("mixed", digest="a", category="build_metadata")
        mixed_new = self.entry("mixed", digest="b", category="runtime_topology")
        removed = self.entry("removed.txt", digest="a", category="distribution_metadata")
        added = self.entry("added.dll", digest="b", category="runtime_native")
        directory_old = self.entry("dir/", kind="directory", digest="a", category="")
        directory_new = self.entry("dir/", kind="directory", digest="b", category="")
        parse_old = self.entry("Parse.class", kind="class", digest="a")
        parse_new = self.entry("Parse.class", kind="class", digest="b")

        base = self.snapshot(
            [unchanged, inactive_old, deferred_old, unknown_old, mixed_old, removed, directory_old, parse_old],
            records=[],
            artifact_sha="a",
            safety=["base_safety_gap"],
            diagnostics=["BASE_DIAGNOSTIC"],
            identity="base",
        )
        current = self.snapshot(
            [unchanged, inactive_new, deferred_new, unknown_new, mixed_new, added, directory_new, parse_new],
            records=[],
            artifact_sha="b",
            diagnostics=["CURRENT_DIAGNOSTIC", "BASE_DIAGNOSTIC"],
            identity="current",
        )
        result = self.compare(base, current)
        self.assertEqual(result["container_diff_status"], "payload_changed")
        self.assertEqual(result["class_diff_status"], "incomplete")
        self.assertEqual(result["resource_diff_status"], "mixed")
        self.assertEqual(result["comparison_coverage_status"], "partial")
        self.assertEqual(result["class_comparison_coverage_status"], "partial")
        self.assertEqual(
            result["runtime_semantics_diagnostic_codes"],
            ["BASE_DIAGNOSTIC", "CURRENT_DIAGNOSTIC"],
        )
        class_rows = [
            row for row in result["entry_deltas"]
            if "class_change_category" in row
        ]
        self.assertTrue(any(
            row["entry_scope"]["entry_name"] == "META-INF/versions/9/A.class"
            and row["class_change_category"] == "inactive_multi_release_variant"
            for row in class_rows
        ))
        self.assertTrue(any(
            row["entry_scope"]["entry_name"] == "B.class"
            and row["class_change_category"] == "runtime_effective_variant_deferred"
            for row in class_rows
        ))
        self.assertTrue(any("unknown_resource:" in gap for gap in result["coverage_gaps"]))
        self.assertTrue(any("class_parse:" in gap for gap in result["coverage_gaps"]))
        self.assertTrue(any("container_change_category" in row for row in result["entry_deltas"]))

    def test_compare_status_precedence_and_container_classifications(self):
        identical = self.snapshot([], artifact_sha="a", identity="same")
        result = self.compare(identical, identical)
        self.assertEqual(result["container_diff_status"], "identical")
        self.assertEqual(result["class_diff_status"], "none")
        self.assertEqual(result["resource_diff_status"], "none")
        self.assertEqual(result["promotion_status"], "audit_only")

        payload = self.entry("payload.txt", digest="a", timestamp=(2024, 1, 1, 0, 0, 0))
        metadata_changed = self.entry("payload.txt", digest="a", timestamp=(2025, 1, 1, 0, 0, 0))
        packaging = self.compare(
            self.snapshot([payload], artifact_sha="a", identity="base"),
            self.snapshot([metadata_changed], artifact_sha="b", identity="current"),
        )
        self.assertEqual(packaging["container_diff_status"], "packaging_noise_only")
        self.assertTrue(packaging["container_metadata_changed"])

        for category, expected_status in (
            ("build_metadata", "build_metadata_only"),
            ("distribution_metadata", "distribution_metadata_only"),
            ("operational_security", "operational_security_changed"),
            ("runtime_native", "runtime_native_changed"),
            ("runtime_topology", "runtime_topology_changed"),
        ):
            with self.subTest(category=category):
                old = self.entry("resource", digest="a", category=category)
                new = self.entry("resource", digest="b", category=category)
                resource_result = self.compare(
                    self.snapshot([old], artifact_sha="a", identity="base"),
                    self.snapshot([new], artifact_sha="b", identity="current"),
                )
                self.assertEqual(resource_result["resource_diff_status"], expected_status)
                if category in {"distribution_metadata", "operational_security"}:
                    self.assertEqual(
                        resource_result["container_diff_status"],
                        "runtime_observable_metadata_changed",
                    )

    def test_compare_class_status_aggregation_and_effective_reselection(self):
        def comparison(categories):
            base_entries = []
            current_entries = []
            base_records = []
            current_records = []
            for index, category in enumerate(categories):
                name = f"C{index}.class"
                old = self.entry(name, kind="class", digest="a", archive_ordinal=index)
                new = self.entry(name, kind="class", digest="b", archive_ordinal=index)
                base_entries.append(old)
                current_entries.append(new)
                kwargs_old = {}
                kwargs_new = {}
                if category == "contract_changed":
                    kwargs_old["contract"] = "old"
                    kwargs_new["contract"] = "new"
                elif category == "implementation_changed":
                    kwargs_old["methods"] = [self.method(implementation="old")]
                    kwargs_new["methods"] = [self.method(implementation="new")]
                elif category == "runtime_diagnostic_metadata_changed":
                    kwargs_old["attributes"] = [{"level": "class", "owner": name, "name": "SourceFile", "sha256": "old"}]
                    kwargs_new["attributes"] = [{"level": "class", "owner": name, "name": "SourceFile", "sha256": "new"}]
                elif category == "classfile_noise_only":
                    pass
                elif category == "incomplete":
                    kwargs_old["frame_type"] = "class_failure"
                else:
                    self.fail(f"unsupported category {category}")
                base_records.append(self.class_record(f"{name}#occurrence=0", **kwargs_old))
                current_records.append(self.class_record(f"{name}#occurrence=0", **kwargs_new))
            return self.compare(
                self.snapshot(base_entries, records=base_records, artifact_sha="a", identity="base"),
                self.snapshot(current_entries, records=current_records, artifact_sha="b", identity="current"),
            )

        self.assertEqual(
            comparison(["classfile_noise_only"])["class_diff_status"],
            "classfile_noise_only",
        )
        self.assertEqual(
            comparison([
                "classfile_noise_only",
                "runtime_diagnostic_metadata_changed",
            ])["class_diff_status"],
            "runtime_diagnostic_metadata_changed",
        )
        self.assertEqual(
            comparison(["contract_changed", "implementation_changed"])["class_diff_status"],
            "mixed",
        )
        self.assertEqual(
            comparison(["contract_changed", "incomplete"])["class_diff_status"],
            "incomplete",
        )

        old = self.entry(
            "META-INF/versions/9/A.class",
            kind="class",
            logical_class="A.class",
            digest="a",
        )
        new = self.entry(
            "META-INF/versions/17/A.class",
            kind="class",
            logical_class="A.class",
            digest="b",
        )
        old_record = self.class_record(
            "META-INF/versions/9/A.class#occurrence=0", contract="old"
        )
        new_record = self.class_record(
            "META-INF/versions/17/A.class#occurrence=0", contract="new"
        )
        reselection = self.compare(
            self.snapshot([old], records=[old_record], artifact_sha="a", identity="base"),
            self.snapshot([new], records=[new_record], artifact_sha="b", identity="current"),
        )
        effective = [
            row for row in reselection["entry_deltas"]
            if row.get("runtime_effective_analysis") is True
        ]
        self.assertEqual(len(effective), 1)
        self.assertEqual(effective[0]["class_change_category"], "contract_changed")

    def test_compare_direct_class_record_failure_unknown_and_metadata_matrix(self):
        old = self.entry("A.class", kind="class", digest="a")
        new = self.entry("A.class", kind="class", digest="b")
        key = "A.class#occurrence=0"

        missing_current = self.compare(
            self.snapshot(
                [old], records=[self.class_record(key)], artifact_sha="a", identity="base"
            ),
            self.snapshot([new], records=[], artifact_sha="b", identity="current"),
        )
        self.assertEqual(missing_current["class_diff_status"], "incomplete")

        old_unknown = self.compare(
            self.snapshot(
                [old],
                records=[self.class_record(key, attributes=[{"name": "OldUnknown"}])],
                artifact_sha="a",
                identity="base",
            ),
            self.snapshot(
                [new], records=[self.class_record(key)], artifact_sha="b", identity="current"
            ),
        )
        self.assertEqual(old_unknown["class_diff_status"], "incomplete")
        self.assertTrue(any(
            "OldUnknown" in gap for gap in old_unknown["coverage_gaps"]
        ))

        new_unknown = self.compare(
            self.snapshot(
                [old], records=[self.class_record(key)], artifact_sha="a", identity="base"
            ),
            self.snapshot(
                [new],
                records=[self.class_record(key, attributes=[{"name": "NewUnknown"}])],
                artifact_sha="b",
                identity="current",
            ),
        )
        self.assertEqual(new_unknown["class_diff_status"], "incomplete")
        self.assertTrue(any(
            "NewUnknown" in gap for gap in new_unknown["coverage_gaps"]
        ))

        metadata = self.compare(
            self.snapshot(
                [old],
                records=[self.class_record(key, attributes=[{
                    "level": "method",
                    "owner": "run()V",
                    "name": "StackMapTable",
                    "sha256": "old",
                }])],
                artifact_sha="a",
                identity="base",
            ),
            self.snapshot(
                [new],
                records=[self.class_record(key, attributes=[{
                    "level": "method",
                    "owner": "run()V",
                    "name": "StackMapTable",
                    "sha256": "new",
                }])],
                artifact_sha="b",
                identity="current",
            ),
        )
        self.assertEqual(metadata["class_diff_status"], "runtime_metadata_changed")

        old_selected = self.entry(
            "META-INF/versions/9/A.class",
            kind="class",
            logical_class="A.class",
            digest="c",
        )
        new_selected = self.entry(
            "META-INF/versions/17/A.class",
            kind="class",
            logical_class="A.class",
            digest="c",
        )
        same_bytes_reselection = self.compare(
            self.snapshot([old_selected], artifact_sha="a", identity="base"),
            self.snapshot([new_selected], artifact_sha="b", identity="current"),
        )
        self.assertFalse(any(
            row.get("runtime_effective_analysis") is True
            for row in same_bytes_reselection["entry_deltas"]
        ))


if __name__ == "__main__":
    unittest.main()
