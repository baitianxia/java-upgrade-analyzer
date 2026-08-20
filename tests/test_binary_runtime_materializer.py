import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_step  # noqa: E402
from binary_runtime_materializer import (  # noqa: E402
    BinaryRuntimeMaterializationError,
    _archive_security_markers,
    _packaged_runtime_configuration,
    _properties,
    materialize_binary_pipeline_config,
)


class BinaryRuntimeMaterializerTest(unittest.TestCase):
    @staticmethod
    def write_artifact(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("fixture/payload.bin", content)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def fixture(self, root):
        report = root / ".upgrade-report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)
        items = []
        business = []
        provenance = []
        for side, version in (("base", "1"), ("current", "2")):
            business_path = root / f"{side}-business.jar"
            business_sha = self.write_artifact(
                business_path, f"business-{side}".encode()
            )
            dependency = root / f"{side}-dependency.jar"
            dependency_sha = self.write_artifact(
                dependency, f"dependency-{side}".encode()
            )
            lib_entry = f"BOOT-INF/lib/library-{version}.jar"
            outer = root / f"{side}-outer.jar"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/fixture/payload.bin",
                    f"business-{side}".encode(),
                )
                archive.writestr(lib_entry, dependency.read_bytes())
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business.append({
                "side": side,
                "retained_path": str(business_path),
                "sha256": business_sha,
                "outer_artifact_path": str(outer),
                "outer_artifact_sha256": outer_sha,
                "container_and_launcher_kind": "spring-boot-executable-jar",
            })
            items.append({
                "side": side,
                "coord": "com.acme:library",
                "version": version,
                "lib_entry": lib_entry,
                "retained_path": str(dependency),
                "nested_jar_sha256": dependency_sha,
                "outer_artifact_sha256": outer_sha,
                "runtime_classpath_index": 0,
                "purposes": ["binary_runtime"],
            })
            jdk = root / f"{side}-jdk"
            jdk.mkdir()
            provenance.append({
                "side": side,
                "target_module": "app",
                "jdk_home": str(jdk),
                "artifact_path": str(outer),
                "artifact_sha256": outer_sha,
            })
        (dependencies / "dependency_jars.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": items,
                "business_artifacts": business,
                "runtime_closure": {
                    side: {
                        "coverage_status": "complete",
                        "coverage_gaps": [],
                        "expected_dependency_count": 1,
                        "retained_dependency_count": 1,
                        "business_artifact_count": 1,
                    }
                    for side in ("base", "current")
                },
            }),
            encoding="utf-8",
        )
        (dependencies / "build_provenance.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v2",
                "sides": provenance,
            }),
            encoding="utf-8",
        )
        return report

    def test_multi_release_jarfile_property_policy_is_bound_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            config = materialize_binary_pipeline_config(report)
            for side in ("base", "current"):
                policy = config[side]["runtime_profile"]["loader_topology"][
                    "multi_release_jar_runtime_policy"
                ]
                self.assertEqual(
                    policy["policy_identity"],
                    "openjdk-jarfile-default-properties-v1",
                )
                self.assertEqual(
                    policy["jdk.util.jar.enableMultiRelease"], "true"
                )
                self.assertEqual(
                    policy["jdk.util.jar.version"],
                    "target-runtime-feature",
                )

            unsupported = (
                {
                    "jvm_system_properties": {
                        "jdk.util.jar.enableMultiRelease": "false"
                    }
                },
                {
                    "base_jvm_arguments": [
                        "-Djdk.util.jar.enableMultiRelease=force"
                    ]
                },
                {
                    "current_runtime_jvm_arguments": (
                        "-Xmx256m -Djdk.util.jar.version=8"
                    )
                },
                {
                    "jvm_system_properties": {
                        "jdk.util.jar.enableMultiRelease": "unexpected"
                    }
                },
                {
                    "jvm_system_properties": {
                        "jdk.util.jar.enableMultiRelease": "TRUE"
                    }
                },
            )
            for runtime_overrides in unsupported:
                with self.subTest(runtime_overrides=runtime_overrides):
                    with self.assertRaises(
                        BinaryRuntimeMaterializationError
                    ) as raised:
                        materialize_binary_pipeline_config(
                            report, runtime_overrides=runtime_overrides
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "BINARY_RUNTIME_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
                    )

            explicitly_default = materialize_binary_pipeline_config(
                report,
                runtime_overrides={
                    "jvm_system_properties": {
                        "jdk.util.jar.enableMultiRelease": " true "
                    }
                },
            )
            self.assertEqual(
                explicitly_default["base"]["runtime_profile"]
                ["loader_topology"]["multi_release_jar_runtime_policy"]
                ["jdk.util.jar.enableMultiRelease"],
                "true",
            )

            with self.assertRaises(
                BinaryRuntimeMaterializationError
            ) as malformed:
                materialize_binary_pipeline_config(
                    report,
                    runtime_overrides={
                        "jvm_arguments": "-Xmx256m 'unterminated"
                    },
                )
            self.assertEqual(
                malformed.exception.reason_code,
                "BINARY_RUNTIME_JVM_ARGUMENTS_INVALID",
            )

    def test_java_properties_escaping_continuation_unicode_and_last_wins(self):
        parsed = _properties(
            b"escaped\\:key\\ with\\ space = value\\ with\\ spaces\n"
            b"unicode=\\u4F60\\u597D\n"
            b"continued=left\\\n   right\n"
            b"duplicate=first\nduplicate:last\n"
            b"white\\ key\tvalue\n"
            b"escaped-newline=line\\nfeed\n"
        )

        self.assertEqual(parsed["escaped:key with space"], "value with spaces")
        self.assertEqual(parsed["unicode"], "你好")
        self.assertEqual(parsed["continued"], "leftright")
        self.assertEqual(parsed["duplicate"], "last")
        self.assertEqual(parsed["white key"], "value")
        self.assertEqual(parsed["escaped-newline"], "line\nfeed")

    def test_malformed_properties_unicode_is_a_configuration_coverage_gap(self):
        with self.assertRaises(ValueError):
            _properties(b"broken=\\u12G4\n")
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "malformed-properties.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("application.properties", b"broken=\\u12G4\n")

            properties, gaps = _packaged_runtime_configuration(
                artifact, target_jvm_major=21
            )

        self.assertEqual(properties, {})
        self.assertIn("packaged_properties_parse_failed:ValueError", gaps)

    def test_materializes_two_complete_ordered_runtime_sides(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            config = materialize_binary_pipeline_config(report)

        self.assertEqual(
            config["runtime_comparison"]["comparison_intent"],
            "release_snapshot",
        )
        for side in ("base", "current"):
            artifacts = config[side]["artifacts"]
            self.assertEqual([item["slot"] for item in artifacts], [0, 1])
            self.assertEqual(
                len({item["outer_artifact_sha256"] for item in artifacts}),
                1,
            )
            self.assertTrue(all(
                len(item["content_sha256"]) == 64
                and set(item["content_sha256"]) <= set("0123456789abcdef")
                for item in artifacts
            ))
            self.assertRegex(
                artifacts[0]["outer_artifact_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(artifacts[0]["path_kind"], "business_classes")
            self.assertEqual(artifacts[1]["lineage"], "com.acme:library")
            self.assertTrue(
                artifacts[1]["coord"].startswith("com.acme:library:")
            )
            self.assertEqual(
                config[side]["runtime_profile"][
                    "runtime_class_closure_coverage_status"
                ],
                "complete",
            )

    def test_missing_packaged_main_class_marks_entrypoint_profile_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            config = materialize_binary_pipeline_config(report)

        for side in ("base", "current"):
            profile = config[side]["runtime_profile"]
            self.assertEqual(
                profile["business_entrypoint_profile"]["coverage_status"],
                "partial",
            )
            self.assertIn(
                "packaged_main_class_manifest_missing",
                profile["business_entrypoint_profile"]["coverage_gaps"],
            )
            self.assertIn(
                "packaged_main_class_manifest_missing",
                profile["entrypoint_discovery_coverage_gaps"],
            )

    def test_real_materializer_and_step1_preflight_share_digest_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))

            result = run_step.validate_step1_runtime_inputs({}, report)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["artifact_count"], 4)

    def test_retained_nested_jar_must_match_its_outer_container_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            dependencies = report / "evidence" / "dependencies"
            manifest_path = dependencies / "dependency_jars.json"
            provenance_path = dependencies / "build_provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "base"
            )
            dependency = next(
                item for item in manifest["items"] if item["side"] == "base"
            )
            outer = Path(business["outer_artifact_path"])
            wrong_nested = Path(tmp) / "wrong-nested.jar"
            self.write_artifact(wrong_nested, b"wrong-runtime-bytes")
            with zipfile.ZipFile(outer, "w") as archive:
                with zipfile.ZipFile(business["retained_path"]) as retained:
                    archive.writestr(
                        "BOOT-INF/classes/fixture/payload.bin",
                        retained.read("fixture/payload.bin"),
                    )
                archive.writestr(
                    dependency["lib_entry"], wrong_nested.read_bytes()
                )
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business["outer_artifact_sha256"] = outer_sha
            dependency["outer_artifact_sha256"] = outer_sha
            next(
                item for item in provenance["sides"] if item["side"] == "base"
            )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_CONTAINER_ENTRY_DIGEST_MISMATCH",
            ):
                materialize_binary_pipeline_config(report)

    def test_retained_business_content_must_match_outer_container_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            dependencies = report / "evidence" / "dependencies"
            manifest_path = dependencies / "dependency_jars.json"
            provenance_path = dependencies / "build_provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "base"
            )
            dependency = next(
                item for item in manifest["items"] if item["side"] == "base"
            )
            outer = Path(business["outer_artifact_path"])
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/fixture/payload.bin",
                    b"different-deployed-business-bytes",
                )
                archive.writestr(
                    dependency["lib_entry"],
                    Path(dependency["retained_path"]).read_bytes(),
                )
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business["outer_artifact_sha256"] = outer_sha
            dependency["outer_artifact_sha256"] = outer_sha
            next(
                item for item in provenance["sides"] if item["side"] == "base"
            )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_BUSINESS_CONTENT_MISMATCH",
            ):
                materialize_binary_pipeline_config(report)

    def test_signed_or_sealed_runtime_is_not_labeled_unsigned_unsealed(self):
        for label, extra_entries in (
            (
                "main-sealed",
                {"META-INF/MANIFEST.MF": (
                    "Manifest-Version: 1.0\r\nSealed: true\r\n\r\n"
                )},
            ),
            (
                "package-sealed",
                {"META-INF/MANIFEST.MF": (
                    "Manifest-Version: 1.0\r\n\r\n"
                    "Name: fixture/\r\nSealed: true\r\n\r\n"
                )},
            ),
            (
                "signed",
                {
                    "META-INF/TEST.SF": "Signature-Version: 1.0\r\n\r\n",
                    "META-INF/TEST.RSA": b"signature-block",
                },
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                report = self.fixture(Path(tmp))
                dependencies = report / "evidence" / "dependencies"
                manifest_path = dependencies / "dependency_jars.json"
                provenance_path = dependencies / "build_provenance.json"
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                provenance = json.loads(
                    provenance_path.read_text(encoding="utf-8")
                )
                business = next(
                    item for item in manifest["business_artifacts"]
                    if item["side"] == "base"
                )
                dependency = next(
                    item for item in manifest["items"]
                    if item["side"] == "base"
                )
                outer = Path(business["outer_artifact_path"])
                with zipfile.ZipFile(outer, "w") as archive:
                    with zipfile.ZipFile(business["retained_path"]) as retained:
                        archive.writestr(
                            "BOOT-INF/classes/fixture/payload.bin",
                            retained.read("fixture/payload.bin"),
                        )
                    archive.writestr(
                        dependency["lib_entry"],
                        Path(dependency["retained_path"]).read_bytes(),
                    )
                    for name, content in extra_entries.items():
                        archive.writestr(name, content)
                outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
                business["outer_artifact_sha256"] = outer_sha
                dependency["outer_artifact_sha256"] = outer_sha
                next(
                    item for item in provenance["sides"]
                    if item["side"] == "base"
                )["artifact_sha256"] = outer_sha
                manifest_path.write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                provenance_path.write_text(
                    json.dumps(provenance), encoding="utf-8"
                )

                with self.assertRaisesRegex(
                    BinaryRuntimeMaterializationError,
                    "BINARY_RUNTIME_SIGNED_OR_SEALED_UNSUPPORTED",
                ):
                    materialize_binary_pipeline_config(report)

    def test_retained_signed_or_sealed_dependency_does_not_abort_step4(self):
        variants = (
            (
                "sealed",
                {"META-INF/MANIFEST.MF": (
                    "Manifest-Version: 1.0\r\nSealed: true\r\n\r\n"
                )},
            ),
            (
                "signed",
                {
                    "META-INF/TEST.SF": "Signature-Version: 1.0\r\n\r\n",
                    "META-INF/TEST.RSA": b"signature-block",
                },
            ),
        )
        for label, extra_entries in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                report = self.fixture(Path(tmp))
                dependencies = report / "evidence" / "dependencies"
                manifest_path = dependencies / "dependency_jars.json"
                provenance_path = dependencies / "build_provenance.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
                business = next(
                    item for item in manifest["business_artifacts"]
                    if item["side"] == "base"
                )
                dependency = next(
                    item for item in manifest["items"] if item["side"] == "base"
                )
                retained = Path(dependency["retained_path"])
                with zipfile.ZipFile(retained, "w") as archive:
                    archive.writestr("fixture/payload.bin", b"dependency-base")
                    for name, content in extra_entries.items():
                        archive.writestr(name, content)
                nested_sha = hashlib.sha256(retained.read_bytes()).hexdigest()
                dependency["nested_jar_sha256"] = nested_sha

                outer = Path(business["outer_artifact_path"])
                with zipfile.ZipFile(outer, "w") as archive:
                    with zipfile.ZipFile(business["retained_path"]) as retained_business:
                        archive.writestr(
                            "BOOT-INF/classes/fixture/payload.bin",
                            retained_business.read("fixture/payload.bin"),
                        )
                    archive.writestr(dependency["lib_entry"], retained.read_bytes())
                outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
                business["outer_artifact_sha256"] = outer_sha
                dependency["outer_artifact_sha256"] = outer_sha
                next(
                    item for item in provenance["sides"] if item["side"] == "base"
                )["artifact_sha256"] = outer_sha
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

                self.assertTrue(_archive_security_markers(retained))
                config = materialize_binary_pipeline_config(report)

                self.assertEqual(
                    config["base"]["artifacts"][1]["content_sha256"], nested_sha
                )

    def test_plain_signed_outer_is_rejected_before_unsigned_profile_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            dependencies = report / "evidence" / "dependencies"
            manifest_path = dependencies / "dependency_jars.json"
            provenance_path = dependencies / "build_provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "base"
            )
            dependency = next(
                item for item in manifest["items"] if item["side"] == "base"
            )
            business["container_and_launcher_kind"] = "java-classpath"
            outer = Path(business["outer_artifact_path"])
            with zipfile.ZipFile(outer, "w") as archive:
                with zipfile.ZipFile(business["retained_path"]) as retained:
                    archive.writestr(
                        "fixture/payload.bin",
                        retained.read("fixture/payload.bin"),
                    )
                archive.writestr(
                    dependency["lib_entry"],
                    Path(dependency["retained_path"]).read_bytes(),
                )
                archive.writestr(
                    "META-INF/PLAIN.SF", "Signature-Version: 1.0\r\n\r\n"
                )
                archive.writestr("META-INF/PLAIN.RSA", b"signature-block")
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business["outer_artifact_sha256"] = outer_sha
            dependency["outer_artifact_sha256"] = outer_sha
            next(
                item for item in provenance["sides"] if item["side"] == "base"
            )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(
                json.dumps(provenance), encoding="utf-8"
            )

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_SIGNED_OR_SEALED_UNSUPPORTED",
            ):
                materialize_binary_pipeline_config(report)

    def test_materialized_config_carries_step0_jdk_preflight_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            config = materialize_binary_pipeline_config(
                report,
                runtime_overrides={
                    "step0_preflight": {
                        "sides": {
                            "base": {"jdk": {"jdk_preflight_identity": "base-jdk"}},
                            "current": {"jdk": {"jdk_preflight_identity": "current-jdk"}},
                        }
                    }
                },
            )

        self.assertEqual(config["base"]["jdk_preflight_identity"], "base-jdk")
        self.assertEqual(
            config["current"]["jdk_preflight_identity"], "current-jdk"
        )

    def test_missing_one_side_business_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["business_artifacts"] = [
                item for item in manifest["business_artifacts"]
                if item["side"] != "base"
            ]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_BUSINESS_ARTIFACT_CARDINALITY",
            ):
                materialize_binary_pipeline_config(report)

    def test_missing_authoritative_artifact_digest_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "base"
            )["sha256"] = ""
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_ARTIFACT_IDENTITY_INVALID",
            ):
                materialize_binary_pipeline_config(report)

    def test_build_provenance_must_name_the_same_outer_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            next(
                item for item in provenance["sides"] if item["side"] == "base"
            )["artifact_sha256"] = "0" * 64
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_PROVENANCE_ARTIFACT_IDENTITY_MISMATCH",
            ):
                materialize_binary_pipeline_config(report)

    def test_duplicate_runtime_classpath_position_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            first = next(
                item for item in manifest["items"] if item["side"] == "base"
            )
            manifest["items"].append({
                **first,
                "coord": "com.acme:duplicate",
                "lib_entry": "BOOT-INF/lib/duplicate.jar",
            })
            manifest["runtime_closure"]["base"].update({
                "expected_dependency_count": 2,
                "retained_dependency_count": 2,
            })
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_CLASSPATH_INDEX_DUPLICATE",
            ):
                materialize_binary_pipeline_config(report)

    def test_malformed_purpose_list_cannot_silently_drop_runtime_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            next(
                item for item in manifest["items"] if item["side"] == "base"
            )["purposes"] = "binary_runtime"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
            ):
                materialize_binary_pipeline_config(report)

    def test_changed_artifact_only_v2_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = report / "evidence" / "dependencies" / "dependency_jars.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema"] = "java-upgrade-analyzer.step1-dependency-jars.v2"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_MANIFEST_SCHEMA_INVALID",
            ):
                materialize_binary_pipeline_config(report)

    def test_unknown_build_provenance_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            provenance["schema"] = "java-upgrade-analyzer.build-provenance.v1"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_PROVENANCE_SCHEMA_INVALID",
            ):
                materialize_binary_pipeline_config(report)

    def test_packaged_properties_materialize_profiles_and_condition_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = report / "evidence" / "dependencies" / "dependency_jars.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            for business in manifest["business_artifacts"]:
                path = Path(business["retained_path"])
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(
                        "application.properties",
                        "spring.profiles.active=prod\nfeature.scheduler=true\n",
                    )
                    archive.writestr(
                        "application-prod.properties",
                        "feature.mode=live\n",
                    )
                business["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                side = business["side"]
                outer = Path(business["outer_artifact_path"])
                with zipfile.ZipFile(outer, "w") as archive:
                    archive.writestr(
                        "BOOT-INF/classes/application.properties",
                        "spring.profiles.active=prod\nfeature.scheduler=true\n",
                    )
                    archive.writestr(
                        "BOOT-INF/classes/application-prod.properties",
                        "feature.mode=live\n",
                    )
                    for item in manifest["items"]:
                        if item["side"] == side:
                            archive.writestr(
                                item["lib_entry"],
                                Path(item["retained_path"]).read_bytes(),
                            )
                outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
                business["outer_artifact_sha256"] = outer_sha
                for item in manifest["items"]:
                    if item["side"] == side:
                        item["outer_artifact_sha256"] = outer_sha
                next(
                    item for item in provenance["sides"] if item["side"] == side
                )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            config = materialize_binary_pipeline_config(report)

        for side in ("base", "current"):
            profile = config[side]["runtime_profile"]
            self.assertEqual(profile["active_profile_identities"], ["prod"])
            self.assertEqual(
                profile["resolved_configuration_properties"]["feature.mode"],
                "live",
            )
            self.assertEqual(profile["resource_selection_coverage_status"], "complete")

    def test_packaged_properties_follow_target_jvm_multi_release_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            manifest_bytes = (
                b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
            )
            for business in manifest["business_artifacts"]:
                side = business["side"]
                retained = Path(business["retained_path"])
                entries = {
                    "META-INF/MANIFEST.MF": manifest_bytes,
                    "application.properties": (
                        b"feature.mode=base\n"
                        b"spring.profiles.active=v8only\n"
                    ),
                    "META-INF/versions/8/application.properties": (
                        b"feature.mode=version8\n"
                    ),
                    # There is deliberately no base config/application.properties.
                    # OpenJDK's runtime lookup selects versions/8 for target 9+
                    # despite JEP 238's n > 8 prose constraint.  This unique
                    # profile resource distinguishes the actual target-8/target-9
                    # views without introducing ambiguous default locations.
                    "META-INF/versions/8/application-v8only.properties": (
                        b"v8.only=runtime-selected\n"
                    ),
                    "META-INF/versions/9/application.properties": (
                        b"feature.mode=version9\n"
                        b"spring.profiles.active=v8only\n"
                    ),
                }
                with zipfile.ZipFile(retained, "w") as archive:
                    for name, content in entries.items():
                        archive.writestr(name, content)
                business["sha256"] = hashlib.sha256(
                    retained.read_bytes()
                ).hexdigest()
                outer = Path(business["outer_artifact_path"])
                with zipfile.ZipFile(outer, "w") as archive:
                    archive.writestr("META-INF/MANIFEST.MF", manifest_bytes)
                    for name, content in entries.items():
                        if name != "META-INF/MANIFEST.MF":
                            archive.writestr(f"BOOT-INF/classes/{name}", content)
                    for item in manifest["items"]:
                        if item["side"] == side:
                            archive.writestr(
                                item["lib_entry"],
                                Path(item["retained_path"]).read_bytes(),
                            )
                outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
                business["outer_artifact_sha256"] = outer_sha
                for item in manifest["items"]:
                    if item["side"] == side:
                        item["outer_artifact_sha256"] = outer_sha
                side_provenance = next(
                    item for item in provenance["sides"]
                    if item["side"] == side
                )
                side_provenance["artifact_sha256"] = outer_sha
                jdk = Path(side_provenance["jdk_home"])
                feature = "1.8.0_402" if side == "base" else "9.0.4"
                (jdk / "release").write_text(
                    f'JAVA_VERSION="{feature}"\n', encoding="utf-8"
                )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(
                json.dumps(provenance), encoding="utf-8"
            )

            config = materialize_binary_pipeline_config(report)

        self.assertEqual(
            config["base"]["runtime_profile"]
            ["resolved_configuration_properties"]["feature.mode"],
            "base",
        )
        self.assertEqual(
            config["current"]["runtime_profile"]
            ["resolved_configuration_properties"]["feature.mode"],
            "version9",
        )
        self.assertNotIn(
            "v8.only",
            config["base"]["runtime_profile"]
            ["resolved_configuration_properties"],
        )
        self.assertEqual(
            config["current"]["runtime_profile"]
            ["resolved_configuration_properties"]["v8.only"],
            "runtime-selected",
        )
        self.assertEqual(
            config["base"]["runtime_profile"]
            ["resource_selection_coverage_status"],
            "complete",
        )

    def test_unknown_target_for_versioned_packaged_config_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "current"
            )
            manifest_bytes = (
                b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
            )
            retained = Path(business["retained_path"])
            with zipfile.ZipFile(retained, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", manifest_bytes)
                archive.writestr("application.properties", "mode=base\n")
                archive.writestr(
                    "META-INF/versions/9/application.properties",
                    "mode=versioned\n",
                )
            business["sha256"] = hashlib.sha256(
                retained.read_bytes()
            ).hexdigest()
            outer = Path(business["outer_artifact_path"])
            with zipfile.ZipFile(outer, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", manifest_bytes)
                archive.writestr(
                    "BOOT-INF/classes/application.properties", "mode=base\n"
                )
                archive.writestr(
                    "BOOT-INF/classes/META-INF/versions/9/application.properties",
                    "mode=versioned\n",
                )
                for item in manifest["items"]:
                    if item["side"] == "current":
                        archive.writestr(
                            item["lib_entry"],
                            Path(item["retained_path"]).read_bytes(),
                        )
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business["outer_artifact_sha256"] = outer_sha
            for item in manifest["items"]:
                if item["side"] == "current":
                    item["outer_artifact_sha256"] = outer_sha
            next(
                item for item in provenance["sides"]
                if item["side"] == "current"
            )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(
                json.dumps(provenance), encoding="utf-8"
            )

            config = materialize_binary_pipeline_config(report)

        profile = config["current"]["runtime_profile"]
        self.assertEqual(profile["resource_selection_coverage_status"], "partial")
        self.assertIn(
            "packaged_multi_release_target_jvm_unknown",
            profile["runtime_configuration_coverage_gaps"],
        )

    def test_dependency_application_configuration_is_explicitly_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            dependencies = report / "evidence" / "dependencies"
            manifest_path = dependencies / "dependency_jars.json"
            provenance_path = dependencies / "build_provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            dependency = next(
                item for item in manifest["items"]
                if item["side"] == "current"
            )
            dependency_path = Path(dependency["retained_path"])
            with zipfile.ZipFile(dependency_path, "w") as archive:
                archive.writestr(
                    "config/application-library.yaml", "feature: enabled\n"
                )
            dependency["nested_jar_sha256"] = hashlib.sha256(
                dependency_path.read_bytes()
            ).hexdigest()
            business = next(
                item for item in manifest["business_artifacts"]
                if item["side"] == "current"
            )
            outer = Path(business["outer_artifact_path"])
            with zipfile.ZipFile(outer, "w") as archive:
                with zipfile.ZipFile(business["retained_path"]) as retained:
                    archive.writestr(
                        "BOOT-INF/classes/fixture/payload.bin",
                        retained.read("fixture/payload.bin"),
                    )
                archive.writestr(
                    dependency["lib_entry"], dependency_path.read_bytes()
                )
            outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
            business["outer_artifact_sha256"] = outer_sha
            dependency["outer_artifact_sha256"] = outer_sha
            next(
                item for item in provenance["sides"]
                if item["side"] == "current"
            )["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(
                json.dumps(provenance), encoding="utf-8"
            )

            config = materialize_binary_pipeline_config(report)

        profile = config["current"]["runtime_profile"]
        self.assertEqual(profile["runtime_configuration_coverage_status"], "partial")
        self.assertIn(
            "dependency_packaged_configuration_not_materialized:"
            "com.acme:library:config/application-library.yaml",
            profile["runtime_configuration_coverage_gaps"],
        )

    def test_materializes_manifest_start_class_from_outer_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = report / "evidence" / "dependencies" / "dependency_jars.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provenance_path = report / "evidence" / "dependencies" / "build_provenance.json"
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            for business in manifest["business_artifacts"]:
                retained = Path(business["retained_path"])
                with zipfile.ZipFile(retained, "w") as archive:
                    archive.writestr("example/Application.class", b"class-bytes")
                business["sha256"] = hashlib.sha256(retained.read_bytes()).hexdigest()
                outer = Path(business["outer_artifact_path"])
                with zipfile.ZipFile(outer, "w") as archive:
                    archive.writestr(
                        "META-INF/MANIFEST.MF",
                        "Manifest-Version: 1.0\r\n"
                        "Main-Class: org.springframework.boot.loader.launch.JarLauncher\r\n"
                        "Start-Class: example.Application\r\n\r\n",
                    )
                    archive.writestr(
                        "BOOT-INF/classes/example/Application.class",
                        b"class-bytes",
                    )
                    for item in manifest["items"]:
                        if item["side"] == business["side"]:
                            archive.writestr(
                                item["lib_entry"],
                                Path(item["retained_path"]).read_bytes(),
                            )
                outer_sha = hashlib.sha256(outer.read_bytes()).hexdigest()
                business["outer_artifact_sha256"] = outer_sha
                side = business["side"]
                for item in manifest["items"]:
                    if item["side"] == side:
                        item["outer_artifact_sha256"] = outer_sha
                for row in provenance["sides"]:
                    if row["side"] == side:
                        row["artifact_sha256"] = outer_sha
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            config = materialize_binary_pipeline_config(report)

        for side in ("base", "current"):
            profile = config[side]["runtime_profile"]
            self.assertEqual(
                profile["business_entrypoint_profile"]["main_class"],
                "example.Application",
            )
            self.assertEqual(
                profile["business_entrypoint_profile"]["coverage_status"],
                "complete",
            )
            self.assertEqual(
                profile["business_entrypoint_profile"]["coverage_gaps"], []
            )
            self.assertEqual(profile["entrypoint_discovery_coverage_gaps"], [])


if __name__ == "__main__":
    unittest.main()
