import copy
import hashlib
import json
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_runtime_materializer as materializer  # noqa: E402
from binary_artifact_diff import BinaryArtifactDiffError  # noqa: E402
from binary_runtime_materializer import (  # noqa: E402
    BinaryRuntimeMaterializationError,
    _archive_security_markers,
    _container_entry_digests,
    _coord_with_version,
    _declared_multi_release_jvm_properties,
    _dependency_runtime_configuration_gaps,
    _existing_sha,
    _jdk_feature,
    _load_object,
    _manifest_attributes,
    _nonnegative_evidence_count,
    _outer_business_content_inventory,
    _packaged_main_class,
    _packaged_runtime_configuration,
    _properties,
    _runtime_classpath_index,
    _side_config,
    _validate_evidence_structure,
    _verify_business_content_binding,
    _zip_content_inventory,
)


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)


def _valid_evidence() -> tuple[dict, dict]:
    items = [
        {
            "side": side,
            "lib_entry": f"lib/{side}.jar",
            "purposes": ["binary_runtime", "source_analysis"],
        }
        for side in ("base", "current")
    ]
    manifest = {
        "items": items,
        "business_artifacts": [
            {"side": "base"},
            {"side": "current"},
        ],
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
    }
    provenance = {"sides": [{"side": "base"}, {"side": "current"}]}
    return manifest, provenance


def _materialization_fixture(root: Path, *, with_dependencies: bool = True) -> Path:
    report = root / ".upgrade-report"
    evidence = report / "evidence" / "dependencies"
    evidence.mkdir(parents=True)
    items = []
    business = []
    sides = []
    for side, version in (("base", "1"), ("current", "2")):
        payload = f"business-{side}".encode()
        business_path = root / f"{side}-business.jar"
        _write_zip(business_path, [("fixture/payload.bin", payload)])
        business_digest = hashlib.sha256(business_path.read_bytes()).hexdigest()
        dependency_path = root / f"{side}-dependency.jar"
        _write_zip(dependency_path, [("fixture/Dependency.class", side.encode())])
        dependency_digest = hashlib.sha256(dependency_path.read_bytes()).hexdigest()
        lib_entry = f"BOOT-INF/lib/library-{version}.jar"
        outer_path = root / f"{side}-outer.jar"
        outer_entries = [("BOOT-INF/classes/fixture/payload.bin", payload)]
        if with_dependencies:
            outer_entries.append((lib_entry, dependency_path.read_bytes()))
        _write_zip(outer_path, outer_entries)
        outer_digest = hashlib.sha256(outer_path.read_bytes()).hexdigest()
        business.append(
            {
                "side": side,
                "retained_path": str(business_path),
                "sha256": business_digest,
                "outer_artifact_path": str(outer_path),
                "outer_artifact_sha256": outer_digest,
                "container_and_launcher_kind": "spring-boot-executable-jar",
            }
        )
        if with_dependencies:
            items.append(
                {
                    "side": side,
                    "coord": "com.acme:library",
                    "version": version,
                    "lib_entry": lib_entry,
                    "retained_path": str(dependency_path),
                    "nested_jar_sha256": dependency_digest,
                    "outer_artifact_sha256": outer_digest,
                    "runtime_classpath_index": 0,
                    "purposes": ["binary_runtime"],
                }
            )
        jdk = root / f"{side}-jdk"
        jdk.mkdir()
        (jdk / "release").write_text(
            'JAVA_VERSION="21.0.2"\n', encoding="utf-8"
        )
        sides.append(
            {
                "side": side,
                "target_module": "app",
                "jdk_home": str(jdk),
                "artifact_path": str(outer_path),
                "artifact_sha256": outer_digest,
            }
        )
    manifest = {
        "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
        "items": items,
        "business_artifacts": business,
        "runtime_closure": {
            side: {
                "coverage_status": "complete",
                "coverage_gaps": [],
                "expected_dependency_count": 1 if with_dependencies else 0,
                "retained_dependency_count": 1 if with_dependencies else 0,
                "business_artifact_count": 1,
            }
            for side in ("base", "current")
        },
    }
    provenance = {
        "schema": "java-upgrade-analyzer.build-provenance.v2",
        "sides": sides,
    }
    (evidence / "dependency_jars.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (evidence / "build_provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    return report


def _read_evidence(report: Path) -> tuple[Path, Path, dict, dict]:
    evidence = report / "evidence" / "dependencies"
    manifest_path = evidence / "dependency_jars.json"
    provenance_path = evidence / "build_provenance.json"
    return (
        manifest_path,
        provenance_path,
        json.loads(manifest_path.read_text(encoding="utf-8")),
        json.loads(provenance_path.read_text(encoding="utf-8")),
    )


def _write_evidence(
    manifest_path: Path,
    provenance_path: Path,
    manifest: dict,
    provenance: dict,
) -> None:
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")


class BinaryRuntimeMaterializerBoundaryTest(unittest.TestCase):
    def assert_reason(self, reason: str, function, *args, **kwargs):
        with self.assertRaises(BinaryRuntimeMaterializationError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.reason_code, reason)
        return raised.exception

    def test_declared_multi_release_properties_cover_every_supported_shape(self):
        provenance = {
            "runtime_system_properties": {
                "jdk.util.jar.enableMultiRelease": " false ",
                "ignored": "one",
            },
            "jvm_system_properties": "not-a-map",
            "runtime_jvm_arguments": (
                "-Xmx128m",
                "-Djdk.util.jar.version=8",
                "-Dignored=two",
            ),
            "jvm_arguments": 17,
        }
        overrides = {
            "runtime_system_properties": {
                "jdk.util.jar.enableMultiRelease": "force",
            },
            "jvm_system_properties": {
                "jdk.util.jar.version": " 11 ",
            },
            "runtime_jvm_arguments": "-Dignored=three",
            "jvm_arguments": ["-Djdk.util.jar.version"],
            "base_runtime_system_properties": {
                "jdk.util.jar.enableMultiRelease": "true",
                "ignored": "four",
            },
            "base_jvm_system_properties": [],
            "base_runtime_jvm_arguments": "-Xms64m -Dignored=five",
            "base_jvm_arguments": [
                "-Djdk.util.jar.version=21",
                "-Djdk.util.jar.enableMultiRelease",
            ],
        }

        self.assertEqual(
            _declared_multi_release_jvm_properties(
                "base", provenance, overrides
            ),
            {
                "jdk.util.jar.enableMultiRelease": "",
                "jdk.util.jar.version": "21",
            },
        )
        self.assertEqual(
            _declared_multi_release_jvm_properties("current", {}, {}), {}
        )
        self.assert_reason(
            "BINARY_RUNTIME_JVM_ARGUMENTS_INVALID",
            _declared_multi_release_jvm_properties,
            "base",
            {},
            {"jvm_arguments": "'unterminated"},
        )

    def test_json_object_loading_distinguishes_io_syntax_and_root_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.json"
            self.assert_reason(
                "BINARY_RUNTIME_EVIDENCE_INVALID", _load_object, missing
            )
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            self.assert_reason(
                "BINARY_RUNTIME_EVIDENCE_INVALID", _load_object, malformed
            )
            collection = root / "collection.json"
            collection.write_text("[]", encoding="utf-8")
            self.assert_reason(
                "BINARY_RUNTIME_EVIDENCE_INVALID", _load_object, collection
            )
            valid = root / "valid.json"
            valid.write_text('{"answer": 42}', encoding="utf-8")
            self.assertEqual(_load_object(valid), {"answer": 42})

    def test_existing_sha_requires_lowercase_identity_existing_file_and_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()

            for invalid in (None, "", digest.upper(), "0" * 63, "g" * 64):
                with self.subTest(invalid=invalid):
                    self.assert_reason(
                        "BINARY_RUNTIME_ARTIFACT_IDENTITY_INVALID",
                        _existing_sha,
                        artifact,
                        invalid,
                        label="fixture",
                    )
            self.assert_reason(
                "BINARY_RUNTIME_ARTIFACT_MISSING",
                _existing_sha,
                root / "missing.bin",
                digest,
                label="fixture",
            )
            self.assert_reason(
                "BINARY_RUNTIME_ARTIFACT_MISSING",
                _existing_sha,
                None,
                digest,
                label="empty-path",
            )
            self.assert_reason(
                "BINARY_RUNTIME_ARTIFACT_DIGEST_MISMATCH",
                _existing_sha,
                artifact,
                "0" * 64,
                label="fixture",
            )
            self.assertEqual(
                _existing_sha(artifact, digest, label="fixture"),
                (artifact.resolve(), digest),
            )

    def test_container_entry_digests_reject_empty_missing_duplicate_and_bad_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "outer.jar"
            _write_zip(
                archive,
                [("directory/", b""), ("a.jar", b"a"), ("b.jar", b"b")],
            )
            expected = hashlib.sha256(b"a").hexdigest()
            self.assertEqual(
                _container_entry_digests(archive, ["a.jar", "a.jar"]),
                {"a.jar": expected},
            )
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_ENTRY_MISSING",
                _container_entry_digests,
                archive,
                [""],
            )
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_ENTRY_MISSING",
                _container_entry_digests,
                archive,
                ["missing.jar"],
            )
            duplicate = root / "duplicate.jar"
            _write_zip(duplicate, [("a.jar", b"one"), ("a.jar", b"two")])
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_ENTRY_DUPLICATE",
                _container_entry_digests,
                duplicate,
                ["a.jar"],
            )
            bad = root / "bad.jar"
            bad.write_bytes(b"not a zip")
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_UNREADABLE",
                _container_entry_digests,
                bad,
                ["a.jar"],
            )

    def test_zip_and_outer_business_inventories_cover_supported_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = root / "plain.jar"
            _write_zip(
                plain,
                [
                    ("dir/", b""),
                    ("pkg/App.class", b"app"),
                    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                    ("META-INF/maven/g/a/pom.xml", b"metadata"),
                    ("META-INF/APP.SF", b"signature"),
                    ("lib/ignored.jar", b"nested"),
                    ("BOOT-INF/ignored.bin", b"launcher"),
                    ("WEB-INF/ignored.bin", b"container"),
                ],
            )
            all_entries = _zip_content_inventory(plain)
            self.assertIn("pkg/App.class", all_entries)
            self.assertIn("META-INF/maven/g/a/pom.xml", all_entries)
            plain_business = _outer_business_content_inventory(plain)
            self.assertEqual(
                set(plain_business),
                {
                    "pkg/App.class",
                    "META-INF/MANIFEST.MF",
                    "META-INF/APP.SF",
                },
            )

            boot = root / "boot.jar"
            _write_zip(
                boot,
                [
                    ("BOOT-INF/classes/", b"not-a-directory-record"),
                    ("BOOT-INF/classes/pkg/App.class", b"boot"),
                    ("WEB-INF/classes/pkg/Web.class", b"web"),
                    ("META-INF/MANIFEST.MF", b"manifest"),
                    ("BOOT-INF/lib/dep.jar", b"dependency"),
                ],
            )
            self.assertEqual(
                set(_outer_business_content_inventory(boot)),
                {"pkg/App.class", "pkg/Web.class", "META-INF/MANIFEST.MF"},
            )

            duplicate = root / "logical-duplicate.jar"
            _write_zip(
                duplicate,
                [
                    ("BOOT-INF/classes/pkg/App.class", b"boot"),
                    ("WEB-INF/classes/pkg/App.class", b"web"),
                ],
            )
            self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_ENTRY_DUPLICATE",
                _outer_business_content_inventory,
                duplicate,
            )

            raw_duplicate = root / "raw-duplicate.jar"
            _write_zip(
                raw_duplicate,
                [("pkg/App.class", b"one"), ("pkg/App.class", b"two")],
            )
            self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_ENTRY_DUPLICATE",
                _zip_content_inventory,
                raw_duplicate,
            )
            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_ARTIFACT_UNREADABLE",
                _zip_content_inventory,
                bad,
            )
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_UNREADABLE",
                _outer_business_content_inventory,
                bad,
            )

    def test_business_binding_accepts_exact_and_non_mr_manifest_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            retained = root / "retained.jar"
            outer = root / "outer.jar"
            _write_zip(retained, [("pkg/App.class", b"same")])
            _write_zip(
                outer,
                [
                    ("pkg/App.class", b"same"),
                    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                ],
            )
            _verify_business_content_binding(retained, retained, side="base")
            _verify_business_content_binding(retained, outer, side="base")

            mr_outer = root / "mr.jar"
            _write_zip(
                mr_outer,
                [
                    ("pkg/App.class", b"same"),
                    (
                        "META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\nMulti-Release: true\n",
                    ),
                ],
            )
            mismatch = self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_CONTENT_MISMATCH",
                _verify_business_content_binding,
                retained,
                mr_outer,
                side="base",
            )
            self.assertIn("unexpected=['META-INF/MANIFEST.MF']", mismatch.detail)

            changed = root / "changed.jar"
            _write_zip(
                changed,
                [("pkg/App.class", b"changed"), ("extra.txt", b"extra")],
            )
            mismatch = self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_CONTENT_MISMATCH",
                _verify_business_content_binding,
                retained,
                changed,
                side="current",
            )
            self.assertIn("changed=['pkg/App.class']", mismatch.detail)
            self.assertIn("unexpected=['extra.txt']", mismatch.detail)

    def test_coordinate_index_and_count_validation_partition_types_and_values(self):
        self.assertEqual(
            _coord_with_version({"coord": " g:a ", "version": " 1 "}),
            ("g:a:1", "g:a"),
        )
        self.assertEqual(
            _coord_with_version({"coord": "g:a:classifier", "version": "2"}),
            ("g:a:classifier:2", "g:a:classifier"),
        )
        for item in (
            {"version": "1", "lib_entry": "missing-coordinate"},
            {"coord": "g:a", "lib_entry": "missing-version"},
            {"version": "1"},
        ):
            with self.subTest(item=item):
                self.assert_reason(
                    "BINARY_RUNTIME_COORDINATE_MISSING", _coord_with_version, item
                )
        for coord in ("g", "g:a:c:too-many"):
            self.assert_reason(
                "BINARY_RUNTIME_COORDINATE_INVALID",
                _coord_with_version,
                {"coord": coord, "version": "1"},
            )

        self.assertEqual(_runtime_classpath_index({"runtime_classpath_index": 0}), 0)
        for value in (True, None, "0", -1):
            with self.subTest(index=value):
                self.assert_reason(
                    "BINARY_RUNTIME_CLASSPATH_INDEX_INVALID",
                    _runtime_classpath_index,
                    {"runtime_classpath_index": value},
                )
        self.assertEqual(_nonnegative_evidence_count(0, label="count"), 0)
        for value in (False, None, "0", -1):
            with self.subTest(count=value):
                self.assert_reason(
                    "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                    _nonnegative_evidence_count,
                    value,
                    label="count",
                )

    def test_evidence_root_collection_contract_rejects_each_invalid_shape(self):
        manifest, provenance = _valid_evidence()
        _validate_evidence_structure(manifest, provenance)
        invalid = []
        for field, values in {
            "items": (None, {}, [None]),
            "business_artifacts": (None, {}, [None]),
            "runtime_closure": (None, [], {"base": {}}),
        }.items():
            for value in values:
                changed = copy.deepcopy(manifest)
                changed[field] = value
                invalid.append((changed, provenance))
        for value in (None, {}, [None]):
            changed = copy.deepcopy(provenance)
            changed["sides"] = value
            invalid.append((manifest, changed))
        for changed_manifest, changed_provenance in invalid:
            with self.subTest(
                manifest=changed_manifest, provenance=changed_provenance
            ):
                self.assert_reason(
                    "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                    _validate_evidence_structure,
                    changed_manifest,
                    changed_provenance,
                )

    def test_evidence_item_side_and_purpose_contract_is_exhaustive(self):
        manifest, provenance = _valid_evidence()
        containers = (
            (manifest["items"], "side"),
            (manifest["business_artifacts"], "side"),
            (provenance["sides"], "side"),
        )
        for container, field in containers:
            original = container[0][field]
            container[0][field] = "future"
            self.assert_reason(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                _validate_evidence_structure,
                manifest,
                provenance,
            )
            container[0][field] = original

        for purposes in (
            None,
            {},
            [1],
            [""],
            ["binary_runtime", "binary_runtime"],
        ):
            changed = copy.deepcopy(manifest)
            changed["items"][0]["purposes"] = purposes
            with self.subTest(purposes=purposes):
                self.assert_reason(
                    "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                    _validate_evidence_structure,
                    changed,
                    provenance,
                )

        changed = copy.deepcopy(manifest)
        del changed["items"][0]["side"]
        self.assert_reason(
            "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
            _validate_evidence_structure,
            changed,
            provenance,
        )

    def test_evidence_closure_status_gap_and_count_contract_is_exhaustive(self):
        manifest, provenance = _valid_evidence()
        for closure in (None, [], "invalid"):
            changed = copy.deepcopy(manifest)
            changed["runtime_closure"]["base"] = closure
            self.assert_reason(
                "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                _validate_evidence_structure,
                changed,
                provenance,
            )

        mutations = (
            ("coverage_status", "future"),
            ("coverage_gaps", None),
            ("coverage_gaps", [1]),
            ("coverage_gaps", [""]),
            ("coverage_gaps", ["gap"]),
        )
        for field, value in mutations:
            changed = copy.deepcopy(manifest)
            changed["runtime_closure"]["base"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_reason(
                    "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                    _validate_evidence_structure,
                    changed,
                    provenance,
                )

        valid_partial = copy.deepcopy(manifest)
        valid_partial["runtime_closure"]["base"].update(
            coverage_status="partial",
            coverage_gaps=["dependency_missing"],
            expected_dependency_count=2,
        )
        _validate_evidence_structure(valid_partial, provenance)

        invalid_count_changes = (
            ("expected_dependency_count", True),
            ("retained_dependency_count", -1),
            ("business_artifact_count", "1"),
            ("retained_dependency_count", 0),
            ("business_artifact_count", 0),
            ("expected_dependency_count", 0),
            ("expected_dependency_count", 2),
        )
        for field, value in invalid_count_changes:
            changed = copy.deepcopy(manifest)
            changed["runtime_closure"]["base"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_reason(
                    "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
                    _validate_evidence_structure,
                    changed,
                    provenance,
                )

        partial_without_gap = copy.deepcopy(manifest)
        partial_without_gap["runtime_closure"]["base"].update(
            coverage_status="partial", coverage_gaps=[]
        )
        self.assert_reason(
            "BINARY_RUNTIME_EVIDENCE_STRUCTURE_INVALID",
            _validate_evidence_structure,
            partial_without_gap,
            provenance,
        )

    def test_properties_parser_covers_java_separator_comment_and_eof_rules(self):
        parsed = _properties(
            b"\n  # comment\n\t! comment\n"
            b"bare-key\n"
            b"space-separated value\n"
            b"space-then-colon   :   value2\n"
            b"colon:value3\n"
            b"escaped\\=key=value4\n"
            b"even-slashes=value\\\\\n"
            b"continued=value\\\n  tail\n"
            b"eof-continuation=value\\"
        )
        self.assertEqual(parsed["bare-key"], "")
        self.assertEqual(parsed["space-separated"], "value")
        self.assertEqual(parsed["space-then-colon"], "value2")
        self.assertEqual(parsed["colon"], "value3")
        self.assertEqual(parsed["escaped=key"], "value4")
        self.assertEqual(parsed["even-slashes"], "value\\")
        self.assertEqual(parsed["continued"], "valuetail")
        self.assertEqual(parsed["eof-continuation"], "value")
        self.assertEqual(_properties(b"key   \n"), {"key": ""})
        self.assertEqual(_properties(b"key   =   \n"), {"key": ""})
        self.assertEqual(_properties(b"key:\n"), {"key": ""})
        self.assertEqual(_properties(b"\\"), {})
        with self.assertRaises(ValueError):
            _properties(b"short=\\u12")

    def test_manifest_parser_stops_at_main_section_and_folds_values(self):
        attributes = _manifest_attributes(
            b"Manifest-Version: 1.0\r\n"
            b"Main-Class: com.example.\r\n"
            b" App\r\n"
            b"Malformed\r\n"
            b": empty-key\r\n"
            b"\r\n"
            b"Name: pkg/App.class\r\n"
        )
        self.assertEqual(attributes["manifest-version"], "1.0")
        self.assertEqual(attributes["main-class"], "com.example.App")
        self.assertNotIn("name", attributes)
        self.assertEqual(
            _manifest_attributes(b" orphan-continuation\nKey: value\n"),
            {"key": "value"},
        )
        self.assertEqual(
            _manifest_attributes(b"Key: value"), {"key": "value"}
        )

    def test_archive_security_markers_cover_signatures_sealing_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clean = root / "clean.jar"
            _write_zip(clean, [("dir/", b""), ("pkg/App.class", b"app")])
            self.assertEqual(_archive_security_markers(clean), ())

            orphan_signature_file = root / "orphan-signature-file.jar"
            _write_zip(
                orphan_signature_file,
                [
                    ("META-INF/BOOT.SF", b"Signature-Version: 1.0\n"),
                    (
                        "META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\nSHA-256-Digest: stale\n",
                    ),
                    ("pkg/App.class", b"app"),
                ],
            )
            self.assertEqual(
                _archive_security_markers(orphan_signature_file), ()
            )

            marked = root / "marked.jar"
            _write_zip(
                marked,
                [
                    ("META-INF/APP.SF", b"Signature-Version: 1.0\n"),
                    ("META-INF/APP.RSA", b"signature"),
                    (
                        "META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\n"
                        b"Sealed: true\n"
                        b"Other-Sealed: false\n"
                        b"SHA-256-Digest: abc\n"
                        b"Folded: first\n second\n"
                        b"No-Separator\n",
                    ),
                ],
            )
            self.assertEqual(
                set(_archive_security_markers(marked)),
                {
                    "signature_entry:META-INF/APP.SF",
                    "signature_entry:META-INF/APP.RSA",
                    "sealed_manifest_section",
                    "signed_manifest_digest",
                },
            )

            leading_fold = root / "leading-fold.jar"
            _write_zip(
                leading_fold,
                [("META-INF/MANIFEST.MF", b" orphan\nSealed: false\n")],
            )
            self.assertEqual(_archive_security_markers(leading_fold), ())

            ambiguous = root / "ambiguous.jar"
            _write_zip(
                ambiguous,
                [
                    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                    ("meta-inf/manifest.mf", b"Manifest-Version: 1.0\n"),
                ],
            )
            self.assertEqual(
                _archive_security_markers(ambiguous), ("manifest_ambiguous",)
            )
            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            self.assert_reason(
                "BINARY_RUNTIME_SECURITY_EVIDENCE_UNREADABLE",
                _archive_security_markers,
                bad,
            )

    def test_packaged_main_class_partitions_manifest_and_class_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            business = root / "business.jar"
            _write_zip(
                business,
                [("dir/", b""), ("com/example/App.class", b"class")],
            )
            outer = root / "outer.jar"
            _write_zip(
                outer,
                [
                    (
                        "META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\n"
                        b"Start-Class: missing.Start\n"
                        b"Main-Class: com/example/App\n",
                    )
                ],
            )
            self.assertEqual(
                _packaged_main_class(outer, business), ("com.example.App", [])
            )
            missing_class = root / "missing-class.jar"
            _write_zip(
                missing_class,
                [("META-INF/MANIFEST.MF", b"Main-Class: missing.App\n")],
            )
            self.assertEqual(
                _packaged_main_class(missing_class, business),
                ("", ["packaged_main_class_not_in_business_artifact"]),
            )
            undeclared = root / "undeclared.jar"
            _write_zip(
                undeclared,
                [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")],
            )
            self.assertEqual(
                _packaged_main_class(undeclared, business),
                ("", ["packaged_main_class_not_declared"]),
            )
            no_manifest = root / "no-manifest.jar"
            _write_zip(no_manifest, [("payload", b"x")])
            self.assertEqual(
                _packaged_main_class(no_manifest, business),
                ("", ["packaged_main_class_manifest_missing"]),
            )
            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            self.assertEqual(
                _packaged_main_class(bad, business),
                ("", ["packaged_main_class_unreadable:BadZipFile"]),
            )

    def test_jdk_feature_parses_legacy_modern_missing_and_malformed_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modern = root / "modern"
            modern.mkdir()
            (modern / "release").write_text(
                'IMPLEMENTOR="fixture"\nJAVA_VERSION="21.0.2"\nmalformed\n',
                encoding="utf-8",
            )
            self.assertEqual(_jdk_feature(modern), 21)
            legacy = root / "legacy"
            legacy.mkdir()
            (legacy / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )
            self.assertEqual(_jdk_feature(legacy), 8)
            malformed = root / "malformed"
            malformed.mkdir()
            (malformed / "release").write_text(
                'JAVA_VERSION="future"\n', encoding="utf-8"
            )
            self.assertIsNone(_jdk_feature(malformed))
            self.assertIsNone(_jdk_feature(root / "missing"))

            with mock.patch.object(
                materializer,
                "resolve_jdk_release",
                return_value={"values": {"JAVA_VERSION": "1.8.0_504"}},
            ):
                self.assertEqual(_jdk_feature(root / "release-less"), 8)
            for failure in (
                materializer.JdkPreflightError("PROBE_FAILED", "failed"),
                OSError("unreadable"),
                UnicodeError("invalid output"),
            ):
                with self.subTest(failure=type(failure).__name__), mock.patch.object(
                    materializer, "resolve_jdk_release", side_effect=failure
                ):
                    self.assertIsNone(_jdk_feature(root / "release-less"))

    def test_packaged_configuration_covers_precedence_yaml_profiles_and_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "config.jar"
            _write_zip(
                artifact,
                [
                    (
                        "application.properties",
                        b"spring.profiles.active=dev, ,prod\nbase=one\n",
                    ),
                    ("config/application.properties", b"base=two\n"),
                    ("application.yml", b"base: yaml\n"),
                    ("application-dev.properties", b"dev=one\n"),
                    ("config/application-dev.properties", b"dev=two\n"),
                    ("application-prod.properties", b"prod=ok\n"),
                ],
            )
            properties, gaps = _packaged_runtime_configuration(
                artifact, target_jvm_major=21
            )
            self.assertEqual(properties, {})
            self.assertIn("packaged_default_properties_precedence_ambiguous", gaps)
            self.assertIn("packaged_yaml_condition_inputs_not_materialized", gaps)

            profile = root / "profile.jar"
            _write_zip(
                profile,
                [
                    (
                        "application.properties",
                        b"spring.profiles.active=dev,prod\nbase=ok\n",
                    ),
                    ("application-dev.properties", b"dev=ok\n"),
                    ("config/application-prod.properties", b"prod=ok\n"),
                ],
            )
            properties, gaps = _packaged_runtime_configuration(
                profile, target_jvm_major=21
            )
            self.assertEqual(properties["dev"], "ok")
            self.assertEqual(properties["prod"], "ok")
            self.assertEqual(gaps, [])

            ambiguous_profile = root / "ambiguous-profile.jar"
            _write_zip(
                ambiguous_profile,
                [
                    ("application.properties", b"spring.profiles.active=dev\n"),
                    ("application-dev.properties", b"dev=one\n"),
                    ("config/application-dev.properties", b"dev=two\n"),
                ],
            )
            properties, gaps = _packaged_runtime_configuration(
                ambiguous_profile, target_jvm_major=21
            )
            self.assertEqual(properties["spring.profiles.active"], "dev")
            self.assertEqual(
                gaps,
                ["packaged_profile_properties_precedence_ambiguous:dev"],
            )

            malformed = root / "malformed.jar"
            _write_zip(malformed, [("application.properties", b"bad=\\uXX00")])
            properties, gaps = _packaged_runtime_configuration(
                malformed, target_jvm_major=21
            )
            self.assertEqual(properties, {})
            self.assertEqual(gaps, ["packaged_properties_parse_failed:ValueError"])

            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            properties, gaps = _packaged_runtime_configuration(
                bad, target_jvm_major=21
            )
            self.assertEqual(properties, {})
            self.assertEqual(gaps, ["packaged_configuration_unreadable:BadZipFile"])

            with mock.patch(
                "binary_runtime_materializer.select_runtime_resource_entries",
                side_effect=BinaryArtifactDiffError("FIXTURE_REASON", "detail"),
            ):
                properties, gaps = _packaged_runtime_configuration(
                    profile, target_jvm_major=21
                )
            self.assertEqual(properties, {})
            self.assertEqual(
                gaps,
                ["packaged_multi_release_selection_failed:FIXTURE_REASON"],
            )

    def test_dependency_configuration_reports_named_unknown_and_unreadable_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "dependency.jar"
            _write_zip(
                artifact,
                [
                    ("application.properties", b"base=one"),
                    ("CONFIG/APPLICATION-DEV.YAML", b"dev: one"),
                    ("not-application.properties", b"ignored"),
                ],
            )
            gaps = _dependency_runtime_configuration_gaps(
                artifact, target_jvm_major=21, artifact_label="g:a:1"
            )
            self.assertEqual(
                gaps,
                [
                    "dependency_packaged_configuration_not_materialized:"
                    "g:a:1:CONFIG/APPLICATION-DEV.YAML",
                    "dependency_packaged_configuration_not_materialized:"
                    "g:a:1:application.properties",
                ],
            )

            mr = root / "mr-dependency.jar"
            _write_zip(
                mr,
                [
                    (
                        "META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\nMulti-Release: true\n",
                    ),
                    (
                        "META-INF/versions/9/application.properties",
                        b"versioned=true\n",
                    ),
                ],
            )
            self.assertIn(
                "dependency_multi_release_target_jvm_unknown:g:a:mr",
                _dependency_runtime_configuration_gaps(
                    mr, target_jvm_major=None, artifact_label="g:a:mr"
                ),
            )
            bad = root / "bad.jar"
            bad.write_bytes(b"bad")
            self.assertEqual(
                _dependency_runtime_configuration_gaps(
                    bad, target_jvm_major=21, artifact_label="bad"
                ),
                ["dependency_packaged_configuration_unreadable:bad"],
            )
            with mock.patch(
                "binary_runtime_materializer.select_runtime_resource_entries",
                side_effect=BinaryArtifactDiffError("FIXTURE_REASON", "detail"),
            ):
                gaps = _dependency_runtime_configuration_gaps(
                    artifact, target_jvm_major=None, artifact_label="g:a:1"
                )
            self.assertEqual(
                gaps,
                [
                    "dependency_multi_release_selection_failed:"
                    "g:a:1:FIXTURE_REASON"
                ],
            )

    def test_side_configuration_cardinality_identity_jdk_and_default_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _materialization_fixture(root)
            manifest_path, provenance_path, manifest, provenance = _read_evidence(
                report
            )

            duplicate_business = copy.deepcopy(manifest)
            duplicate_business["business_artifacts"].append(
                copy.deepcopy(duplicate_business["business_artifacts"][0])
            )
            self.assert_reason(
                "BINARY_RUNTIME_BUSINESS_ARTIFACT_CARDINALITY",
                _side_config,
                "base",
                duplicate_business,
                provenance,
                {},
            )

            duplicate_provenance = copy.deepcopy(provenance)
            duplicate_provenance["sides"].append(
                copy.deepcopy(duplicate_provenance["sides"][0])
            )
            self.assert_reason(
                "BINARY_RUNTIME_PROVENANCE_CARDINALITY",
                _side_config,
                "base",
                manifest,
                duplicate_provenance,
                {},
            )

            missing_jdk = copy.deepcopy(provenance)
            missing_jdk["sides"][0]["jdk_home"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_JDK_HOME_MISSING",
                _side_config,
                "base",
                manifest,
                missing_jdk,
                {},
            )

            alternate = root / "alternate-outer.jar"
            original_outer = Path(
                manifest["business_artifacts"][0]["outer_artifact_path"]
            )
            alternate.write_bytes(original_outer.read_bytes())
            alternate_provenance = copy.deepcopy(provenance)
            alternate_provenance["sides"][0]["artifact_path"] = str(alternate)
            config = _side_config(
                "base", manifest, alternate_provenance, {}
            )
            self.assertEqual(config["artifacts"][0]["slot"], 0)

            whitespace_module = copy.deepcopy(provenance)
            whitespace_module["sides"][0]["target_module"] = "   "
            config = _side_config("base", manifest, whitespace_module, {})
            self.assertEqual(
                config["artifacts"][0]["coord"], "application:application:base"
            )
            missing_module = copy.deepcopy(provenance)
            del missing_module["sides"][0]["target_module"]
            config = _side_config("base", manifest, missing_module, {})
            self.assertEqual(
                config["artifacts"][0]["coord"], "application:application:base"
            )

            missing_digest = copy.deepcopy(provenance)
            missing_digest["sides"][0]["artifact_sha256"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_PROVENANCE_ARTIFACT_IDENTITY_MISMATCH",
                _side_config,
                "base",
                manifest,
                missing_digest,
                {},
            )
            missing_path = copy.deepcopy(provenance)
            missing_path["sides"][0]["artifact_path"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_ARTIFACT_MISSING",
                _side_config,
                "base",
                manifest,
                missing_path,
                {},
            )

            override_jdk = root / "override-jdk"
            override_jdk.mkdir()
            (override_jdk / "release").write_text(
                'JAVA_VERSION="17.0.12"\n', encoding="utf-8"
            )
            config = _side_config(
                "base",
                manifest,
                provenance,
                {"base_jdk_home": str(override_jdk)},
            )
            self.assertEqual(
                config["runtime_profile"]["loader_topology"]
                ["multi_release_jar_runtime_policy"]["target_runtime_feature"],
                17,
            )

            _write_evidence(
                manifest_path, provenance_path, manifest, provenance
            )

    def test_side_configuration_covers_empty_dependency_and_container_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _materialization_fixture(root, with_dependencies=False)
            _, _, manifest, provenance = _read_evidence(report)
            kinds = (
                ("spring-boot-executable-jar", "BOOT-INF/classes/"),
                ("servlet-war", "WEB-INF/classes/"),
                ("plain-jar", "<artifact>"),
            )
            for kind, expected in kinds:
                changed = copy.deepcopy(manifest)
                changed["business_artifacts"][0][
                    "container_and_launcher_kind"
                ] = kind
                with self.subTest(kind=kind):
                    config = _side_config(
                        "base", changed, provenance, {}
                    )
                    self.assertEqual(
                        config["artifacts"][0]["container_entry"], expected
                    )
                    self.assertEqual(len(config["artifacts"]), 1)
            missing_kind = copy.deepcopy(manifest)
            del missing_kind["business_artifacts"][0][
                "container_and_launcher_kind"
            ]
            config = _side_config("base", missing_kind, provenance, {})
            self.assertEqual(
                config["runtime_profile"]["container_and_launcher_kind"],
                "java-classpath",
            )
            self.assertEqual(config["artifacts"][0]["container_entry"], "<artifact>")

    def test_side_configuration_rejects_duplicate_entries_and_ambiguous_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _materialization_fixture(root)
            _, _, manifest, provenance = _read_evidence(report)

            duplicate_entry = copy.deepcopy(manifest)
            second = copy.deepcopy(duplicate_entry["items"][0])
            second["runtime_classpath_index"] = 1
            duplicate_entry["items"].append(second)
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_ENTRY_DECLARATION_DUPLICATE",
                _side_config,
                "base",
                duplicate_entry,
                provenance,
                {},
            )

            dependency_row = next(
                item for item in manifest["items"] if item["side"] == "base"
            )
            dependency = Path(dependency_row["retained_path"])
            _write_zip(
                dependency,
                [
                    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                    ("meta-inf/manifest.mf", b"Manifest-Version: 1.0\n"),
                ],
            )
            dependency_row["nested_jar_sha256"] = hashlib.sha256(
                dependency.read_bytes()
            ).hexdigest()
            outer = Path(
                next(
                    item
                    for item in manifest["business_artifacts"]
                    if item["side"] == "base"
                )["outer_artifact_path"]
            )
            _write_zip(
                outer,
                [
                    (
                        "BOOT-INF/classes/fixture/payload.bin",
                        b"business-base",
                    ),
                    (dependency_row["lib_entry"], dependency.read_bytes()),
                ],
            )
            outer_digest = hashlib.sha256(outer.read_bytes()).hexdigest()
            next(
                item
                for item in manifest["business_artifacts"]
                if item["side"] == "base"
            )["outer_artifact_sha256"] = outer_digest
            dependency_row["outer_artifact_sha256"] = outer_digest
            next(
                item for item in provenance["sides"] if item["side"] == "base"
            )["artifact_sha256"] = outer_digest
            self.assert_reason(
                "BINARY_RUNTIME_MANIFEST_AMBIGUOUS",
                _side_config,
                "base",
                manifest,
                provenance,
                {},
            )

            clean_report = _materialization_fixture(
                root / "outer-ambiguous", with_dependencies=False
            )
            _, _, clean_manifest, clean_provenance = _read_evidence(clean_report)
            business_row = clean_manifest["business_artifacts"][0]
            business_path = Path(business_row["retained_path"])
            outer_path = Path(business_row["outer_artifact_path"])
            manifests = [
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                ("meta-inf/manifest.mf", b"Manifest-Version: 1.0\n"),
            ]
            _write_zip(
                business_path,
                [("fixture/payload.bin", b"business-base"), *manifests],
            )
            _write_zip(
                outer_path,
                [
                    (
                        "BOOT-INF/classes/fixture/payload.bin",
                        b"business-base",
                    ),
                    *manifests,
                ],
            )
            business_row["sha256"] = hashlib.sha256(
                business_path.read_bytes()
            ).hexdigest()
            outer_digest = hashlib.sha256(outer_path.read_bytes()).hexdigest()
            business_row["outer_artifact_sha256"] = outer_digest
            clean_provenance["sides"][0]["artifact_sha256"] = outer_digest
            self.assert_reason(
                "BINARY_RUNTIME_MANIFEST_AMBIGUOUS",
                _side_config,
                "base",
                clean_manifest,
                clean_provenance,
                {},
            )

    def test_side_configuration_rejects_dependency_identity_and_required_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = _materialization_fixture(Path(tmp))
            _, _, manifest, provenance = _read_evidence(report)

            wrong_outer = copy.deepcopy(manifest)
            wrong_outer["items"][0]["outer_artifact_sha256"] = "0" * 64
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_IDENTITY_MISMATCH",
                _side_config,
                "base",
                wrong_outer,
                provenance,
                {},
            )
            missing_outer = copy.deepcopy(manifest)
            missing_outer["items"][0]["outer_artifact_sha256"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_IDENTITY_MISMATCH",
                _side_config,
                "base",
                missing_outer,
                provenance,
                {},
            )

            missing_coordinate = copy.deepcopy(manifest)
            missing_coordinate["items"][0]["coord"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_COORDINATE_MISSING",
                _side_config,
                "base",
                missing_coordinate,
                provenance,
                {},
            )

            missing_entry = copy.deepcopy(manifest)
            missing_entry["items"][0]["lib_entry"] = ""
            self.assert_reason(
                "BINARY_RUNTIME_CONTAINER_ENTRY_MISSING",
                _side_config,
                "base",
                missing_entry,
                provenance,
                {},
            )

    def test_side_configuration_runtime_profiles_cover_override_and_build_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _materialization_fixture(root, with_dependencies=False)
            _, _, manifest, provenance = _read_evidence(report)

            checkout = copy.deepcopy(provenance)
            checkout["sides"][0].update(
                input_mode="checkout_build",
                build_executed_by_system=True,
                build_execution_status="cached",
            )
            config = _side_config(
                "base",
                manifest,
                checkout,
                {
                    "base_resolved_configuration_properties": {
                        "spring.profiles.active": "from-property, second",
                        "answer": 42,
                    },
                    "active_profile_identities": ["explicit"],
                    "external_config_snapshot_identities": ["config:one"],
                    "agent_transformer_plugin_profile_identities": ["agent:one"],
                    "step0_preflight": {
                        "sides": {
                            "base": {
                                "jdk": {"jdk_preflight_identity": "jdk:base"}
                            }
                        }
                    },
                },
            )
            profile = config["runtime_profile"]
            self.assertEqual(profile["active_profile_identities"], ["explicit"])
            self.assertEqual(profile["resolved_configuration_properties"]["answer"], "42")
            self.assertEqual(profile["external_config_snapshot_identities"], ["config:one"])
            self.assertEqual(profile["agent_transformer_plugin_profile_identities"], ["agent:one"])
            self.assertEqual(profile["runtime_configuration_coverage_status"], "complete")
            self.assertEqual(config["jdk_preflight_identity"], "jdk:base")
            build = config["build_identity"]["artifact_build_provenance"]
            self.assertTrue(build["build_executed_by_system"])
            self.assertEqual(build["build_execution_status"], "cached")

            derived = _side_config(
                "base",
                manifest,
                provenance,
                {
                    "resolved_configuration_properties": {
                        "spring.profiles.active": "dev, ,prod"
                    }
                },
            )
            self.assertEqual(
                derived["runtime_profile"]["active_profile_identities"],
                ["dev", "prod"],
            )

            external_unknown = _side_config(
                "base",
                manifest,
                provenance,
                {"external_config_snapshot_identities": ["config:unknown"]},
            )
            profile = external_unknown["runtime_profile"]
            self.assertEqual(profile["runtime_configuration_coverage_status"], "partial")
            self.assertEqual(profile["resource_selection_coverage_status"], "partial")
            self.assertIn(
                "external_configuration_snapshot_content_missing",
                profile["runtime_configuration_coverage_gaps"],
            )

            unknown_mode = copy.deepcopy(provenance)
            unknown_mode["sides"][0]["input_mode"] = "future-mode"
            normalized = _side_config(
                "base", manifest, unknown_mode, {}
            )["build_identity"]["artifact_build_provenance"]
            self.assertEqual(normalized["input_mode"], "provided_artifact")
            self.assertFalse(normalized["build_executed_by_system"])
            self.assertEqual(normalized["build_execution_status"], "not_executed")

            checkout_default = copy.deepcopy(provenance)
            checkout_default["sides"][0]["input_mode"] = "checkout_build"
            checkout_default["sides"][0].pop("build_execution_status", None)
            normalized = _side_config(
                "base", manifest, checkout_default, {}
            )["build_identity"]["artifact_build_provenance"]
            self.assertEqual(normalized["build_execution_status"], "succeeded")

    def test_side_configuration_detects_outer_mutation_after_dependency_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _materialization_fixture(root)
            _, _, manifest, provenance = _read_evidence(report)
            outer = Path(manifest["business_artifacts"][0]["outer_artifact_path"])
            actual = hashlib.sha256(outer.read_bytes()).hexdigest()
            real_sha = hashlib.sha256

            call_count = 0

            def changing_sha(path):
                nonlocal call_count
                call_count += 1
                if call_count == 4:
                    return "0" * 64
                digest = real_sha()
                with Path(path).open("rb") as handle:
                    digest.update(handle.read())
                return digest.hexdigest()

            self.assertEqual(actual, manifest["business_artifacts"][0]["outer_artifact_sha256"])
            with mock.patch(
                "binary_runtime_materializer._sha256", side_effect=changing_sha
            ):
                self.assert_reason(
                    "BINARY_RUNTIME_ARTIFACT_CHANGED_DURING_MATERIALIZATION",
                    _side_config,
                    "base",
                    manifest,
                    provenance,
                    {},
                )


if __name__ == "__main__":
    unittest.main()
