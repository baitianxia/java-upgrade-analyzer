import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import constant_impact  # noqa: E402


@unittest.skipUnless(shutil.which("javac"), "javac is required")
class ConstantEvidenceExtractionTest(unittest.TestCase):
    def _compile_fixture(self, root):
        source = root / "src" / "sample"
        classes = root / "classes"
        source.mkdir(parents=True)
        (source / "Flags.java").write_text(
            "package sample; public class Flags {"
            " public static final String TEXT = \"old\";"
            " public static final int COUNT = 7;"
            " public static String DYNAMIC = \"live\";"
            "}",
            encoding="utf-8",
        )
        (source / "Caller.java").write_text(
            "package sample; public class Caller {"
            " public String text() { return Flags.TEXT; }"
            " public int count() { return Flags.COUNT; }"
            " public String dynamic() { return Flags.DYNAMIC; }"
            "}",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "javac", "-d", str(classes),
                str(source / "Flags.java"), str(source / "Caller.java"),
            ],
            check=True,
            capture_output=True,
        )
        provider = root / "provider.jar"
        consumer = root / "consumer.jar"
        with zipfile.ZipFile(provider, "w") as archive:
            archive.write(classes / "sample" / "Flags.class", "sample/Flags.class")
        with zipfile.ZipFile(consumer, "w") as archive:
            archive.write(classes / "sample" / "Caller.class", "sample/Caller.class")
        return provider, consumer

    def test_extracts_sha_bound_constant_value_by_exact_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider, _consumer = self._compile_fixture(Path(tmp))

            text = constant_impact.extract_constant_field_evidence(
                provider, "sample.Flags", "TEXT", "Ljava/lang/String;"
            )
            count = constant_impact.extract_constant_field_evidence(
                provider, "sample.Flags", "COUNT", "I"
            )
            dynamic = constant_impact.extract_constant_field_evidence(
                provider, "sample.Flags", "DYNAMIC", "Ljava/lang/String;"
            )
            wrong_descriptor = constant_impact.extract_constant_field_evidence(
                provider, "sample.Flags", "TEXT", "I"
            )
            provider_sha = hashlib.sha256(provider.read_bytes()).hexdigest()

        self.assertEqual(text.status, "complete")
        self.assertTrue(text.has_constant_value)
        self.assertEqual(text.constant_value, "old")
        self.assertEqual(text.artifact_sha256, provider_sha)
        self.assertEqual(text.artifact_entry, "sample/Flags.class")
        self.assertEqual(count.constant_value, 7)
        self.assertFalse(dynamic.has_constant_value)
        self.assertEqual(wrong_descriptor.status, "field_not_found")
        self.assertFalse(wrong_descriptor.has_constant_value)

    def test_scans_only_exact_runtime_field_links_from_consumer_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider, consumer = self._compile_fixture(Path(tmp))

            inlined_text = constant_impact.scan_consumer_field_links(
                [consumer], "sample.Flags", "TEXT", "Ljava/lang/String;"
            )
            inlined_count = constant_impact.scan_consumer_field_links(
                [consumer], "sample.Flags", "COUNT", "I"
            )
            dynamic = constant_impact.scan_consumer_field_links(
                [consumer], "sample.Flags", "DYNAMIC", "Ljava/lang/String;"
            )
            consumer_sha = hashlib.sha256(consumer.read_bytes()).hexdigest()

        self.assertEqual(inlined_text, ())
        self.assertEqual(inlined_count, ())
        self.assertEqual(len(dynamic), 1)
        self.assertEqual(dynamic[0].consumer_owner, "sample.Caller")
        self.assertEqual(dynamic[0].target_owner, "sample.Flags")
        self.assertEqual(dynamic[0].target_descriptor, "Ljava/lang/String;")
        self.assertEqual(dynamic[0].opcode, "getstatic")
        self.assertEqual(dynamic[0].artifact_sha256, consumer_sha)
        self.assertEqual(dynamic[0].artifact_entry, "sample/Caller.class")

    def test_rejects_entry_path_that_disagrees_with_internal_class_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider, _consumer = self._compile_fixture(root)
            renamed = root / "renamed.jar"
            with zipfile.ZipFile(provider) as source, zipfile.ZipFile(renamed, "w") as target:
                target.writestr("sample/Renamed.class", source.read("sample/Flags.class"))

            evidence = constant_impact.extract_constant_field_evidence(
                renamed, "sample.Renamed", "TEXT", "Ljava/lang/String;"
            )

        self.assertEqual(evidence.status, "incomplete")
        self.assertIn("class_owner_mismatch", " ".join(evidence.failures))

    def test_malformed_target_class_is_incomplete_not_field_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "malformed.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/Flags.class", b"not-a-class")

            evidence = constant_impact.extract_constant_field_evidence(
                artifact, "sample.Flags", "TEXT", "Ljava/lang/String;"
            )

        self.assertEqual(evidence.status, "incomplete")
        self.assertTrue(evidence.failures)


if __name__ == "__main__":
    unittest.main()
