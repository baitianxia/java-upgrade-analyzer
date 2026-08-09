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

    def test_unknown_changed_resource_makes_only_that_comparison_scope_partial(self):
        base = self.jar("base.jar", [("config/custom.bin", b"old")])
        current = self.jar("current.jar", [("config/custom.bin", b"new")])

        base_snapshot, current_snapshot, result = self.compare(base, current)

        self.assertEqual(base_snapshot.comparison_coverage_status, "partial")
        self.assertEqual(current_snapshot.comparison_coverage_status, "partial")
        self.assertEqual(result["resource_diff_status"], "unknown")
        self.assertEqual(result["comparison_coverage_status"], "partial")
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
