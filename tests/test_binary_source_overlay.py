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
import binary_artifact_diff  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import ArtifactInstance  # noqa: E402
from binary_source_overlay import build_source_overlay, source_method_descriptor  # noqa: E402
from enhanced_source_analyzer import MethodDef  # noqa: E402


class BinarySourceOverlayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("javac"):
            raise unittest.SkipTest("javac required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "src" / "demo" / "Sample.java"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(
            "package demo; public class Sample { public String value(int n, String[] v){ return v[n]; } }",
            encoding="utf-8",
        )
        classes = self.root / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(self.source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.jar = self.root / "sample.jar"
        with zipfile.ZipFile(self.jar, "w") as archive:
            archive.write(classes / "demo" / "Sample.class", "demo/Sample.class")
        sha = binary_artifact_diff._sha256_file(self.jar)
        self.instance = ArtifactInstance(
            outer_artifact_sha256=sha,
            container_entry="<artifact>",
            content_sha256=sha,
            runtime_profile_identity="runtime-1",
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=0,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity="origin-1",
            coord="com.acme:sample:1",
        )
        self.store = BinaryFactStore()
        snapshot = binary_artifact_diff.snapshot_archive(
            self.jar,
            artifact_instance_identity=self.instance.identity,
            expected_sha256=sha,
            asm_jar=self.asm_jar,
        )
        self.store.add_artifact_snapshot(self.instance, snapshot)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def method(self, *, params=None, symbol="source-value"):
        return MethodDef(
            symbol_id=symbol,
            qualified_key="demo.Sample.value",
            simple_key="method:value",
            class_fqcn="demo.Sample",
            class_name="Sample",
            method_name="value",
            return_type="java.lang.String",
            file=str(self.source),
            line=1,
            end_line=1,
            package_name="demo",
            owner_type="business",
            owner_coord="BUSINESS",
            module="root",
            source_root=str(self.root / "src"),
            language="java",
            is_test=False,
            param_types=params or {"n": "int", "v": "java.lang.String[]"},
        )

    def test_exact_descriptor_maps_source_location_without_replacing_binary_member(self):
        before = self.store.counts()["members"]
        method = self.method()

        result = build_source_overlay(
            self.store,
            [method],
            analysis_context_identity="context-1",
            source_snapshot_identity="source-snapshot-1",
        )

        self.assertEqual(source_method_descriptor(method), "(I[Ljava/lang/String;)Ljava/lang/String;")
        self.assertEqual(result.mapped_count, 1)
        self.assertGreaterEqual(result.binary_only_count, 1)  # constructor has no source row
        self.assertEqual(self.store.counts()["members"], before)
        mapped = next(item for item in result.rows if item["mapping_status"] == "mapped")
        self.assertEqual(mapped["source_location"]["logical_path"], "demo/Sample.java")
        self.assertEqual(mapped["source_location"]["owner_coord"], "BUSINESS")
        self.assertEqual(mapped["binary_member"]["class_name"], "demo/Sample")
        self.assertNotIn(str(self.root), mapped["overlay_identity"])

    def test_descriptor_mismatch_is_conflict_and_binary_graph_remains_complete(self):
        wrong = self.method(params={"n": "long", "v": "java.lang.String[]"})

        result = build_source_overlay(
            self.store,
            [wrong],
            analysis_context_identity="context-wrong",
            source_snapshot_identity="source-snapshot-wrong",
        )

        self.assertEqual(result.conflict_count, 1)
        conflict = next(item for item in result.rows if item["mapping_status"] == "source_conflict")
        self.assertEqual(conflict["conflict"]["reason_code"], "SOURCE_BINARY_DESCRIPTOR_MISMATCH")
        self.assertTrue(self.store.rows("direct_edges"))

    def test_duplicate_exact_source_methods_are_ambiguous_not_arbitrarily_selected(self):
        result = build_source_overlay(
            self.store,
            [self.method(symbol="one"), self.method(symbol="two")],
            analysis_context_identity="context-ambiguous",
            source_snapshot_identity="source-snapshot-ambiguous",
        )

        self.assertEqual(result.ambiguous_count, 1)
        ambiguous = next(item for item in result.rows if item["mapping_status"] == "ambiguous")
        self.assertEqual(ambiguous["conflict"]["candidate_symbol_ids"], ["one", "two"])

    def test_unqualified_java_lang_char_sequence_uses_platform_descriptor(self):
        method = self.method(params={"value": "CharSequence"})

        self.assertEqual(
            source_method_descriptor(method),
            "(Ljava/lang/CharSequence;)Ljava/lang/String;",
        )


if __name__ == "__main__":
    unittest.main()
