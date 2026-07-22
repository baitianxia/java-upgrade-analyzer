import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s4_jar_compare as step4  # noqa: E402


class Step4RemovedJarSymbolsTest(unittest.TestCase):
    def test_parse_removed_jar_javap_output_extracts_class_method_and_constructor(self):
        text = """
Compiled from "LegacyApi.java"
public class com.example.LegacyApi {
  public com.example.LegacyApi();
  public java.lang.String call(java.lang.String);
  protected void helper();
}
"""

        rows = step4._parse_removed_jar_javap_output(
            text,
            coord="com.example:legacy-lib",
            old_ver="1.0.0",
            class_binary_name="com.example.LegacyApi",
        )

        self.assertEqual(rows[0]["symbol_kind"], "class")
        self.assertEqual(rows[0]["api_name"], "com.example.LegacyApi")
        self.assertEqual(rows[1]["symbol_kind"], "constructor")
        self.assertEqual(rows[1]["api_name"], "com.example.LegacyApi.LegacyApi")
        self.assertEqual(rows[1]["api_signature"], "()")
        self.assertEqual(rows[2]["symbol_kind"], "method")
        self.assertEqual(rows[2]["api_name"], "com.example.LegacyApi.call")
        self.assertEqual(rows[2]["api_signature"], "(java.lang.String)")
        self.assertEqual(rows[3]["symbol_kind"], "method")
        self.assertEqual(rows[3]["api_name"], "com.example.LegacyApi.helper")
        self.assertEqual(rows[3]["source"], "old_jar")

    def test_export_removed_jar_apis_aggregates_all_public_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            old_jar = output_dir / "legacy-lib-1.0.0.jar"
            old_jar.write_bytes(b"final-artifact-jar")
            with patch.object(
                step4,
                "_iter_jar_class_entries",
                return_value=["com.example.LegacyApi"],
            ), patch.object(
                step4,
                "_run_javap_public_api_dump",
                return_value=(
                    "public class com.example.LegacyApi {\n"
                    "  public com.example.LegacyApi();\n"
                    "  public void run();\n"
                    "}\n"
                ),
            ):
                out_file, apis, jar_info, err = step4.export_removed_jar_apis(
                    coord="com.example:legacy-lib",
                    old_ver="1.0.0",
                    output_dir=str(output_dir),
                    old_jar_path=str(old_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                )
                self.assertIsNone(err)
                self.assertTrue(Path(out_file).exists())
                self.assertEqual(jar_info["old_jar"], str(old_jar))
                self.assertEqual([row["symbol_kind"] for row in apis], ["class", "constructor", "method"])

    def test_export_removed_jar_apis_accepts_complete_empty_api_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            old_jar = output_dir / "empty-placeholder-1.0.0.jar"
            with zipfile.ZipFile(old_jar, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

            out_file, apis, jar_info, err = step4.export_removed_jar_apis(
                coord="com.example:empty-placeholder",
                old_ver="1.0.0",
                output_dir=str(output_dir),
                old_jar_path=str(old_jar),
                old_jar_evidence={"source": "step1_final_artifact"},
            )

            self.assertIsNone(err)
            self.assertEqual(apis, [])
            self.assertEqual(jar_info["class_count"], 0)
            self.assertEqual(jar_info["exported_api_count"], 0)
            self.assertTrue(jar_info["api_surface_empty"])
            self.assertEqual(jar_info["javap_invocations"], 0)
            self.assertIn("api_surface_empty=true", Path(out_file).read_text())

    def test_export_removed_jar_batches_classes_without_cross_attributing_members(self):
        javap_output = """
Compiled from "LegacyA.java"
public class com.example.LegacyA {
  public com.example.LegacyA();
  public void alpha();
}
Compiled from "LegacyB.java"
public class com.example.LegacyB {
  public com.example.LegacyB();
  public void beta();
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            old_jar = Path(tmp) / "legacy.jar"
            old_jar.write_bytes(b"final-artifact-jar")
            with patch.object(
                step4,
                "_iter_jar_class_entries",
                return_value=["com.example.LegacyA", "com.example.LegacyB"],
            ), patch.object(
                step4,
                "run_cmd",
                return_value=(javap_output, "", 0),
            ) as run_cmd:
                _out, apis, details, error = step4.export_removed_jar_apis(
                    coord="com.example:legacy",
                    old_ver="1.0",
                    output_dir=tmp,
                    old_jar_path=str(old_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                )

        self.assertIsNone(error)
        self.assertEqual(run_cmd.call_count, 1)
        self.assertEqual(details["javap_invocations"], 1)
        methods = {
            row["api_name"] for row in apis if row["symbol_kind"] == "method"
        }
        self.assertEqual(methods, {
            "com.example.LegacyA.alpha",
            "com.example.LegacyB.beta",
        })

    def test_export_removed_jar_is_incomplete_when_any_javap_batch_fails(self):
        class_names = [f"com.example.Legacy{index}" for index in range(65)]
        first_batch_output = "\n".join(
            f"public class {name} {{\n  public {name}();\n}}"
            for name in class_names[:64]
        )
        with tempfile.TemporaryDirectory() as tmp:
            old_jar = Path(tmp) / "legacy.jar"
            old_jar.write_bytes(b"final-artifact-jar")
            with patch.object(
                step4, "_iter_jar_class_entries", return_value=class_names,
            ), patch.object(
                step4,
                "run_cmd",
                side_effect=[
                    (first_batch_output, "", 0),
                    ("", "simulated javap failure", 1),
                ],
            ):
                _out, apis, details, error = step4.export_removed_jar_apis(
                    coord="com.example:legacy",
                    old_ver="1.0",
                    output_dir=tmp,
                    old_jar_path=str(old_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                )

        self.assertTrue(apis)
        self.assertTrue(details["errors"])
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
