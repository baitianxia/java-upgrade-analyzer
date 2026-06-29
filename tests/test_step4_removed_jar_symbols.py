import sys
import tempfile
import unittest
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
            with patch.object(
                step4,
                "find_jar_in_m2",
                return_value=str(output_dir / "legacy-lib-1.0.0.jar"),
            ), patch.object(
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
                )
                self.assertIsNone(err)
                self.assertTrue(Path(out_file).exists())
                self.assertEqual(jar_info["old_jar"], str(output_dir / "legacy-lib-1.0.0.jar"))
                self.assertEqual([row["symbol_kind"] for row in apis], ["class", "constructor", "method"])


if __name__ == "__main__":
    unittest.main()
