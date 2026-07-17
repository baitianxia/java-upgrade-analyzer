import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import constant_impact  # noqa: E402


class ConstantImpactTest(unittest.TestCase):
    def test_removed_inlined_constant_has_compile_break_and_no_runtime_link(self):
        result = constant_impact.classify_constant_impact(
            change_type="REMOVED",
            old_field_has_constant_value=True,
            source_reference_present=True,
            runtime_field_edge_present=False,
            source_artifact_aligned=True,
        )
        self.assertEqual(result.compile_impact, "recompile_break")
        self.assertEqual(result.runtime_link_impact, "inlined_no_link")

    def test_changed_inlined_constant_keeps_old_runtime_value(self):
        result = constant_impact.classify_constant_impact(
            change_type="CONSTANT_VALUE_CHANGED",
            old_field_has_constant_value=True,
            source_reference_present=True,
            runtime_field_edge_present=False,
            source_artifact_aligned=True,
        )
        self.assertEqual(result.compile_impact, "recompile_value_change")
        self.assertEqual(result.runtime_link_impact, "inlined_old_value")

    def test_nonconstant_field_with_runtime_edge_is_linked(self):
        result = constant_impact.classify_constant_impact(
            change_type="REMOVED",
            old_field_has_constant_value=False,
            source_reference_present=True,
            runtime_field_edge_present=True,
            source_artifact_aligned=True,
        )
        self.assertEqual(result.compile_impact, "recompile_break")
        self.assertEqual(result.runtime_link_impact, "runtime_link_present")

    def test_source_artifact_mismatch_keeps_both_dimensions_unverified(self):
        result = constant_impact.classify_constant_impact(
            change_type="REMOVED",
            old_field_has_constant_value=True,
            source_reference_present=True,
            runtime_field_edge_present=False,
            source_artifact_aligned=False,
        )
        self.assertEqual(result.compile_impact, "unverified")
        self.assertEqual(result.runtime_link_impact, "unverified")

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_javap_proves_constant_value_and_caller_inlining(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "p"
            classes = root / "classes"
            source.mkdir()
            (source / "Provider.java").write_text(
                'package p; public class Provider { public static final String VALUE = "old"; '
                'public static String DYNAMIC = "live"; }', encoding="utf-8"
            )
            (source / "Caller.java").write_text(
                'package p; public class Caller { public String a() { return Provider.VALUE; } '
                'public String b() { return Provider.DYNAMIC; } }', encoding="utf-8"
            )
            subprocess.run(
                ["javac", "-d", str(classes), str(source / "Provider.java"),
                 str(source / "Caller.java")], check=True
            )

            self.assertTrue(constant_impact.javap_field_has_constant_value(
                classes, "p.Provider", "VALUE"
            ))
            self.assertFalse(constant_impact.javap_field_has_constant_value(
                classes, "p.Provider", "DYNAMIC"
            ))
            self.assertFalse(constant_impact.javap_caller_has_field_link(
                classes, "p.Caller", "p.Provider", "VALUE"
            ))
            self.assertTrue(constant_impact.javap_caller_has_field_link(
                classes, "p.Caller", "p.Provider", "DYNAMIC"
            ))


if __name__ == "__main__":
    unittest.main()
