import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import constant_impact  # noqa: E402
import constant_impact_oracle as oracle  # noqa: E402


@unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
class ConstantImpactOracleTest(unittest.TestCase):
    def _fixture(self, root):
        src = root / "src" / "sample"
        classes = root / "classes"
        src.mkdir(parents=True)
        (src / "Flags.java").write_text(
            'package sample; public class Flags {'
            ' public static final String TEXT = "old";'
            ' public static String DYNAMIC = "live"; }',
            encoding="utf-8",
        )
        (src / "Caller.java").write_text(
            'package sample; public class Caller {'
            ' public String text() { return Flags.TEXT; }'
            ' public String dynamic() { return Flags.DYNAMIC; } }',
            encoding="utf-8",
        )
        subprocess.run(
            ["javac", "-d", str(classes), str(src / "Flags.java"), str(src / "Caller.java")],
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

    def test_javap_oracle_proves_constant_and_inlined_absence_for_every_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider, consumer = self._fixture(Path(tmp))
            rows = [
                {
                    "coord": "sample:provider", "api_name": "sample.Flags.TEXT",
                    "symbol_kind": "field", "field_descriptor": "Ljava/lang/String;",
                    "change_type": "REMOVED",
                },
                {
                    "coord": "sample:provider", "api_name": "sample.Flags.DYNAMIC",
                    "symbol_kind": "field", "field_descriptor": "Ljava/lang/String;",
                    "change_type": "REMOVED",
                },
            ]

            ledger = oracle.run_constant_oracle(provider, [consumer], rows)

        self.assertTrue(ledger.complete, ledger.failures)
        self.assertEqual(len(ledger.records), 2)
        by_name = {record.api_name: record for record in ledger.records}
        self.assertTrue(by_name["sample.Flags.TEXT"].has_constant_value)
        self.assertEqual(by_name["sample.Flags.TEXT"].constant_value, "old")
        self.assertEqual(by_name["sample.Flags.TEXT"].runtime_links, ())
        self.assertFalse(by_name["sample.Flags.DYNAMIC"].has_constant_value)
        self.assertEqual(len(by_name["sample.Flags.DYNAMIC"].runtime_links), 1)
        self.assertEqual(by_name["sample.Flags.DYNAMIC"].runtime_links[0]["opcode"], "getstatic")

    def test_oracle_does_not_import_or_call_analyzer_constant_extractor(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider, consumer = self._fixture(Path(tmp))
            row = {
                "coord": "sample:provider", "api_name": "sample.Flags.TEXT",
                "symbol_kind": "field", "field_descriptor": "Ljava/lang/String;",
                "change_type": "REMOVED",
            }
            with patch.object(
                constant_impact,
                "extract_constant_field_evidence",
                side_effect=AssertionError("Oracle must remain independent"),
            ):
                ledger = oracle.run_constant_oracle(provider, [consumer], [row])

        self.assertTrue(ledger.complete, ledger.failures)
        self.assertTrue(ledger.records[0].has_constant_value)

    def test_closed_set_audit_rejects_missing_extra_and_wrong_analyzer_evidence(self):
        oracle_rows = [
            {"identity": "a", "has_constant_value": True, "runtime_link_present": False},
            {"identity": "b", "has_constant_value": False, "runtime_link_present": True},
        ]
        analyzer_rows = [
            {"identity": "a", "has_constant_value": False, "runtime_link_present": False},
            {"identity": "extra", "has_constant_value": False, "runtime_link_present": False},
        ]

        audit = oracle.audit_constant_evidence(analyzer_rows, oracle_rows)

        self.assertTrue(audit["blocking"])
        self.assertEqual(audit["missing_identities"], ["b"])
        self.assertEqual(audit["extra_identities"], ["extra"])
        self.assertEqual(audit["incorrect_identities"], ["a"])


if __name__ == "__main__":
    unittest.main()
