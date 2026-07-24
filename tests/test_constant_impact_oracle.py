import ast
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
    def test_oracle_import_boundary_is_independent_from_analyzer_modules(self):
        tree = ast.parse(
            (ROOT / "scripts" / "constant_impact_oracle.py").read_text(encoding="utf-8")
        )
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        allowed = {
            "dataclasses", "hashlib", "io", "pathlib", "re", "subprocess",
            "tempfile", "zipfile", "path_runtime", "signature_utils",
        }

        self.assertEqual(imported_roots - allowed, set())

    def _fixture(self, root):
        src = root / "src" / "sample"
        classes = root / "classes"
        src.mkdir(parents=True)
        (src / "Flags.java").write_text(
            'package sample; public class Flags {'
            ' public static final String TEXT = "old";'
            ' public static final String EMPTY = "";'
            ' public static String DYNAMIC = "live"; }',
            encoding="utf-8",
        )
        (src / "Caller.java").write_text(
            'package sample; public class Caller {'
            ' static String INITIAL = Flags.DYNAMIC;'
            ' public String text() { return Flags.TEXT; }'
            ' String packageDynamic() { return Flags.DYNAMIC; }'
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
        self.assertEqual(len(by_name["sample.Flags.DYNAMIC"].runtime_links), 3)
        links = {
            (item["consumer_method"], item["consumer_descriptor"]): item
            for item in by_name["sample.Flags.DYNAMIC"].runtime_links
        }
        self.assertEqual(set(links), {
            ("<clinit>", "()V"),
            ("packageDynamic", "()Ljava/lang/String;"),
            ("dynamic", "()Ljava/lang/String;"),
        })
        link = links[("dynamic", "()Ljava/lang/String;")]
        self.assertEqual(link["opcode"], "getstatic")
        self.assertEqual(link["consumer_owner"], "sample.Caller")
        self.assertEqual(link["consumer_method"], "dynamic")
        self.assertEqual(link["consumer_descriptor"], "()Ljava/lang/String;")
        self.assertEqual(link["target_owner"], "sample.Flags")
        self.assertEqual(link["target_field"], "DYNAMIC")
        self.assertEqual(link["target_descriptor"], "Ljava/lang/String;")
        self.assertEqual(
            by_name["sample.Flags.TEXT"].consumer_artifact_sha256s,
            by_name["sample.Flags.DYNAMIC"].consumer_artifact_sha256s,
        )
        self.assertEqual(len(by_name["sample.Flags.TEXT"].consumer_artifact_sha256s), 1)

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

    def test_javap_oracle_preserves_empty_string_constant_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider, consumer = self._fixture(Path(tmp))
            row = {
                "coord": "sample:provider", "api_name": "sample.Flags.EMPTY",
                "symbol_kind": "field", "field_descriptor": "Ljava/lang/String;",
                "change_type": "REMOVED",
            }

            ledger = oracle.run_constant_oracle(provider, [consumer], [row])

        self.assertTrue(ledger.complete, ledger.failures)
        self.assertEqual(ledger.records[0].constant_value, "")

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

    def test_closed_set_audit_rejects_duplicates_descriptor_value_sha_and_stronger_conclusion(self):
        oracle_rows = [{
            "identity": "g:a|sample.Flags.TEXT|field|",
            "descriptor": "Ljava/lang/String;",
            "has_constant_value": True,
            "constant_value": "old",
            "runtime_links": [],
            "old_artifact_sha256": "a" * 64,
            "expected_conclusion": "uncertain",
        }]
        analyzer_rows = [{
            "identity": "g:a|sample.Flags.TEXT|field|",
            "descriptor": "I",
            "has_constant_value": True,
            "constant_value": "new",
            "runtime_link_present": False,
            "old_artifact_sha256": "b" * 64,
            "conclusion": "reachable",
        }, {
            "identity": "g:a|sample.Flags.TEXT|field|",
            "descriptor": "Ljava/lang/String;",
            "has_constant_value": True,
            "constant_value": "old",
            "runtime_link_present": False,
            "old_artifact_sha256": "a" * 64,
            "conclusion": "uncertain",
        }]

        audit = oracle.audit_constant_evidence(analyzer_rows, oracle_rows)

        self.assertTrue(audit["blocking"])
        self.assertEqual(
            audit["analyzer_duplicate_identities"],
            ["g:a|sample.Flags.TEXT|field|"],
        )
        self.assertEqual(
            audit["incorrect_fields"]["g:a|sample.Flags.TEXT|field|"],
            ["conclusion", "constant_value", "descriptor", "old_artifact_sha256"],
        )

    def test_closed_set_audit_rejects_duplicate_oracle_identity(self):
        row = {
            "identity": "g:a|sample.Flags.TEXT|field|",
            "descriptor": "Ljava/lang/String;",
            "has_constant_value": True,
            "constant_value": "old",
            "runtime_links": [],
            "old_artifact_sha256": "a" * 64,
            "expected_conclusion": "uncertain",
        }

        audit = oracle.audit_constant_evidence([], [row, dict(row)])

        self.assertTrue(audit["blocking"])
        self.assertEqual(audit["oracle_duplicate_identities"], [row["identity"]])

    def test_closed_set_audit_reconciles_exact_runtime_link_multiset_and_consumer_sha(self):
        link = {
            "consumer_owner": "sample.Caller", "consumer_method": "dynamic",
            "consumer_descriptor": "()Ljava/lang/String;",
            "target_owner": "sample.Flags", "target_field": "DYNAMIC",
            "target_descriptor": "Ljava/lang/String;", "opcode": "getstatic",
            "instruction_offset": 0, "artifact_sha256": "b" * 64,
            "artifact_entry": "sample/Caller.class",
        }
        oracle_rows = [{
            "identity": "dynamic", "has_constant_value": False,
            "runtime_links": [link], "consumer_artifact_sha256s": ["b" * 64],
        }]
        analyzer_rows = [{
            "identity": "dynamic", "has_constant_value": False,
            "runtime_links": [{**link, "instruction_offset": 1}],
            "consumer_artifact_sha256s": ["c" * 64],
        }]

        audit = oracle.audit_constant_evidence(analyzer_rows, oracle_rows)

        self.assertTrue(audit["blocking"])
        self.assertEqual(
            audit["incorrect_fields"]["dynamic"],
            ["consumer_artifact_sha256s", "runtime_links"],
        )


if __name__ == "__main__":
    unittest.main()
