import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import third_party_jdk_oracle as jdk_oracle  # noqa: E402


class ThirdPartyJdkOracleTest(unittest.TestCase):
    def test_javap_certifies_only_exact_owner_and_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "p"
            classes = root / "classes"
            source.mkdir(parents=True)
            classes.mkdir()
            (source / "Target.java").write_text(
                "package p; public class Target { "
                "public static void call(String value) {} "
                "public static void call(int value) {} }",
                encoding="utf-8",
            )
            (source / "Caller.java").write_text(
                'package p; public class Caller { void run() { Target.call("x"); } }',
                encoding="utf-8",
            )
            subprocess.run(
                ["javac", "-d", str(classes), str(source / "Target.java"), str(source / "Caller.java")],
                check=True,
                capture_output=True,
                text=True,
            )
            changed = [
                {"coord": "g:a", "api_name": "p.Target.call", "api_signature": "(java.lang.String)", "symbol_kind": "method"},
                {"coord": "g:a", "api_name": "p.Target.call", "api_signature": "(int)", "symbol_kind": "method"},
            ]

            records = jdk_oracle.scan_class_files(
                changed,
                sorted(classes.rglob("*.class")),
                root / "evidence",
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["api_signature"], "(java.lang.String)")
        self.assertEqual(records[0]["oracle_conclusion"], "reachable")
        self.assertEqual(records[0]["authority"], "jdk-javap")
        self.assertEqual(len(records[0]["evidence_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
