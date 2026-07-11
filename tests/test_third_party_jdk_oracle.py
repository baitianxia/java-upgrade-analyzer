import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import third_party_jdk_oracle as jdk_oracle  # noqa: E402


class ThirdPartyJdkOracleTest(unittest.TestCase):
    def test_discovery_rejects_an_empty_compiled_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "no production class files"):
                jdk_oracle.discover_calls(
                    [],
                    owner_prefixes=("dep/",),
                    coord="g:a",
                    evidence_dir=Path(tmp),
                )

    def test_discovers_dependency_calls_as_exhaustive_changed_api_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            classes = root / "classes"
            (source / "dep").mkdir(parents=True)
            (source / "app").mkdir()
            classes.mkdir()
            (source / "dep" / "Tool.java").write_text(
                "package dep; public class Tool { "
                "public static void use(String value) {} "
                "public static void use(int value) {} }",
                encoding="utf-8",
            )
            (source / "app" / "Caller.java").write_text(
                'package app; public class Caller { void run() { '
                'dep.Tool.use("x"); dep.Tool.use("y"); dep.Tool.use(1); } }',
                encoding="utf-8",
            )
            subprocess.run(
                ["javac", "-d", str(classes), *(str(path) for path in source.rglob("*.java"))],
                check=True,
                capture_output=True,
                text=True,
            )

            rows = jdk_oracle.discover_calls(
                [classes / "app" / "Caller.class"],
                owner_prefixes=("dep/",),
                coord="g:a",
                evidence_dir=root / "evidence",
            )

        self.assertEqual(
            [(row["api_name"], row["api_signature"]) for row in rows],
            [("dep.Tool.use", "(int)"), ("dep.Tool.use", "(java.lang.String)")],
        )
        self.assertTrue(all(row["symbol_kind"] == "method" for row in rows))
        self.assertTrue(all(row["oracle_conclusion"] == "reachable" for row in rows))
        self.assertTrue(all(row["authority"] == "jdk-javap" for row in rows))
        self.assertTrue(all(row["caller_class"] == "app.Caller" for row in rows))

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
