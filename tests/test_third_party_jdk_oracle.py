import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_discovery_runs_independent_javap_tasks_with_bounded_parallelism(self):
        active = 0
        peak_active = 0
        lock = threading.Lock()

        def fake_run(command, **_kwargs):
            nonlocal active, peak_active
            if command[1] == "-version":
                return subprocess.CompletedProcess(command, 0, stdout="24\n", stderr="")
            with lock:
                active += 1
                peak_active = max(peak_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "public class app.Caller {\n"
                    "  void run();\n"
                    "    descriptor: ()V\n"
                    "       0: invokestatic #1 // Method dep/Tool.use:()V\n"
                    "}\n"
                ),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            jdk_oracle.subprocess, "run", side_effect=fake_run
        ):
            rows = jdk_oracle.discover_calls(
                [Path(tmp) / f"Caller{index}.class" for index in range(6)],
                owner_prefixes=("dep/",),
                coord="g:a",
                evidence_dir=Path(tmp) / "evidence",
            )

        self.assertGreater(peak_active, 1)
        self.assertLessEqual(peak_active, 8)
        self.assertEqual(len(rows), 1)

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
                {"coord": "g:a", "api_name": "p.Target.call", "api_signature": "(java.lang.String)", "symbol_kind": "method", "change_type": "REMOVED"},
                {"coord": "g:a", "api_name": "p.Target.call", "api_signature": "(java.lang.String)", "symbol_kind": "method", "change_type": "SIGNATURE_CHANGED"},
                {"coord": "g:a", "api_name": "p.Target.call", "api_signature": "(int)", "symbol_kind": "method"},
            ]

            records = jdk_oracle.scan_class_files(
                changed,
                sorted(classes.rglob("*.class")),
                root / "evidence",
            )

        self.assertEqual(len(records), 2)
        self.assertEqual(
            {record["change_type"] for record in records},
            {"REMOVED", "SIGNATURE_CHANGED"},
        )
        self.assertTrue(all(record["api_signature"] == "(java.lang.String)" for record in records))
        self.assertTrue(all(record["oracle_conclusion"] == "reachable" for record in records))
        self.assertTrue(all(record["authority"] == "jdk-javap" for record in records))
        self.assertTrue(all(len(record["evidence_sha256"]) == 64 for record in records))

    def test_javap_distinguishes_business_reachability_from_internal_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            classes = root / "classes"
            for package in ("app", "dep", "p"):
                (source / package).mkdir(parents=True, exist_ok=True)
            classes.mkdir()
            (source / "p" / "Target.java").write_text(
                "package p; public class Target { "
                "public static void call(String value) {} "
                "public static void call(int value) {} }",
                encoding="utf-8",
            )
            (source / "dep" / "Bridge.java").write_text(
                'package dep; public class Bridge { public static void entry() { '
                'p.Target.call("x"); } }',
                encoding="utf-8",
            )
            (source / "dep" / "Internal.java").write_text(
                "package dep; public class Internal { public static void run() { "
                "p.Target.call(1); } }",
                encoding="utf-8",
            )
            (source / "app" / "Caller.java").write_text(
                "package app; public class Caller { public void run() { "
                "dep.Bridge.entry(); } }",
                encoding="utf-8",
            )
            subprocess.run(
                ["javac", "-d", str(classes), *(str(path) for path in source.rglob("*.java"))],
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
                business_class_files=[classes / "app" / "Caller.class"],
            )

        conclusions = {
            row["api_signature"]: row["oracle_conclusion"] for row in records
        }
        self.assertEqual(conclusions, {
            "(java.lang.String)": "reachable",
            "(int)": "uncertain",
        })


if __name__ == "__main__":
    unittest.main()
