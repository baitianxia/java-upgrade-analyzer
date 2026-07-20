import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import third_party_jdeps_oracle as jdeps_oracle  # noqa: E402


class ThirdPartyJdepsOracleTest(unittest.TestCase):
    def test_parse_jdeps_class_dependencies_ignores_summary_lines(self):
        output = (
            "classes -> java.base\n"
            "   app.Entry -> vendor.Target provider\n"
            "   app.Entry -> java.lang.Object java.base\n"
        )

        self.assertEqual(jdeps_oracle.parse_jdeps_class_dependencies(output), [
            ("app.Entry", "vendor.Target"),
            ("app.Entry", "java.lang.Object"),
        ])

    def test_scan_artifact_uses_jdeps_as_independent_class_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            classes = root / "classes"
            (source / "vendor").mkdir(parents=True)
            (source / "app").mkdir(parents=True)
            (source / "vendor" / "Target.java").write_text(
                "package vendor; public class Target {}", encoding="utf-8"
            )
            (source / "app" / "Entry.java").write_text(
                "package app; public class Entry { vendor.Target value; }", encoding="utf-8"
            )
            classes.mkdir()
            subprocess.run([
                "javac", "-d", str(classes),
                str(source / "vendor" / "Target.java"),
                str(source / "app" / "Entry.java"),
            ], check=True, capture_output=True)
            provider = io.BytesIO()
            with zipfile.ZipFile(provider, "w") as nested:
                nested.write(classes / "vendor" / "Target.class", "vendor/Target.class")
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.write(
                    classes / "app" / "Entry.class",
                    "BOOT-INF/classes/app/Entry.class",
                )
                outer.writestr("BOOT-INF/lib/provider.jar", provider.getvalue())
            selected = [
                {
                    "coord": "vendor:api", "api_name": "vendor.Target",
                    "symbol_kind": "class", "change_type": "REMOVED",
                },
                {
                    "coord": "vendor:api", "api_name": "vendor.Target",
                    "symbol_kind": "class", "change_type": "SIGNATURE_CHANGED",
                },
                {
                    "coord": "vendor:api", "api_name": "vendor.Absent",
                    "symbol_kind": "class", "change_type": "REMOVED",
                },
            ]

            result = jdeps_oracle.scan_artifact_class_references(
                artifact,
                selected,
                excluded_nested_jars={"BOOT-INF/lib/provider.jar"},
            )

        self.assertTrue(result["complete"], result["errors"])
        target_identities = {
            jdeps_oracle.serialized_api_identity(row)
            for row in selected if row["api_name"] == "vendor.Target"
        }
        self.assertEqual(len(target_identities), 2)
        self.assertTrue(all(
            result["api_reachability"][identity] == "reachable"
            for identity in target_identities
        ))
        absent_identity = jdeps_oracle.serialized_api_identity(selected[-1])
        self.assertEqual(
            result["api_reachability"][absent_identity],
            "not_found_in_static_analysis",
        )

    def test_scan_artifact_stops_before_jdeps_when_total_budget_is_exhausted(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/app/Entry.class", b"not-needed")
            selected = [{
                "coord": "vendor:api", "api_name": "vendor.Target",
                "symbol_kind": "class", "change_type": "REMOVED",
            }]

            result = jdeps_oracle.scan_artifact_class_references(
                artifact, selected, time_budget_seconds=0.0
            )

        self.assertFalse(result["complete"])
        self.assertTrue(result["metrics"]["timed_out"])
        self.assertIn("oracle_time_budget_exceeded", result["errors"])
        self.assertEqual(result["metrics"]["jdeps_invocations"], 0)

    def test_provider_exclusion_is_scoped_to_each_api_coord(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            classes = root / "classes"
            for package in ("vendor/a", "vendor/b"):
                (source / package).mkdir(parents=True)
            (source / "vendor/a/TargetA.java").write_text(
                "package vendor.a; public class TargetA {}", encoding="utf-8"
            )
            (source / "vendor/b/TargetB.java").write_text(
                "package vendor.b; public class TargetB {}", encoding="utf-8"
            )
            (source / "vendor/a/UsesB.java").write_text(
                "package vendor.a; public class UsesB { vendor.b.TargetB value; }",
                encoding="utf-8",
            )
            classes.mkdir()
            subprocess.run([
                "javac", "-d", str(classes),
                str(source / "vendor/a/TargetA.java"),
                str(source / "vendor/b/TargetB.java"),
                str(source / "vendor/a/UsesB.java"),
            ], check=True, capture_output=True)
            provider_a = io.BytesIO()
            with zipfile.ZipFile(provider_a, "w") as nested:
                nested.write(classes / "vendor/a/TargetA.class", "vendor/a/TargetA.class")
                nested.write(classes / "vendor/a/UsesB.class", "vendor/a/UsesB.class")
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/provider-a.jar", provider_a.getvalue())
            selected = [
                {"coord": "vendor:a", "api_name": "vendor.a.TargetA", "symbol_kind": "class"},
                {"coord": "vendor:b", "api_name": "vendor.b.TargetB", "symbol_kind": "class"},
            ]

            result = jdeps_oracle.scan_artifact_class_references(
                artifact,
                selected,
                provider_nested_jars_by_coord={
                    "vendor:a": {"BOOT-INF/lib/provider-a.jar"},
                },
            )

        identity_a = jdeps_oracle.serialized_api_identity(selected[0])
        identity_b = jdeps_oracle.serialized_api_identity(selected[1])
        self.assertTrue(result["complete"], result["errors"])
        self.assertEqual(
            result["api_reachability"][identity_a],
            "not_found_in_static_analysis",
        )
        self.assertEqual(result["api_reachability"][identity_b], "uncertain")

    def test_same_coordinate_provider_retains_other_class_internal_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "vendor"
            classes = root / "classes"
            source.mkdir(parents=True)
            (source / "Target.java").write_text(
                "package vendor; public class Target {}", encoding="utf-8"
            )
            (source / "Bridge.java").write_text(
                "package vendor; public class Bridge { vendor.Target value; }",
                encoding="utf-8",
            )
            classes.mkdir()
            subprocess.run([
                "javac", "-d", str(classes), str(source / "Target.java"),
                str(source / "Bridge.java"),
            ], check=True, capture_output=True)
            provider = io.BytesIO()
            with zipfile.ZipFile(provider, "w") as nested:
                nested.write(classes / "vendor" / "Target.class", "vendor/Target.class")
                nested.write(classes / "vendor" / "Bridge.class", "vendor/Bridge.class")
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/provider.jar", provider.getvalue())
            selected = [{
                "coord": "vendor:api", "api_name": "vendor.Target",
                "symbol_kind": "class", "change_type": "REMOVED",
            }]

            result = jdeps_oracle.scan_artifact_class_references(
                artifact,
                selected,
                provider_nested_jars_by_coord={
                    "vendor:api": {"BOOT-INF/lib/provider.jar"},
                },
            )

        identity = jdeps_oracle.serialized_api_identity(selected[0])
        self.assertTrue(result["complete"], result["errors"])
        self.assertEqual(result["api_reachability"][identity], "uncertain")
        self.assertEqual(result["references"][0]["caller_class"], "vendor.Bridge")


if __name__ == "__main__":
    unittest.main()
