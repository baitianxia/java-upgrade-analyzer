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


if __name__ == "__main__":
    unittest.main()
