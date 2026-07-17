import csv
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import confidence_weighted_tracer as tracer  # noqa: E402
import enhanced_source_analyzer as source_analyzer  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


class RuntimeTopologyMatrixTest(unittest.TestCase):
    def test_war_catalog_uses_web_inf_business_classes_and_nested_libraries(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            nested = report / "library.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("com/acme/Library.class", b"library")
            artifact = report / "application.war"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("WEB-INF/lib/library-1.0.jar", nested.read_bytes())
                archive.writestr("WEB-INF/classes/com/acme/Application.class", b"application")

            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            with (dependencies / "deps_current_resolved.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["coord", "version", "scope", "lib_entry"]
                )
                writer.writeheader()
                writer.writerow({
                    "coord": "com.acme:library",
                    "version": "1.0",
                    "scope": "packaged",
                    "lib_entry": "WEB-INF/lib/library-1.0.jar",
                })
            (dependencies / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")

            catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertEqual(catalog["status"], "complete")
            self.assertEqual(
                Path(catalog["by_coord"]["com.acme:library"]["jar_path"]).read_bytes(),
                nested.read_bytes(),
            )
            with zipfile.ZipFile(catalog["by_coord"]["__business__"]["jar_path"]) as archive:
                self.assertEqual(archive.read("com/acme/Application.class"), b"application")

    def test_multi_release_selection_matrix_respects_target_jdk(self):
        entries = [
            "com/acme/Consumer.class",
            "META-INF/versions/11/com/acme/Consumer.class",
            "META-INF/versions/17/com/acme/Consumer.class",
        ]
        expected = {
            8: ("com/acme/Consumer.class", "base"),
            11: ("META-INF/versions/11/com/acme/Consumer.class", 11),
            16: ("META-INF/versions/11/com/acme/Consumer.class", 11),
            17: ("META-INF/versions/17/com/acme/Consumer.class", 17),
            21: ("META-INF/versions/17/com/acme/Consumer.class", 17),
        }

        for target_jdk, selected in expected.items():
            with self.subTest(target_jdk=target_jdk):
                variants, is_multi_release, parsed_target = tracer._runtime_class_variants(
                    entries, str(target_jdk), multi_release_enabled=True
                )
                self.assertTrue(is_multi_release)
                self.assertEqual(parsed_target, target_jdk)
                self.assertEqual(variants, [(selected[0], "com/acme/Consumer.class", selected[1])])

    def test_kotlin_standard_package_and_import_resolve_call_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "com/acme/Service.kt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package com.acme\n"
                "import com.vendor.LegacyApi\n"
                "class Service {\n"
                "  fun run(api: LegacyApi): String {\n"
                "    return api.removed()\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            methods, diagnostics = source_analyzer.analyze_file(
                str(source),
                {"root": tmp, "owner_type": "business", "owner_coord": "BUSINESS", "module": "app"},
                return_diagnostics=True,
            )

            self.assertEqual(diagnostics["language"], "kotlin")
            self.assertEqual(len(methods), 1)
            self.assertEqual(methods[0].class_fqcn, "com.acme.Service")
            edges = source_analyzer.extract_call_edges_enhanced(methods[0])
            self.assertTrue(any(
                edge.callee_key.startswith("com.vendor.LegacyApi.removed")
                for edge in edges
            ), [edge.callee_key for edge in edges])


if __name__ == "__main__":
    unittest.main()
