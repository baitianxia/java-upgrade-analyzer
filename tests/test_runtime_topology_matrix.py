import csv
import hashlib
import json
import shutil
import subprocess
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
import enhanced_output_formatter as formatter  # noqa: E402
import final_artifact_edge_oracle as artifact_oracle  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


class RuntimeTopologyMatrixTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK required")
    def test_war_catalog_uses_web_inf_business_classes_and_nested_libraries(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            source = report / "src"
            library_source = source / "com/acme/Library.java"
            application_source = source / "com/acme/Application.java"
            library_source.parent.mkdir(parents=True)
            library_source.write_text(
                "package com.acme; public class Library { "
                "public static String changed() { return \"ok\"; } }",
                encoding="utf-8",
            )
            application_source.write_text(
                "package com.acme; public class Application { "
                "public String run() { return Library.changed(); } }",
                encoding="utf-8",
            )
            library_classes = report / "library-classes"
            application_classes = report / "application-classes"
            library_classes.mkdir()
            application_classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(library_classes), str(library_source)], check=True
            )
            subprocess.run(
                [
                    "javac", "-classpath", str(library_classes), "-d",
                    str(application_classes), str(application_source),
                ],
                check=True,
            )
            nested = report / "library.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.write(
                    library_classes / "com/acme/Library.class",
                    "com/acme/Library.class",
                )
            artifact = report / "application.war"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("WEB-INF/lib/library-1.0.jar", nested.read_bytes())
                archive.write(
                    application_classes / "com/acme/Application.class",
                    "WEB-INF/classes/com/acme/Application.class",
                )

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
                self.assertTrue(archive.read("com/acme/Application.class").startswith(b"\xca\xfe\xba\xbe"))

            target = {
                "coord": "com.acme:library",
                "api_name": "com.acme.Library.changed",
                "api_simple": "changed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            graph = type("Graph", (), {
                "methods_by_id": {},
                "reverse_edges": {},
                "runtime_dependency_catalog": catalog,
            })()
            analyzer_scan = tracer._scan_packaged_runtime_dependencies_for_api(
                target, graph
            )
            oracle_scan = artifact_oracle.scan_final_artifact(
                artifact, selected_targets=[target]
            )

            self.assertEqual(analyzer_scan["status"], "hit")
            self.assertTrue(any(
                hit.get("class_fqcn") == "com.acme.Application"
                for hit in analyzer_scan["hits"]
            ), analyzer_scan)
            self.assertTrue(oracle_scan["complete"], oracle_scan["failures"])
            self.assertTrue(any(
                edge["caller_owner"] == "com.acme.Application"
                and edge["callee_owner"] == "com.acme.Library"
                and edge["callee_member"] == "changed"
                for edge in oracle_scan["edges"]
            ), oracle_scan["edges"])

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

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK required")
    def test_multi_release_runtime_scan_uses_target_jdk_version(self):
        target_jdk = int(
            subprocess.run(
                ["javap", "-version"], check=True, capture_output=True,
                text=True, encoding="utf-8",
            ).stdout.strip().split(".")[0]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            api_source = root / "api/com/vendor/Api.java"
            base_source = root / "base/com/acme/Consumer.java"
            version_source = root / "version/com/acme/Consumer.java"
            api_source.parent.mkdir(parents=True)
            base_source.parent.mkdir(parents=True)
            version_source.parent.mkdir(parents=True)
            api_source.write_text(
                "package com.vendor; public class Api { "
                "public static void base() {} public static void versioned() {} }",
                encoding="utf-8",
            )
            base_source.write_text(
                "package com.acme; import com.vendor.Api; "
                "public class Consumer { public void run() { Api.base(); } }",
                encoding="utf-8",
            )
            version_source.write_text(
                "package com.acme; import com.vendor.Api; "
                "public class Consumer { public void run() { Api.versioned(); } }",
                encoding="utf-8",
            )
            api_classes = root / "api-classes"
            base_classes = root / "base-classes"
            version_classes = root / "version-classes"
            for directory in (api_classes, base_classes, version_classes):
                directory.mkdir()
            subprocess.run(["javac", "-d", str(api_classes), str(api_source)], check=True)
            for source, output in ((base_source, base_classes), (version_source, version_classes)):
                subprocess.run(
                    [
                        "javac", "-classpath", str(api_classes), "-d", str(output),
                        str(source),
                    ],
                    check=True,
                )
            artifact = root / "consumer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMulti-Release: true\n\n",
                )
                archive.write(
                    base_classes / "com/acme/Consumer.class",
                    "com/acme/Consumer.class",
                )
                archive.write(
                    version_classes / "com/acme/Consumer.class",
                    f"META-INF/versions/{target_jdk}/com/acme/Consumer.class",
                )
            graph = type("Graph", (), {
                "methods_by_id": {},
                "reverse_edges": {},
                "target_jdk": str(target_jdk),
                "runtime_dependency_catalog": {
                    "status": "complete",
                    "by_coord": {
                        "com.acme:consumer": {
                            "coord": "com.acme:consumer",
                            "jar_path": str(artifact),
                        }
                    },
                },
            })()
            scan = tracer._scan_packaged_runtime_dependencies_for_api(
                {
                    "coord": "com.vendor:api",
                    "api_name": "com.vendor.Api.versioned",
                    "api_simple": "versioned",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                },
                graph,
            )

        self.assertEqual(scan["status"], "hit", scan)
        self.assertTrue(any(
            hit.get("class_fqcn") == "com.acme.Consumer"
            and int(hit.get("multi_release_version") or 0) == target_jdk
            for hit in scan["hits"]
        ), scan["hits"])

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

            graph_result = step5.build_enhanced_source_graph([{
                "root": tmp,
                "owner_type": "business",
                "owner_coord": "BUSINESS",
                "module": "app",
            }])
            graph = graph_result["graph"]
            result = tracer.trace_api_with_confidence_weighting(
                {
                    "coord": "com.vendor:legacy",
                    "api_name": "com.vendor.LegacyApi.removed",
                    "api_simple": "removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "confirmed": "true",
                },
                graph,
                graph.type_metadata,
            )
            output = Path(tmp) / "output"
            formatter.generate_enhanced_summary([result], output)
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))

            self.assertEqual(result.analysis_status, "reachable")
            self.assertEqual(summary["reachable"], 1)
            self.assertEqual(summary["reachable_apis"][0]["api_name"], "com.vendor.LegacyApi.removed")


if __name__ == "__main__":
    unittest.main()
