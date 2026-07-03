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
from unittest.mock import patch
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s5_call_chain_engine_integrated as step5
import confidence_weighted_tracer as tracer


class ArtifactBytecodeCatalogTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("javac") and shutil.which("jdeps") and shutil.which("javap"), "JDK tools required")
    def test_every_reference_found_by_jdeps_is_visible_to_upgrade_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src/com/vendor/Client.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package com.vendor; public class Client { public void removedMethod(String value) {} }",
                encoding="utf-8",
            )
            target_classes = root / "target-classes"
            target_classes.mkdir()
            subprocess.run(["javac", "-d", str(target_classes), str(target_src)], check=True, capture_output=True)
            target_jar = root / "client-1.jar"
            with zipfile.ZipFile(target_jar, "w") as zf:
                zf.write(target_classes / "com/vendor/Client.class", "com/vendor/Client.class")

            consumer_src = root / "consumer-src/com/acme/Consumer.java"
            consumer_src.parent.mkdir(parents=True)
            consumer_src.write_text(
                "package com.acme; public class Consumer { public void use(com.vendor.Client c) { c.removedMethod(\"x\"); } }",
                encoding="utf-8",
            )
            consumer_classes = root / "consumer-classes"
            consumer_classes.mkdir()
            subprocess.run(
                ["javac", "-cp", str(target_jar), "-d", str(consumer_classes), str(consumer_src)],
                check=True, capture_output=True,
            )
            consumer_jar = root / "consumer.jar"
            with zipfile.ZipFile(consumer_jar, "w") as zf:
                zf.write(consumer_classes / "com/acme/Consumer.class", "com/acme/Consumer.class")

            jdeps = subprocess.run(
                ["jdeps", "-verbose:class", "-filter:none", "-cp", str(target_jar), str(consumer_jar)],
                check=True, capture_output=True, text=True,
            )
            self.assertIn("com.vendor.Client", jdeps.stdout)

            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete",
                "by_coord": {
                    "com.acme:consumer": {"coord": "com.acme:consumer", "jar_path": str(consumer_jar)},
                    "com.vendor:client": {"coord": "com.vendor:client", "jar_path": str(target_jar)},
                },
            })
            api_row = {
                "coord": "com.vendor:client", "old_version": "1", "new_version": "2",
                "api_name": "com.vendor.Client.removedMethod", "api_simple": "removedMethod",
                "api_signature": "(String)", "symbol_kind": "method", "change_type": "METHOD_REMOVED",
            }
            scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

            self.assertEqual(scan["status"], "hit")
            self.assertEqual(scan["hits"][0]["coord"], "com.acme:consumer")

    def test_catalog_uses_exact_nested_jar_and_business_classes_from_current_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            nested = report / "consumer.jar"
            with zipfile.ZipFile(nested, "w") as zf:
                zf.writestr("com/acme/Consumer.class", b"consumer-bytecode")
            nested_bytes = nested.read_bytes()

            artifact = report / "current.jar"
            with zipfile.ZipFile(artifact, "w") as zf:
                zf.writestr("BOOT-INF/lib/consumer-1.0.jar", nested_bytes)
                zf.writestr("BOOT-INF/classes/com/example/App.class", b"business-bytecode")

            with (report / "s1_deps_current_resolved.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["coord", "version", "scope", "lib_entry"])
                writer.writeheader()
                writer.writerow({
                    "coord": "com.acme:consumer", "version": "1.0", "scope": "packaged",
                    "lib_entry": "BOOT-INF/lib/consumer-1.0.jar",
                })
            (report / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current", "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")

            with patch.object(step5, "_find_maven_jar", side_effect=AssertionError("must not use m2")):
                catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertEqual(catalog["status"], "complete")
            item = catalog["by_coord"]["com.acme:consumer"]
            self.assertEqual(item["evidence_source"], "current_final_artifact")
            self.assertEqual(Path(item["jar_path"]).read_bytes(), nested_bytes)
            business_jar = Path(catalog["by_coord"]["__business__"]["jar_path"])
            with zipfile.ZipFile(business_jar) as zf:
                self.assertEqual(zf.read("com/example/App.class"), b"business-bytecode")

    def test_catalog_marks_local_maven_fallback_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            fallback = report / "fallback.jar"
            with zipfile.ZipFile(fallback, "w") as zf:
                zf.writestr("com/acme/Consumer.class", b"x")
            with (report / "s1_deps_current_resolved.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["coord", "version", "scope", "lib_entry"])
                writer.writeheader()
                writer.writerow({"coord": "com.acme:consumer", "version": "1", "scope": "packaged", "lib_entry": ""})

            with patch.object(step5, "_find_maven_jar", return_value=str(fallback)):
                catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertEqual(catalog["status"], "partial")
            self.assertIn("local_maven_fallback_used", catalog["reason_codes"])


if __name__ == "__main__":
    unittest.main()
