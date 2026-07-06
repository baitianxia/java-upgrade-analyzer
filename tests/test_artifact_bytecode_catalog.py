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
    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_reflection_bytecode_is_visible_to_upgrade_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            consumer_src = root / "src/com/acme/Consumer.java"
            consumer_src.parent.mkdir(parents=True)
            consumer_src.write_text(
                "package com.acme; public class Consumer { public Object check(String value) throws Exception { "
                "return Class.forName(\"org.apache.commons.lang.StringUtils\")"
                ".getMethod(\"isBlank\", String.class).invoke(null, value); } }",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(["javac", "-d", str(classes), str(consumer_src)], check=True)
            consumer_jar = root / "consumer.jar"
            with zipfile.ZipFile(consumer_jar, "w") as zf:
                zf.write(classes / "com/acme/Consumer.class", "com/acme/Consumer.class")
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete", "target_jdk": "17",
                "by_coord": {"com.acme:consumer": {"jar_path": str(consumer_jar)}},
            })

            scan = tracer._scan_packaged_runtime_dependencies_for_api({
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank", "api_signature": "(String)",
                "symbol_kind": "method",
            }, graph)

        self.assertEqual(scan["status"], "hit")
        self.assertEqual(scan["hits"][0]["consumer_method"], "check")
        self.assertEqual(scan["hits"][0]["evidence_type"], "bytecode_reflection_method_invocation")

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_method_reference_bytecode_is_visible_to_upgrade_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src/org/apache/commons/lang/StringUtils.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package org.apache.commons.lang; public class StringUtils { "
                "public static boolean isBlank(String value) { return value == null; } }",
                encoding="utf-8",
            )
            target_classes = root / "target-classes"
            target_classes.mkdir()
            subprocess.run(["javac", "-d", str(target_classes), str(target_src)], check=True)
            target_jar = root / "commons-lang.jar"
            with zipfile.ZipFile(target_jar, "w") as zf:
                zf.write(
                    target_classes / "org/apache/commons/lang/StringUtils.class",
                    "org/apache/commons/lang/StringUtils.class",
                )

            consumer_src = root / "consumer-src/com/acme/Consumer.java"
            consumer_src.parent.mkdir(parents=True)
            consumer_src.write_text(
                "package com.acme; import java.util.function.Predicate; "
                "import org.apache.commons.lang.StringUtils; public class Consumer { "
                "public boolean check(String value) { Predicate<String> p = StringUtils::isBlank; "
                "return p.test(value); } }",
                encoding="utf-8",
            )
            consumer_classes = root / "consumer-classes"
            consumer_classes.mkdir()
            subprocess.run([
                "javac", "-cp", str(target_jar), "-d", str(consumer_classes), str(consumer_src)
            ], check=True)
            consumer_jar = root / "consumer.jar"
            with zipfile.ZipFile(consumer_jar, "w") as zf:
                zf.write(consumer_classes / "com/acme/Consumer.class", "com/acme/Consumer.class")

            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete", "target_jdk": "17",
                "by_coord": {"com.acme:consumer": {"jar_path": str(consumer_jar)}},
            })
            scan = tracer._scan_packaged_runtime_dependencies_for_api({
                "coord": "commons-lang:commons-lang",
                "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                "api_simple": "isBlank", "api_signature": "(String)",
                "symbol_kind": "method",
            }, graph)

        self.assertEqual(scan["status"], "hit")
        self.assertEqual(scan["hits"][0]["consumer_method"], "check")
        self.assertEqual(scan["hits"][0]["evidence_type"], "bytecode_invokedynamic_method_reference")

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_direct_method_bytecode_uses_constant_pool_fast_path_without_javap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_src = root / "target-src/org/apache/commons/lang/StringUtils.java"
            target_src.parent.mkdir(parents=True)
            target_src.write_text(
                "package org.apache.commons.lang; public class StringUtils { "
                "public static boolean isBlank(String value) { return value == null; } }",
                encoding="utf-8",
            )
            target_classes = root / "target-classes"
            target_classes.mkdir()
            subprocess.run(["javac", "-d", str(target_classes), str(target_src)], check=True)
            target_jar = root / "commons-lang.jar"
            with zipfile.ZipFile(target_jar, "w") as zf:
                zf.write(
                    target_classes / "org/apache/commons/lang/StringUtils.class",
                    "org/apache/commons/lang/StringUtils.class",
                )

            consumer_src = root / "consumer-src/com/acme/Consumer.java"
            consumer_src.parent.mkdir(parents=True)
            consumer_src.write_text(
                "package com.acme; import org.apache.commons.lang.StringUtils; "
                "public class Consumer { public boolean check(String value) { "
                "return StringUtils.isBlank(value); } }",
                encoding="utf-8",
            )
            consumer_classes = root / "consumer-classes"
            consumer_classes.mkdir()
            subprocess.run([
                "javac", "-cp", str(target_jar), "-d", str(consumer_classes), str(consumer_src)
            ], check=True)
            consumer_jar = root / "consumer.jar"
            with zipfile.ZipFile(consumer_jar, "w") as zf:
                zf.write(consumer_classes / "com/acme/Consumer.class", "com/acme/Consumer.class")

            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete", "target_jdk": "17",
                "by_coord": {"com.acme:consumer": {"jar_path": str(consumer_jar)}},
            })
            with patch.object(tracer, "run_cmd", side_effect=AssertionError("javap should not be called")):
                scan = tracer._scan_packaged_runtime_dependencies_for_api({
                    "coord": "commons-lang:commons-lang",
                    "api_name": "org.apache.commons.lang.StringUtils.isBlank",
                    "api_simple": "isBlank", "api_signature": "(String)",
                    "symbol_kind": "method",
                }, graph)

        self.assertEqual(scan["status"], "hit")
        self.assertEqual(scan["hits"][0]["consumer_method"], "<unknown>")
        self.assertEqual(scan["hits"][0]["evidence_type"], "bytecode_constant_pool_method_reference")

    def test_javap_parser_attributes_throws_and_static_initializer_correctly(self):
        parsed = tracer._parse_javap_bytecode_references("""
public class com.acme.Consumer {
  public boolean check(java.lang.String) throws java.lang.Exception;
    descriptor: (Ljava/lang/String;)Z
    Code:
       0: invokestatic #7 // Method com/vendor/Client.check:(Ljava/lang/String;)Z
  static {};
    descriptor: ()V
    Code:
       0: invokestatic #8 // Method com/vendor/Client.bootstrap:()V
}
""", "com.acme.Consumer")

        consumers = {(item["name"], item["consumer_method"]) for item in parsed["method_refs"]}
        self.assertIn(("check", "check"), consumers)
        self.assertIn(("bootstrap", "<clinit>"), consumers)

    def test_javap_parser_resolves_lambda_method_handle_target(self):
        parsed = tracer._parse_javap_bytecode_references("""
public class com.acme.Consumer {
  public boolean check(java.lang.String);
    descriptor: (Ljava/lang/String;)Z
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:test:()Ljava/util/function/Predicate;
}
BootstrapMethods:
  0: #33 REF_invokeStatic java/lang/invoke/LambdaMetafactory.metafactory:(Ljava/lang/invoke/MethodHandles$Lookup;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #26 REF_invokeStatic org/apache/commons/lang/StringUtils.isBlank:(Ljava/lang/String;)Z
""", "com.acme.Consumer")

        target = next(item for item in parsed["method_refs"] if item["name"] == "isBlank")
        self.assertEqual(target["owner"], "org.apache.commons.lang.StringUtils")
        self.assertEqual(target["consumer_method"], "check")
        self.assertEqual(target["reference_kind"], "invokedynamic_method_handle")

    def test_multi_release_jar_uses_effective_target_jdk_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMulti-Release: true\n")
                zf.writestr("com/acme/Consumer.class", b"clean")
                zf.writestr(
                    "META-INF/versions/11/com/acme/Consumer.class",
                    b"com/vendor/Client removedMethod",
                )
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete", "target_jdk": "17",
                "by_coord": {"com.acme:consumer": {"jar_path": str(jar_path)}},
            })
            api_row = {
                "coord": "com.vendor:client", "api_name": "com.vendor.Client.removedMethod",
                "api_simple": "removedMethod", "api_signature": "()", "symbol_kind": "method",
            }
            refs = {"method_refs": [{
                "owner": "com.vendor.Client", "name": "removedMethod", "signature": "()",
                "consumer_method": "use", "consumer_signature": "()",
            }], "field_refs": [], "class_refs": []}
            with patch.object(
                tracer, "_load_runtime_dependency_class_references", return_value=refs
            ) as loader:
                scan = tracer._scan_packaged_runtime_dependencies_for_api(api_row, graph)

        self.assertEqual(scan["status"], "hit")
        self.assertEqual(scan["hits"][0]["multi_release_version"], 11)
        self.assertEqual(loader.call_args.kwargs["multi_release_version"], 11)

    def test_multi_release_miss_is_unavailable_when_target_jdk_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMulti-Release: true\n")
                zf.writestr("com/acme/Consumer.class", b"clean")
                zf.writestr("META-INF/versions/11/com/acme/Consumer.class", b"clean")
            graph = SimpleNamespace(runtime_dependency_catalog={
                "status": "complete",
                "by_coord": {"com.acme:consumer": {"jar_path": str(jar_path)}},
            })
            scan = tracer._scan_packaged_runtime_dependencies_for_api({
                "coord": "com.vendor:client", "api_name": "com.vendor.Client.removedMethod",
                "api_simple": "removedMethod", "api_signature": "()", "symbol_kind": "method",
            }, graph)

        self.assertEqual(scan["status"], "unavailable")
        self.assertEqual(scan["reason"], "MULTI_RELEASE_TARGET_JDK_UNKNOWN")

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
