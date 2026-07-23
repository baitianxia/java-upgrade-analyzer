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
from step5_artifact_fact_store import Step5ArtifactFactStore
from tests.retained_artifact_test_support import retain_current_artifact_contract


class ArtifactBytecodeCatalogTest(unittest.TestCase):
    def test_reactor_recovery_uses_only_explicitly_active_profile_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><modules><module>library</module></modules>
                <profiles><profile><id>boot</id><modules><module>application</module>
                </modules></profile></profiles></project>""",
                encoding="utf-8",
            )
            for module, dependencies in (
                ("library", ""),
                ("application", "<dependencies><dependency><groupId>com.acme</groupId>"
                 "<artifactId>library</artifactId></dependency></dependencies>"),
            ):
                module_root = root / module
                (module_root / "src/main/java").mkdir(parents=True)
                (module_root / "pom.xml").write_text(
                    "<project><modelVersion>4.0.0</modelVersion>"
                    f"<groupId>com.acme</groupId><artifactId>{module}</artifactId>"
                    f"<version>1</version>{dependencies}</project>",
                    encoding="utf-8",
                )
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/maven/com.acme/application/pom.properties",
                    "groupId=com.acme\nartifactId=application\nversion=1\n",
                )

            inactive = step5._recover_reactor_module_coords(
                [root], {"com.acme:application"}
            )
            active = step5._recover_reactor_module_coords(
                [root], {"com.acme:application"},
                active_profiles={"boot"},
            )

        self.assertEqual(inactive, set())
        self.assertEqual(active, {"com.acme:application", "com.acme:library"})

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_shared_inventory_preserves_exact_packaged_scan_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src/com/acme/Consumer.java"
            target = root / "src/com/vendor/Target.java"
            source.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            source.write_text(
                'package com.acme; import com.vendor.Target; public class Consumer {'
                ' public Object call() throws Exception {'
                ' return Class.forName("com.vendor.Target")'
                '.getDeclaredMethod("removed").invoke(null); }'
                ' public int direct() { Target.removed(); return Target.VALUE; }'
                ' public Target create() { return new Target(); }'
                ' public Runnable reference() { return Target::removed; }}',
                encoding="utf-8",
            )
            target.write_text(
                'package com.vendor; public class Target {'
                ' public static int VALUE = 7; public static void removed() {} }',
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(classes), str(source), str(target)], check=True,
            )
            jar_path = root / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.write(classes / "com/acme/Consumer.class", "com/acme/Consumer.class")
            entry = {
                "coord": "com.acme:consumer", "jar_path": str(jar_path),
                "sha256": hashlib.sha256(jar_path.read_bytes()).hexdigest(),
                "application_owned": False,
            }
            api_row = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed", "api_signature": "()",
                "symbol_kind": "method",
            }
            legacy_catalog = {
                "status": "complete", "target_jdk": "17", "entries": [dict(entry)],
            }
            shared_catalog = {
                "status": "complete", "target_jdk": "17", "entries": [dict(entry)],
            }
            legacy = tracer._scan_packaged_runtime_dependencies_for_api(
                api_row, SimpleNamespace(runtime_dependency_catalog=legacy_catalog),
            )
            shared_graph = SimpleNamespace(
                runtime_dependency_catalog=shared_catalog,
                step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(shared_catalog),
                report_dir=str(root / "report"),
            )
            shared = tracer._scan_packaged_runtime_dependencies_for_api(
                api_row, shared_graph,
            )
            exhaustive_legacy_catalog = {
                "status": "complete", "target_jdk": "17", "entries": [dict(entry)],
            }
            exhaustive_shared_catalog = {
                "status": "complete", "target_jdk": "17", "entries": [dict(entry)],
            }
            exhaustive_legacy = tracer._collect_exhaustive_runtime_reference_edges(
                SimpleNamespace(runtime_dependency_catalog=exhaustive_legacy_catalog)
            )
            exhaustive_shared = tracer._collect_exhaustive_runtime_reference_edges(
                SimpleNamespace(
                    runtime_dependency_catalog=exhaustive_shared_catalog,
                    step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(
                        exhaustive_shared_catalog
                    ),
                )
            )

        self.assertEqual(legacy, shared)
        self.assertEqual(exhaustive_legacy, exhaustive_shared)

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_large_api_batch_member_index_fast_path_preserves_exact_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src/com/acme/Consumer.java"
            target = root / "src/com/vendor/Target.java"
            source.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            source.write_text(
                'package com.acme; import com.vendor.Target; public class Consumer {'
                ' public Object call() throws Exception {'
                ' return Class.forName("com.vendor.Target")'
                '.getDeclaredMethod("removed").invoke(null); }'
                ' public int direct() { Target.removed(); return Target.VALUE; }'
                ' public Target create() { return new Target(); }'
                ' public Runnable reference() { return Target::removed; }}',
                encoding="utf-8",
            )
            target.write_text(
                'package com.vendor; public class Target {'
                ' public static int VALUE = 7; public static void removed() {} }',
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(classes), str(source), str(target)], check=True,
            )
            jar_path = root / "consumer.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.write(classes / "com/acme/Consumer.class", "com/acme/Consumer.class")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entries = [{
                "coord": f"com.acme:consumer-{index}",
                "jar_path": str(jar_path), "sha256": digest,
                "application_owned": False,
            } for index in range(8)]
            api_definitions = [{
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.removed",
                "api_simple": "removed", "api_signature": "()", "symbol_kind": "method",
            }, {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target.VALUE",
                "api_simple": "VALUE", "api_signature": "", "symbol_kind": "field",
            }, {
                "coord": "com.vendor:target", "api_name": "com.vendor.Target",
                "api_simple": "Target", "api_signature": "", "symbol_kind": "class",
            }]
            api_rows = [dict(api_definitions[index % 3]) for index in range(32)]
            legacy_catalog = {
                "status": "complete", "target_jdk": "17",
                "entries": [dict(entry) for entry in entries],
            }
            shared_catalog = {
                "status": "complete", "target_jdk": "17",
                "entries": [dict(entry) for entry in entries],
            }
            legacy_graph = SimpleNamespace(runtime_dependency_catalog=legacy_catalog)
            shared_graph = SimpleNamespace(
                runtime_dependency_catalog=shared_catalog,
                step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(shared_catalog),
                report_dir=str(root / "report"),
            )
            legacy = tracer._build_packaged_runtime_dependency_scan_cache(
                api_rows, legacy_graph,
            )
            with patch.object(
                tracer, "_get_runtime_dependency_member_candidate_index",
                wraps=tracer._get_runtime_dependency_member_candidate_index,
            ) as unified_index:
                shared = tracer._build_packaged_runtime_dependency_scan_cache(
                    api_rows, shared_graph,
                )
            self.assertEqual(unified_index.call_count, 1)
            cache_path = (
                root / "report/.runtime/cache/s5_runtime_member_candidate_index.json"
            )
            self.assertTrue(cache_path.is_file())
            reload_catalog = {
                "status": "complete", "target_jdk": "17",
                "entries": [dict(entry) for entry in entries],
            }
            reload_graph = SimpleNamespace(
                runtime_dependency_catalog=reload_catalog,
                report_dir=str(root / "report"),
            )
            with patch.object(
                tracer, "_build_runtime_dependency_member_candidate_index",
                side_effect=AssertionError("persistent member index should be reused"),
            ):
                reloaded_index = tracer._get_runtime_dependency_member_candidate_index(
                    reload_graph, reload_catalog["entries"], "17",
                )
            self.assertEqual(
                tracer._runtime_member_index_serializable(
                    shared_graph._runtime_dependency_member_candidate_index
                ),
                tracer._runtime_member_index_serializable(reloaded_index),
            )

            stable_jar_path = root / "stable-consumer.jar"
            shutil.copyfile(jar_path, stable_jar_path)
            mutation_entries = [dict(entry) for entry in entries]
            mutation_entries[0].update({
                "jar_path": str(stable_jar_path),
                "sha256": hashlib.sha256(stable_jar_path.read_bytes()).hexdigest(),
            })
            mutation_catalog = {
                "status": "complete", "target_jdk": "17",
                "entries": mutation_entries,
            }
            mutation_graph = SimpleNamespace(
                runtime_dependency_catalog=mutation_catalog,
                step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(
                    mutation_catalog
                ),
                report_dir=str(root / "mutation-report"),
            )
            original_write = tracer._write_runtime_member_index_cache

            def mutating_write(path, identity, index):
                original_write(path, identity, index)
                with zipfile.ZipFile(jar_path, "a") as archive:
                    archive.writestr("mutation-marker", b"changed")

            with patch.object(
                tracer, "_write_runtime_member_index_cache",
                side_effect=mutating_write,
            ):
                mutation_results = tracer._build_packaged_runtime_dependency_scan_cache(
                    api_rows, mutation_graph,
                )
            mutation_index = mutation_graph._runtime_dependency_member_candidate_index
            mutation_cache_path = (
                root / "mutation-report/.runtime/cache/"
                "s5_runtime_member_candidate_index.json"
            )

            size_catalog = {
                "status": "complete", "target_jdk": "17",
                "entries": [{
                    **entry,
                    "jar_path": str(stable_jar_path),
                    "sha256": hashlib.sha256(stable_jar_path.read_bytes()).hexdigest(),
                } for entry in entries],
            }
            size_graph = SimpleNamespace(
                runtime_dependency_catalog=size_catalog,
                step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(
                    size_catalog
                ),
                report_dir=str(root / "size-report"),
            )
            with patch.object(
                tracer.os.path, "getsize",
                side_effect=FileNotFoundError("artifact disappeared"),
            ):
                size_results = tracer._build_packaged_runtime_dependency_scan_cache(
                    api_rows, size_graph,
                )

        self.assertEqual(legacy, shared)
        self.assertEqual(
            {"hit"}, {result["status"] for result in shared.values()},
        )
        self.assertEqual(
            1,
            shared_graph._step5_perf_stats["bytecode_scan"]["member_index_fast_path"],
        )
        self.assertFalse(mutation_index["complete"])
        self.assertFalse(mutation_cache_path.exists())
        self.assertEqual(
            {"unavailable"},
            {result["status"] for result in mutation_results.values()},
        )
        self.assertEqual(
            {"BYTECODE_SCAN_INPUT_CHANGED"},
            {result["reason"] for result in mutation_results.values()},
        )
        self.assertEqual(
            {"unavailable"},
            {result["status"] for result in size_results.values()},
        )
        self.assertEqual(
            {"BYTECODE_SCAN_INPUT_CHANGED"},
            {result["reason"] for result in size_results.values()},
        )

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_large_api_fast_path_preserves_class_literal_and_loader_reflection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            literal = root / "src/com/acme/LiteralConsumer.java"
            loader = root / "src/com/acme/LoaderConsumer.java"
            target = root / "src/com/vendor/Target.java"
            literal.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            literal.write_text(
                'package com.acme; import com.vendor.Target; public class LiteralConsumer {'
                ' public Object method() throws Exception {'
                ' return Target.class.getDeclaredMethod("removed").invoke(null); }'
                ' public Object field() throws Exception {'
                ' return Target.class.getDeclaredField("VALUE").get(null); }'
                ' public Object construct() throws Exception {'
                ' return Target.class.getDeclaredConstructor().newInstance(); }}',
                encoding="utf-8",
            )
            loader.write_text(
                'package com.acme; public class LoaderConsumer {'
                ' public Object load() throws Exception {'
                ' return ClassLoader.getSystemClassLoader()'
                '.loadClass("com.vendor.Target"); }}',
                encoding="utf-8",
            )
            target.write_text(
                'package com.vendor; public class Target {'
                ' public static int VALUE = 7; public Target() {}'
                ' public static void removed() {} }',
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(classes), str(literal), str(loader), str(target)],
                check=True,
            )
            literal_jar = root / "literal-consumer.jar"
            with zipfile.ZipFile(literal_jar, "w") as archive:
                archive.write(
                    classes / "com/acme/LiteralConsumer.class",
                    "com/acme/LiteralConsumer.class",
                )
            loader_jar = root / "loader-consumer.jar"
            with zipfile.ZipFile(loader_jar, "w") as archive:
                archive.write(
                    classes / "com/acme/LoaderConsumer.class",
                    "com/acme/LoaderConsumer.class",
                )
            literal_definitions = [{
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.removed",
                "api_simple": "removed", "api_signature": "()",
                "symbol_kind": "method",
            }, {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.VALUE",
                "api_simple": "VALUE", "api_signature": "",
                "symbol_kind": "field",
            }, {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target.Target",
                "api_simple": "Target", "api_signature": "()",
                "symbol_kind": "constructor",
            }]
            class_definition = {
                "coord": "com.vendor:target",
                "api_name": "com.vendor.Target",
                "api_simple": "Target", "api_signature": "",
                "symbol_kind": "class",
            }

            def scan_pair(jar_path, definitions, label):
                digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
                entries = [{
                    "coord": f"com.acme:{label}-{index}",
                    "jar_path": str(jar_path), "sha256": digest,
                    "application_owned": False,
                } for index in range(8)]
                api_rows = [
                    dict(definitions[index % len(definitions)])
                    for index in range(32)
                ]
                legacy_catalog = {
                    "status": "complete", "target_jdk": "17",
                    "entries": [dict(entry) for entry in entries],
                }
                indexed_catalog = {
                    "status": "complete", "target_jdk": "17",
                    "entries": [dict(entry) for entry in entries],
                }
                legacy = tracer._build_packaged_runtime_dependency_scan_cache(
                    api_rows, SimpleNamespace(runtime_dependency_catalog=legacy_catalog),
                )
                indexed_graph = SimpleNamespace(
                    runtime_dependency_catalog=indexed_catalog,
                    step5_artifact_fact_store=Step5ArtifactFactStore.from_catalog(
                        indexed_catalog
                    ),
                    report_dir=str(root / f"{label}-indexed-report"),
                )
                indexed = tracer._build_packaged_runtime_dependency_scan_cache(
                    api_rows, indexed_graph,
                )
                return legacy, indexed

            literal_legacy, literal_indexed = scan_pair(
                literal_jar, literal_definitions, "literal",
            )
            loader_legacy, loader_indexed = scan_pair(
                loader_jar, [class_definition], "loader",
            )

        self.assertEqual(
            {"hit"}, {result["status"] for result in literal_legacy.values()},
        )
        self.assertEqual(literal_legacy, literal_indexed)
        self.assertEqual(
            {"miss"}, {result["status"] for result in loader_legacy.values()},
        )
        self.assertEqual(
            {
                key: (value.get("status"), value.get("reason"), value.get("hits"))
                for key, value in loader_legacy.items()
            },
            {
                key: (value.get("status"), value.get("reason"), value.get("hits"))
                for key, value in loader_indexed.items()
            },
        )

    def test_application_owned_nested_module_requires_a_business_entry_path(self):
        result = tracer._new_trace_draft({
            "api_name": "com.vendor.Legacy.removed", "api_simple": "removed",
            "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
            "coord": "com.vendor:legacy", "severity": "P0", "confirmed": "true",
            "source": "japicmp", "analysis_scope": "api",
        })
        hit = {
            "coord": "com.acme:library", "application_owned": True,
            "ownership_evidence": {
                "authority": "reactor_coordinate_and_final_artifact_entry",
                "reactor_coord": "com.acme:library",
                "artifact_entry": "BOOT-INF/lib/library.jar",
                "final_artifact_sha256": "a" * 64,
            },
            "jar_path": "/artifact/BOOT-INF/lib/library.jar",
            "class_fqcn": "com.acme.library.Job", "consumer_method": "run",
            "consumer_signature": "()", "target_display": "com.vendor.Legacy.removed()",
            "evidence_type": "bytecode_method_invocation",
        }

        tracer._build_packaged_dependency_hit_result(result, [hit])
        built = tracer._finalize_trace_draft(result)

        self.assertEqual(built.analysis_status, "uncertain")
        self.assertIsNone(built.is_reachable)
        self.assertFalse(built.path_details[0]["business_reachable"])
        self.assertEqual(built.path_details[0]["business_entry"], "")
        self.assertEqual(
            built.path_details[0]["stop_reason"], "BUSINESS_ENTRY_NOT_CONFIRMED"
        )

    def test_fat_jar_reactor_library_is_marked_application_owned_from_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            nested = root / "library.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("com/acme/library/Helper.class", b"fixture")
            application = root / "application.jar"
            with zipfile.ZipFile(application, "w") as archive:
                archive.writestr("BOOT-INF/lib/library-1.0.jar", nested.read_bytes())
                archive.writestr("BOOT-INF/classes/com/acme/App.class", b"fixture")
            dependency_dir = report / "evidence/dependencies"
            dependency_dir.mkdir(parents=True)
            with (dependency_dir / "deps_current_resolved.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["coord", "version", "scope", "lib_entry", "resolution_status"],
                )
                writer.writeheader()
                writer.writerow({
                    "coord": "com.acme:library", "version": "1.0", "scope": "runtime",
                    "lib_entry": "BOOT-INF/lib/library-1.0.jar", "resolution_status": "resolved",
                })
            (dependency_dir / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current", "artifact_path": str(application),
                    "artifact_sha256": hashlib.sha256(application.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")
            retain_current_artifact_contract(report, application)
            state = report / ".runtime/state/main_state.json"
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                "step5": {"input": {"project_scope": {
                    "included_module_coords": ["com.acme:application", "com.acme:library"]
                }}}
            }), encoding="utf-8")

            catalog = step5.build_runtime_dependency_catalog(str(report))

        self.assertTrue(catalog["by_coord"]["com.acme:library"]["application_owned"])
        self.assertEqual(catalog["metrics"]["application_owned_nested_dependencies"], 1)

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
        self.assertEqual(scan["hits"][0]["consumer_method"], "check")
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
                "opcode_family": "invokevirtual", "instruction_offset": 7,
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

            deps_dir = report / "evidence" / "dependencies"
            deps_dir.mkdir(parents=True)
            with (deps_dir / "deps_current_resolved.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["coord", "version", "scope", "lib_entry"])
                writer.writeheader()
                writer.writerow({
                    "coord": "com.acme:consumer", "version": "1.0", "scope": "packaged",
                    "lib_entry": "BOOT-INF/lib/consumer-1.0.jar",
                })
            (deps_dir / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current", "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")
            retain_current_artifact_contract(report, artifact)

            with patch.object(
                step5,
                "_find_maven_jar",
                side_effect=AssertionError("must not use m2"),
                create=True,
            ):
                catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertEqual(catalog["status"], "complete")
            item = catalog["by_coord"]["com.acme:consumer"]
            self.assertEqual(item["evidence_source"], "current_final_artifact")
            self.assertEqual(Path(item["jar_path"]).read_bytes(), nested_bytes)
            business_jar = Path(catalog["by_coord"]["__business__"]["jar_path"])
            with zipfile.ZipFile(business_jar) as zf:
                self.assertEqual(zf.read("com/example/App.class"), b"business-bytecode")

    def test_catalog_rejects_local_maven_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            fallback = report / "fallback.jar"
            with zipfile.ZipFile(fallback, "w") as zf:
                zf.writestr("com/acme/Consumer.class", b"x")
            deps_dir = report / "evidence" / "dependencies"
            deps_dir.mkdir(parents=True)
            with (deps_dir / "deps_current_resolved.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["coord", "version", "scope", "lib_entry"])
                writer.writeheader()
                writer.writerow({"coord": "com.acme:consumer", "version": "1", "scope": "packaged", "lib_entry": ""})

            with patch.object(
                step5,
                "_find_maven_jar",
                side_effect=AssertionError("不得读取本地 Maven 仓库"),
                create=True,
            ):
                catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertEqual(catalog["status"], "insufficient")
            self.assertIn("runtime_dependency_jars_missing", catalog["reason_codes"])
            self.assertNotIn("local_maven_fallback_used", catalog["reason_codes"])


if __name__ == "__main__":
    unittest.main()
