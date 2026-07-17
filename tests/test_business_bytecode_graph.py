import sys
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from business_bytecode_graph import (
    collect_business_bytecode_batch,
    collect_business_bytecode_edges,
    merge_business_bytecode_edges,
    method_descriptor_signature,
    parse_classfile_calls,
    parse_javap_calls,
)


class BusinessBytecodeGraphTest(unittest.TestCase):
    def test_business_bytecode_batch_interns_repeated_immutable_edge_strings(self):
        import business_bytecode_graph as module

        digest_a = "".join(["a" for _ in range(64)])
        digest_b = (" " + digest_a).strip()
        path_a = "".join(["/tmp/app.jar", "!/fixture/Consumer.class"])
        path_b = (" " + path_a).strip()
        base = {
            "caller_owner": "fixture.Consumer",
            "caller_name": "run",
            "caller_signature": "()",
            "callee_key": "java.lang.System.nanoTime()",
            "callee_simple_key": "method:nanoTime()",
            "evidence_type": "bytecode_method_invocation",
            "parser": "classfile",
            "evidence_source": "current_final_artifact",
            "content": "invokestatic java.lang.System.nanoTime",
        }
        evidence = [
            {**base, "artifact_sha256": digest_a, "class_file": path_a, "instruction_offset": 1},
            {**base, "artifact_sha256": digest_b, "class_file": path_b, "instruction_offset": 4},
        ]

        batch = module._business_bytecode_batch(
            evidence,
            {"artifact_sha256": digest_a, "classes_scanned": 1},
            strict_final_artifact=True,
        )

        self.assertEqual(len(batch.edges), 2)
        self.assertIsNot(batch.edges[0], batch.edges[1])
        self.assertIs(
            batch.edges[0].provenance.artifact_sha256,
            batch.edges[1].provenance.artifact_sha256,
        )
        self.assertIs(
            batch.edges[0].provenance.artifact_path,
            batch.edges[1].provenance.artifact_path,
        )
        self.assertIs(batch.edges[0].caller_symbol, batch.edges[1].caller_symbol)
        self.assertIs(batch.edges[0].callee_symbol, batch.edges[1].callee_symbol)

    def test_collect_business_bytecode_batch_preserves_method_constructor_field_and_reflection_identities(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            original = module.parse_classfile_calls
            module.parse_classfile_calls = lambda _data, _name: [
                {"caller_owner": "com.acme.Service", "caller_name": "run", "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()", "callee_simple_key": "method:call()", "evidence_type": "bytecode_method_invocation", "line": 11},
                {"caller_owner": "com.acme.Service", "caller_name": "run", "caller_signature": "()", "callee_key": "com.vendor.Dto.Dto()", "callee_simple_key": "method:Dto()", "evidence_type": "bytecode_constructor_invocation", "line": 12},
                {"caller_owner": "com.acme.Service", "caller_name": "run", "caller_signature": "()", "callee_key": "com.vendor.Flags.ENABLED", "callee_simple_key": "field:ENABLED", "evidence_type": "bytecode_field_access", "line": 13},
                {"caller_owner": "com.acme.Service", "caller_name": "run", "caller_signature": "()", "callee_key": "com.vendor.Legacy.reflect()", "callee_simple_key": "method:reflect()", "evidence_type": "bytecode_reflection_method_invocation", "line": 14},
            ]
            try:
                batch = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "a" * 64,
                }}}, None)
            finally:
                module.parse_classfile_calls = original

        self.assertEqual(batch.collector, "business_bytecode")
        self.assertEqual(
            [(edge.caller_symbol, edge.callee_symbol, edge.edge_kind) for edge in batch.edges],
            [
                ("com.acme.Service.run()", "com.vendor.Legacy.call()", "bytecode_method_invocation"),
                ("com.acme.Service.run()", "com.vendor.Dto.Dto()", "bytecode_constructor_invocation"),
                ("com.acme.Service.run()", "com.vendor.Flags.ENABLED", "bytecode_field_access"),
                ("com.acme.Service.run()", "com.vendor.Legacy.reflect()", "bytecode_reflection_method_invocation"),
            ],
        )
        self.assertTrue(all(
            edge.provenance.artifact_sha256 == "a" * 64 for edge in batch.edges
        ))

    def test_collect_business_bytecode_batch_reports_parse_failure(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            original_parse, original_run = module.parse_classfile_calls, module.run_cmd
            module.parse_classfile_calls = lambda _data, _name: None
            module.run_cmd = lambda *_args, **_kwargs: ("", "bad class", 1)
            try:
                failed = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "b" * 64,
                }}}, None)
            finally:
                module.parse_classfile_calls, module.run_cmd = original_parse, original_run

        self.assertEqual(failed.edges, ())
        self.assertEqual(failed.failures[0].reason_code, "BYTECODE_PARSE_FAILED")

    def test_collect_business_bytecode_batch_records_unresolved_caller_as_failure(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            original = module.parse_classfile_calls
            module.parse_classfile_calls = lambda _data, _name: [{
                "caller_owner": "com.acme.Service", "caller_name": "",
                "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
                "callee_simple_key": "method:call()",
                "evidence_type": "bytecode_method_invocation",
            }]
            try:
                batch = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "c" * 64,
                }}}, None)
            finally:
                module.parse_classfile_calls = original

        self.assertEqual(batch.edges, ())
        self.assertEqual(batch.failures[0].reason_code, "BYTECODE_CALLER_UNRESOLVED")
        self.assertTrue(batch.failures[0].blocking)

    def test_collect_business_bytecode_batch_does_not_treat_constant_pool_class_refs_as_call_edges(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Marker.class", b"not-a-real-class")
            original = module.parse_classfile_calls
            module.parse_classfile_calls = lambda _data, _name: [{
                "caller_owner": "com.acme.Marker",
                "caller_name": "Marker",
                "caller_signature": "",
                "callee_key": "com.vendor.LegacyType",
                "callee_simple_key": "class:LegacyType",
                "evidence_type": "bytecode_class_reference",
                "content": "classfile constant-pool/signature/annotation reference",
            }]
            try:
                batch = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "d" * 64,
                }}}, None)
            finally:
                module.parse_classfile_calls = original

        self.assertEqual(batch.edges, ())
        self.assertEqual(batch.failures, ())
        self.assertEqual(dict(batch.metrics)["non_executable_class_references"], 1)

    def test_collect_business_bytecode_batch_rejects_invalid_sha_with_stable_failure(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            original = module.parse_classfile_calls
            module.parse_classfile_calls = lambda _data, _name: [{
                "caller_owner": "com.acme.Service", "caller_name": "run",
                "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
                "callee_simple_key": "method:call()",
                "evidence_type": "bytecode_method_invocation",
            }]
            try:
                batch = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "not-a-sha",
                }}}, None)
            finally:
                module.parse_classfile_calls = original

        self.assertEqual(batch.edges, ())
        self.assertEqual(
            [failure.reason_code for failure in batch.failures],
            ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"],
        )
        self.assertEqual(
            dict(batch.metrics)["failures"],
            ("CURRENT_FINAL_ARTIFACT_SHA_INVALID",),
        )

    def test_collect_business_bytecode_batch_records_javap_parser_across_cache_hit(self):
        import business_bytecode_graph as module

        javap = """
  public void run();
    descriptor: ()V
    Code:
       1: invokestatic #7 // Method com/vendor/Legacy.call:()V
"""
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            cache_path = Path(tmp) / "bytecode-index.json"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"reflection-class")
            catalog = {"by_coord": {"__business__": {
                "jar_path": str(jar_path), "sha256": "d" * 64,
            }}}
            original_parse, original_run = module.parse_classfile_calls, module.run_cmd
            module.parse_classfile_calls = lambda _data, _name: None
            module.run_cmd = lambda *_args, **_kwargs: (javap, "", 0)
            try:
                first = collect_business_bytecode_batch([], catalog, str(cache_path))
                module.parse_classfile_calls = lambda *_args: (_ for _ in ()).throw(
                    AssertionError("cache miss")
                )
                second = collect_business_bytecode_batch([], catalog, str(cache_path))
            finally:
                module.parse_classfile_calls, module.run_cmd = original_parse, original_run

        self.assertTrue(first.edges)
        self.assertTrue(dict(second.metrics)["cache_hit"])
        self.assertTrue(all(edge.provenance.parser == "javap" for edge in first.edges))
        self.assertTrue(all(edge.provenance.parser == "javap" for edge in second.edges))

    def test_collect_business_bytecode_batch_streams_validated_v3_cache_without_read_text(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            cache_path = Path(tmp) / "bytecode-index.json"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            catalog = {"by_coord": {"__business__": {
                "jar_path": str(jar_path), "sha256": "f" * 64,
            }}}
            original_parse, original_read_text = module.parse_classfile_calls, Path.read_text
            module.parse_classfile_calls = lambda _data, _name: [{
                "caller_owner": "com.acme.Service", "caller_name": "run",
                "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
                "callee_simple_key": "method:call()",
                "evidence_type": "bytecode_method_invocation",
                "instruction_offset": 7,
            }]
            try:
                first = collect_business_bytecode_batch([], catalog, str(cache_path))
                with cache_path.open("rb") as cache_file:
                    header = cache_file.readline()
                self.assertIn(b"java-upgrade-analyzer.bytecode-index.v3", header)
                module.parse_classfile_calls = lambda *_args: (_ for _ in ()).throw(
                    AssertionError("validated cache should avoid artifact rescan")
                )
                Path.read_text = lambda path, *args, **kwargs: (
                    (_ for _ in ()).throw(AssertionError("cache must be streamed"))
                    if path == cache_path else original_read_text(path, *args, **kwargs)
                )
                second = collect_business_bytecode_batch([], catalog, str(cache_path))
            finally:
                module.parse_classfile_calls, Path.read_text = original_parse, original_read_text

        self.assertEqual(first.edges, second.edges)
        self.assertTrue(dict(second.metrics)["cache_hit"])

    def test_collect_business_bytecode_batch_rejects_tampered_v3_cache_and_rescans(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            cache_path = Path(tmp) / "bytecode-index.json"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            catalog = {"by_coord": {"__business__": {
                "jar_path": str(jar_path), "sha256": "1" * 64,
            }}}
            calls = []
            original_parse = module.parse_classfile_calls

            def parse(_data, _name):
                calls.append(_name)
                return [{
                    "caller_owner": "com.acme.Service", "caller_name": "run",
                    "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
                    "callee_simple_key": "method:call()",
                    "evidence_type": "bytecode_method_invocation",
                    "instruction_offset": 7,
                }]

            module.parse_classfile_calls = parse
            try:
                collect_business_bytecode_batch([], catalog, str(cache_path))
                tampered = cache_path.read_text(encoding="utf-8").replace(
                    "com.vendor.Legacy.call()", "com.vendor.Legacy.fail()", 1
                )
                cache_path.write_text(tampered, encoding="utf-8")
                second = collect_business_bytecode_batch([], catalog, str(cache_path))
            finally:
                module.parse_classfile_calls = original_parse

        self.assertEqual(calls, ["com.acme.Service", "com.acme.Service"])
        self.assertFalse(dict(second.metrics).get("cache_hit", False))
        self.assertEqual(second.edges[0].callee_symbol, "com.vendor.Legacy.call()")

    def test_business_bytecode_batch_can_release_consumed_raw_edges(self):
        import business_bytecode_graph as module

        evidence = [{
            "caller_owner": "com.acme.Service", "caller_name": "run",
            "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
            "callee_simple_key": "method:call()",
            "evidence_type": "bytecode_method_invocation",
            "artifact_sha256": "2" * 64,
            "class_file": "/tmp/application.jar!/com/acme/Service.class",
            "parser": "classfile",
        }]

        batch = module._business_bytecode_batch(
            evidence,
            {"artifact_sha256": "2" * 64},
            strict_final_artifact=True,
            release_consumed=True,
        )

        self.assertEqual(len(batch.edges), 1)
        self.assertEqual(evidence, [None])

    def test_collect_business_bytecode_batch_keeps_evidence_when_cache_write_fails(self):
        import business_bytecode_graph as module

        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "application.jar"
            cache_path = Path(tmp) / "bytecode-index.json"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/acme/Service.class", b"not-a-real-class")
            original_parse = module.parse_classfile_calls
            original_write = module._write_business_bytecode_cache
            module.parse_classfile_calls = lambda _data, _name: [{
                "caller_owner": "com.acme.Service", "caller_name": "run",
                "caller_signature": "()", "callee_key": "com.vendor.Legacy.call()",
                "callee_simple_key": "method:call()",
                "evidence_type": "bytecode_method_invocation",
            }]
            module._write_business_bytecode_cache = (
                lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cache denied"))
            )
            try:
                batch = collect_business_bytecode_batch([], {"by_coord": {"__business__": {
                    "jar_path": str(jar_path), "sha256": "e" * 64,
                }}}, str(cache_path))
            finally:
                module.parse_classfile_calls = original_parse
                module._write_business_bytecode_cache = original_write

        self.assertEqual(len(batch.edges), 1)
        self.assertEqual(batch.failures, ())
        self.assertEqual(batch.concerns[0].reason_code, "BYTECODE_CACHE_WRITE_FAILED")
        self.assertTrue(dict(batch.metrics)["cache_write_failed"])
    def test_collect_business_bytecode_rejects_target_classes_without_final_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            classes = project / "module-a" / "target" / "classes" / "app"
            classes.mkdir(parents=True)
            (classes / "Stale.class").write_bytes(b"stale-unpackaged-bytecode")

            evidence, metrics = collect_business_bytecode_edges(
                [{"root": str(project), "owner_type": "business"}],
                artifact_catalog={"by_coord": {}},
            )

        self.assertEqual(evidence, [])
        self.assertEqual(metrics["classes_scanned"], 0)
        self.assertEqual(metrics["evidence_source"], "unavailable")
        self.assertIn("current_final_artifact_required", metrics["failures"])

    def test_descriptor_preserves_arrays_and_object_types(self):
        self.assertEqual(
            method_descriptor_signature("(Ljava/lang/String;[I[[Lcom/acme/Dto;)V"),
            "(java.lang.String,int[],com.acme.Dto[][])",
        )

    def test_parse_javap_calls_emits_method_constructor_and_field_edges(self):
        text = """
  public void execute();
    descriptor: ()V
    Code:
       1: invokevirtual #7 // Method com/acme/Client.call:(Ljava/lang/String;)V
       2: invokespecial #8 // Method com/acme/Dto."<init>":()V
       3: getstatic #9 // Field com/acme/Flags.ENABLED:Z
"""
        edges = parse_javap_calls(text, "com.acme.Service")
        by_type = {edge["evidence_type"]: edge for edge in edges}
        self.assertEqual(by_type["bytecode_method_invocation"]["callee_key"], "com.acme.Client.call(java.lang.String)")
        self.assertEqual(by_type["bytecode_constructor_invocation"]["callee_key"], "com.acme.Dto.Dto()")
        self.assertEqual(by_type["bytecode_field_access"]["callee_key"], "com.acme.Flags.ENABLED")
        self.assertTrue(all(edge["caller_name"] == "execute" for edge in edges))

    def test_parse_javap_calls_retains_offsets_for_repeated_physical_calls(self):
        text = """
  public void execute();
    descriptor: ()V
    Code:
       1: invokestatic #7 // Method com/acme/Target.hit:()V
       4: invokestatic #7 // Method com/acme/Target.hit:()V
"""

        calls = [
            edge for edge in parse_javap_calls(text, "com.acme.Service")
            if edge["callee_key"] == "com.acme.Target.hit()"
        ]

        self.assertEqual([edge["instruction_offset"] for edge in calls], [1, 4])

    def test_parse_javap_verbose_emits_type_and_invokedynamic_edges(self):
        text = """
  #12 = Class #13 // com/acme/AnnotationType
  public void execute();
    descriptor: (Lcom/acme/Input;)V
    Code:
       1: checkcast #7 // class com/acme/Target
       2: invokedynamic #8, 0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
"""
        edges = parse_javap_calls(text, "com.acme.Service")
        kinds = {edge["evidence_type"] for edge in edges}
        self.assertIn("bytecode_type_reference", kinds)
        self.assertIn("bytecode_invokedynamic", kinds)
        self.assertIn("bytecode_class_reference", kinds)

    def test_parse_classfile_calls_emits_core_edges_without_javap(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Client.java").write_text(
                """
package com.acme;
public class Client {
  public static String NAME = "x";
  public void call(String value) {}
}
""",
                encoding="utf-8",
            )
            (src / "Dto.java").write_text(
                "package com.acme; public class Dto {}\n",
                encoding="utf-8",
            )
            (src / "Service.java").write_text(
                """
package com.acme;
public class Service {
  public void execute(Client client, Object raw) {
    client.call(Client.NAME);
    new Dto();
    Client casted = (Client) raw;
    Runnable r = () -> client.call("lambda");
    r.run();
  }
}
""",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True,
                capture_output=True,
            )

            data = (out / "com" / "acme" / "Service.class").read_bytes()
            edges = parse_classfile_calls(data, "com.acme.Service")

        self.assertIsNotNone(edges)
        by_type = {}
        for edge in edges:
            by_type.setdefault(edge["evidence_type"], set()).add(edge["callee_key"])
        self.assertIn("com.acme.Client.call(java.lang.String)", by_type["bytecode_method_invocation"])
        self.assertIn("com.acme.Client.NAME", by_type["bytecode_field_access"])
        self.assertIn("com.acme.Dto.Dto()", by_type["bytecode_constructor_invocation"])
        self.assertIn("com.acme.Client", by_type["bytecode_type_reference"])
        self.assertIn("bytecode_invokedynamic", by_type)
        self.assertTrue(
            any(key.startswith("com.acme.Service.lambda$execute$0")
                for key in by_type["bytecode_invokedynamic_method_reference"])
        )

    def test_collected_physical_calls_retain_distinct_jvm_instruction_offsets(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "com" / "acme"
            source.mkdir(parents=True)
            (source / "Target.java").write_text(
                "package com.acme; public class Target { public static void hit() {} }\n",
                encoding="utf-8",
            )
            (source / "Service.java").write_text(
                "package com.acme; public class Service { public void run() { "
                "Target.hit(); Target.hit(); } }\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(classes)] + [str(path) for path in source.glob("*.java")],
                check=True,
                capture_output=True,
            )
            jar_path = root / "application.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                for class_file in classes.rglob("*.class"):
                    archive.write(class_file, class_file.relative_to(classes).as_posix())

            batch = collect_business_bytecode_batch([], {
                "by_coord": {"__business__": {
                    "jar_path": str(jar_path),
                    "sha256": "a" * 64,
                }},
            }, None)

        calls = [
            edge for edge in batch.edges
            if edge.callee_symbol == "com.acme.Target.hit()"
        ]
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            len({edge.provenance.instruction_offset for edge in calls}),
            2,
        )
        self.assertTrue(all(edge.provenance.instruction_offset >= 0 for edge in calls))

    def test_parse_classfile_calls_resolves_method_reference_bootstrap_target(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Target.java").write_text(
                "package com.acme; public class Target { public static String map(String v) { return v; } }\n",
                encoding="utf-8",
            )
            (src / "Service.java").write_text(
                "package com.acme; import java.util.function.Function; "
                "public class Service { Function<String,String> mapper() { return Target::map; } }\n",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True, capture_output=True,
            )
            edges = parse_classfile_calls(
                (out / "com/acme/Service.class").read_bytes(), "com.acme.Service"
            )

        self.assertTrue(any(
            edge.get("evidence_type") == "bytecode_invokedynamic_method_reference"
            and edge.get("callee_key") == "com.acme.Target.map(java.lang.String)"
            for edge in edges
        ))

    def test_try_with_resources_emits_implicit_close_edge_from_bytecode(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Resource.java").write_text(
                "package com.acme; public class Resource implements AutoCloseable { "
                "public void close() {} }",
                encoding="utf-8",
            )
            (src / "Service.java").write_text(
                "package com.acme; public class Service { void run() throws Exception { "
                "try (Resource resource = new Resource()) { } } }",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True,
                capture_output=True,
            )

            edges = parse_classfile_calls(
                (out / "com/acme/Service.class").read_bytes(),
                "com.acme.Service",
            )

        self.assertTrue(any(
            edge.get("caller_name") == "run"
            and edge.get("callee_key") == "com.acme.Resource.close()"
            and edge.get("evidence_type") == "bytecode_method_invocation"
            for edge in edges
        ))

    def test_generic_bridge_keeps_connectivity_without_duplicate_target_edge(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Target.java").write_text(
                "package com.acme; public class Target { static String changed() { return \"x\"; } }",
                encoding="utf-8",
            )
            (src / "Base.java").write_text(
                "package com.acme; interface Base<T> { T get(); }",
                encoding="utf-8",
            )
            (src / "Impl.java").write_text(
                "package com.acme; class Impl implements Base<String> { "
                "public String get() { return Target.changed(); } }",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True,
                capture_output=True,
            )

            edges = parse_classfile_calls(
                (out / "com/acme/Impl.class").read_bytes(),
                "com.acme.Impl",
            )

        target_edges = [edge for edge in edges if edge.get("callee_key") == "com.acme.Target.changed()"]
        self.assertEqual(len(target_edges), 1)
        self.assertTrue(any(
            edge.get("caller_descriptor") == "()Ljava/lang/Object;"
            and edge.get("callee_key") == "com.acme.Impl.get()"
            for edge in edges
        ))

    def test_parse_classfile_calls_keeps_calls_after_dense_and_sparse_switches(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Target.java").write_text(
                "package com.acme; public class Target { public static void hit() {} }\n",
                encoding="utf-8",
            )
            (src / "Switches.java").write_text(
                """
package com.acme;
public class Switches {
  public void dense(int value) {
    switch (value) { case 1: break; case 2: break; case 3: break; default: break; }
    Target.hit();
  }
  public void sparse(int value) {
    switch (value) { case 1: break; case 100: break; default: break; }
    Target.hit();
  }
}
""",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True,
                capture_output=True,
            )
            edges = parse_classfile_calls(
                (out / "com/acme/Switches.class").read_bytes(), "com.acme.Switches"
            )

        callers = {
            edge["caller_name"] for edge in edges
            if edge.get("callee_key") == "com.acme.Target.hit()"
        }
        self.assertEqual(callers, {"dense", "sparse"})

    def test_synthetic_generic_bridge_does_not_duplicate_target_invocation(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Box.java").write_text(
                "package com.acme; interface Box<T> { T get(); }\n", encoding="utf-8"
            )
            (src / "Target.java").write_text(
                "package com.acme; final class Target { static String removed() { return \"\"; } }\n",
                encoding="utf-8",
            )
            (src / "StringBox.java").write_text(
                "package com.acme; final class StringBox implements Box<String> { "
                "public String get() { return Target.removed(); } }\n",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True, capture_output=True,
            )
            edges = parse_classfile_calls(
                (out / "com/acme/StringBox.class").read_bytes(), "com.acme.StringBox"
            )

        target_edges = [
            edge for edge in edges
            if edge.get("callee_key") == "com.acme.Target.removed()"
        ]
        self.assertEqual(len(target_edges), 1)
        self.assertEqual(target_edges[0]["caller_name"], "get")

    def test_parse_classfile_calls_emits_catch_type_reference_on_handling_method(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "OldException.java").write_text(
                "package com.acme; class OldException extends RuntimeException {}\n",
                encoding="utf-8",
            )
            (src / "Service.java").write_text(
                "package com.acme; class Service { void run() { "
                "try { System.nanoTime(); } catch (OldException error) {} } }\n",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True, capture_output=True,
            )
            edges = parse_classfile_calls(
                (out / "com/acme/Service.class").read_bytes(), "com.acme.Service"
            )

        self.assertTrue(any(
            edge["caller_name"] == "run"
            and edge["callee_key"] == "com.acme.OldException"
            and edge["evidence_type"] == "bytecode_exception_handler_reference"
            for edge in edges
        ))

    def test_parse_classfile_calls_falls_back_for_reflection_markers(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Reflective.java").write_text(
                """
package com.acme;
public class Reflective {
  public void execute(String name) throws Exception {
    Class.forName("com.acme.Target").getMethod("call", String.class).invoke(null, name);
  }
}
""",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out), str(src / "Reflective.java")],
                check=True,
                capture_output=True,
            )
            data = (out / "com" / "acme" / "Reflective.class").read_bytes()

        self.assertIsNone(parse_classfile_calls(data, "com.acme.Reflective"))

    def test_collect_business_bytecode_edges_uses_classfile_fast_path_for_jar(self):
        if not shutil.which("javac"):
            self.skipTest("javac not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "com" / "acme"
            src.mkdir(parents=True)
            (src / "Client.java").write_text(
                "package com.acme; public class Client { public void call(String value) {} }\n",
                encoding="utf-8",
            )
            (src / "Service.java").write_text(
                """
package com.acme;
public class Service {
  public void execute(Client client) { client.call("x"); }
}
""",
                encoding="utf-8",
            )
            out = root / "classes"
            out.mkdir()
            subprocess.run(
                ["javac", "-d", str(out)] + [str(path) for path in src.glob("*.java")],
                check=True,
                capture_output=True,
            )
            jar_path = root / "app.jar"
            with zipfile.ZipFile(jar_path, "w") as zf:
                for class_file in out.rglob("*.class"):
                    zf.write(class_file, class_file.relative_to(out).as_posix())

            evidence, metrics = collect_business_bytecode_edges(
                [],
                max_classes=100,
                artifact_catalog={
                    "by_coord": {
                        "__business__": {
                            "jar_path": str(jar_path),
                            "sha256": "fixture-sha",
                        }
                    }
                },
            )

        self.assertGreater(metrics["classfile_fast_path_classes"], 0)
        self.assertEqual(metrics["javap_fallback_classes"], 0)
        self.assertTrue(
            any(edge["callee_key"] == "com.acme.Client.call(java.lang.String)" for edge in evidence)
        )

    def test_merge_business_bytecode_edges_resolves_symbol_ids_to_method_defs(self):
        method = SimpleNamespace(
            symbol_id="m1",
            qualified_key="com.acme.Service.execute()",
            owner_coord="BUSINESS",
            module="app",
        )
        graph = SimpleNamespace(
            methods_by_id={"m1": method},
            methods_by_qualified={"com.acme.Service.execute": ["m1"]},
            lookup_keys_by_symbol={"m1": ["com.acme.Service.execute()"]},
            reverse_edges={},
        )
        evidence = [{
            "caller_owner": "com.acme.Service",
            "caller_name": "execute",
            "caller_signature": "()",
            "callee_key": "com.acme.Client.call(java.lang.String)",
            "callee_simple_key": "method:call(java.lang.String)",
            "evidence_type": "bytecode_method_invocation",
            "evidence_source": "current_final_artifact",
            "artifact_sha256": "fixture-sha256",
            "class_file": "/tmp/Service.class",
            "line": 12,
            "content": "invokevirtual Client.call",
        }]

        metrics = merge_business_bytecode_edges(graph, evidence)

        self.assertEqual(metrics, {"merged_edges": 1, "skipped_unresolved_callers": 0})
        edges = graph.reverse_edges["com.acme.Client.call(java.lang.String)"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].caller_symbol_id, "m1")
        self.assertEqual(edges[0].caller_qualified_key, "com.acme.Service.execute()")
        self.assertEqual(edges[0].evidence_source, "current_final_artifact")
        self.assertEqual(edges[0].artifact_sha256, "fixture-sha256")


if __name__ == "__main__":
    unittest.main()
