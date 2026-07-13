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
    collect_business_bytecode_edges,
    merge_business_bytecode_edges,
    method_descriptor_signature,
    parse_classfile_calls,
    parse_javap_calls,
)


class BusinessBytecodeGraphTest(unittest.TestCase):
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
