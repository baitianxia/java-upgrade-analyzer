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


if __name__ == "__main__":
    unittest.main()
