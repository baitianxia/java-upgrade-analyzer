import hashlib
import io
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import edge_truth  # noqa: E402
import final_artifact_edge_oracle as oracle  # noqa: E402


JDK_TOOLS = shutil.which("javac") and shutil.which("jar") and shutil.which("javap")


def _write_source(root: Path, relative_path: str, text: str) -> Path:
    source = root / relative_path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(text, encoding="utf-8")
    return source


def _compile(classes: Path, sources: list[Path], classpath: Path | None = None) -> None:
    command = ["javac", "-d", str(classes)]
    if classpath is not None:
        command.extend(["-classpath", str(classpath)])
    command.extend(str(source) for source in sources)
    subprocess.run(command, check=True, capture_output=True, text=True)


@unittest.skipUnless(JDK_TOOLS, "JDK tools required")
class FinalArtifactEdgeOracleTest(unittest.TestCase):
    def _compile_single_class(self, root: Path, method_name: str) -> Path:
        source = _write_source(
            root / "src",
            "fixture/Versioned.java",
            "package fixture; public class Versioned { public String " + method_name
            + "() { return String.valueOf(1); } }",
        )
        classes = root / "classes"
        classes.mkdir()
        _compile(classes, [source])
        return classes / "fixture/Versioned.class"

    def _build_artifact(self, root: Path) -> Path:
        dependency_source = _write_source(
            root / "dependency-src",
            "fixture/Dependency.java",
            """
            package fixture;
            public class Dependency {
              public static int staticValue;
              public int value;
              public Dependency() {}
              public void virtualCall() {}
              public static void staticCall() {}
            }
            """,
        )
        dependency_classes = root / "dependency-classes"
        dependency_classes.mkdir()
        _compile(dependency_classes, [dependency_source])
        dependency_jar = root / "dependency.jar"
        with zipfile.ZipFile(dependency_jar, "w") as archive:
            archive.write(
                dependency_classes / "fixture/Dependency.class",
                "fixture/Dependency.class",
            )

        worker_source = _write_source(
            root / "app-src",
            "fixture/Worker.java",
            "package fixture; public interface Worker { void run(); }",
        )
        app_source = _write_source(
            root / "app-src",
            "fixture/App.java",
            """
            package fixture;
            public class App {
              private Dependency dependency = new Dependency();
              public void use(Worker worker) {
                dependency.virtualCall();
                worker.run();
                Dependency.staticCall();
                new Dependency();
                int instance = dependency.value;
                dependency.value = instance;
                int statik = Dependency.staticValue;
                Dependency.staticValue = statik;
                Runnable callback = () -> Dependency.staticCall();
                callback.run();
              }
              public void throwing() throws java.io.IOException {
                Dependency.staticCall();
              }
              static {
                Dependency.staticCall();
              }
            }
            """,
        )
        app_classes = root / "app-classes"
        app_classes.mkdir()
        _compile(app_classes, [worker_source, app_source], dependency_jar)

        artifact = root / "app.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.write(app_classes / "fixture/App.class", "BOOT-INF/classes/fixture/App.class")
            archive.write(app_classes / "fixture/Worker.class", "BOOT-INF/classes/fixture/Worker.class")
            archive.write(dependency_jar, "BOOT-INF/lib/dependency.jar")
        return artifact

    def test_scans_each_jvm_instruction_family_from_final_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = self._build_artifact(Path(temp_dir))
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["artifact_sha256"], digest)
        self.assertEqual(result["class_count"], 3)
        app_edges = [
            row for row in result["edges"]
            if row["caller_owner"] == "fixture.App" and row["caller_member"] == "use"
        ]
        edge_rows = [
            (
                row["caller_descriptor"], row["callee_owner"], row["callee_member"],
                row["callee_descriptor"], row["opcode_family"], row["artifact_entry"],
                row["instruction_offset"],
            )
            for row in app_edges
        ]
        lambda_descriptor = (
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
            "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
            "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
            "Ljava/lang/invoke/CallSite;"
        )
        expected = [
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 1),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "<init>", "()V", "invokespecial", "BOOT-INF/classes/fixture/App.class", 20),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 13),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticValue", "I", "getstatic", "BOOT-INF/classes/fixture/App.class", 40),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "staticValue", "I", "putstatic", "BOOT-INF/classes/fixture/App.class", 45),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "value", "I", "getfield", "BOOT-INF/classes/fixture/App.class", 28),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "value", "I", "putfield", "BOOT-INF/classes/fixture/App.class", 37),
            ("(Lfixture/Worker;)V", "fixture.Dependency", "virtualCall", "()V", "invokevirtual", "BOOT-INF/classes/fixture/App.class", 4),
            ("(Lfixture/Worker;)V", "fixture.Worker", "run", "()V", "invokeinterface", "BOOT-INF/classes/fixture/App.class", 8),
            ("(Lfixture/Worker;)V", "java.lang.Runnable", "run", "()V", "invokeinterface", "BOOT-INF/classes/fixture/App.class", 57),
            ("(Lfixture/Worker;)V", "java.lang.invoke.LambdaMetafactory", "metafactory", lambda_descriptor, "invokedynamic", "BOOT-INF/classes/fixture/App.class", 48),
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 25),
            ("(Lfixture/Worker;)V", "fixture.App", "dependency", "Lfixture/Dependency;", "getfield", "BOOT-INF/classes/fixture/App.class", 33),
        ]
        self.assertListEqual(edge_rows, sorted(expected))
        self.assertTrue(all(row["authority"] == "jdk-javap" for row in app_edges))
        self.assertTrue(all(row["authority_version"] for row in app_edges))
        self.assertTrue(all(row["procedure"] for row in app_edges))
        lifecycle_rows = sorted(
            (
                row["caller_member"], row["caller_descriptor"], row["callee_owner"],
                row["callee_member"], row["callee_descriptor"], row["opcode_family"],
                row["artifact_entry"], row["instruction_offset"],
            )
            for row in result["edges"]
            if row["caller_owner"] == "fixture.App" and row["caller_member"] in {"throwing", "<clinit>"}
        )
        self.assertListEqual(lifecycle_rows, [
            ("<clinit>", "()V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 0),
            ("throwing", "()V", "fixture.Dependency", "staticCall", "()V", "invokestatic", "BOOT-INF/classes/fixture/App.class", 0),
        ])

    def test_invalid_header_cannot_reuse_the_previous_member_context(self):
        output = """
public class fixture.Leak {
  public void first();
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method fixture/Dependency.staticCall:()V
  public void broken(;
    descriptor: ()V
    Code:
       0: invokestatic #7 // Method fixture/Dependency.staticCall:()V
}
"""
        rows, failures = oracle._parse_javap_output(output, "a" * 64, "fixture/Leak.class", "24.0.2")

        self.assertEqual([row["caller_member"] for row in rows], ["first"])
        self.assertTrue(any("without a valid header" in failure for failure in failures))

    def test_unresolved_invokedynamic_is_a_parse_failure(self):
        output = """
public class fixture.Dynamic {
  public void use();
    descriptor: ()V
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
}
"""
        rows, failures = oracle._parse_javap_output(output, "a" * 64, "fixture/Dynamic.class", "24.0.2")

        self.assertEqual(rows, [])
        self.assertTrue(any("unresolved invokedynamic bootstrap" in failure for failure in failures))

    def test_duplicate_nested_class_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            class_file = self._compile_single_class(root, "duplicate")
            nested = root / "duplicate.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.write(class_file, "fixture/Versioned.class")
                archive.write(class_file, "fixture/Versioned.class")
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/duplicate.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 0)
        self.assertTrue(any("duplicate logical class entry" in failure for failure in result["failures"]))

    def test_multi_release_nested_jar_uses_highest_entry_supported_by_javap(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            selected_class = self._compile_single_class(root / "selected", "selected")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nmUlTi-ReLeAsE: TrUe\n\n")
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(selected_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(row["caller_member"] == "selected" for row in result["edges"]))
        self.assertTrue(all(
            row["artifact_entry"] == f"BOOT-INF/lib/versioned.jar!/{versioned_entry}"
            for row in result["edges"]
        ))

    def test_multi_release_entries_without_manifest_opt_in_use_base_class(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(root / "ignored", "ignored")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(ignored_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(row["caller_member"] == "base" for row in result["edges"]))
        self.assertFalse(any(row["caller_member"] == "ignored" for row in result["edges"]))
        self.assertTrue(all(
            row["artifact_entry"] == "BOOT-INF/lib/versioned.jar!/fixture/Versioned.class"
            for row in result["edges"]
        ))

    def test_named_manifest_section_cannot_activate_multi_release(self):
        version_text = subprocess.run(
            ["javap", "-version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        target_major = int(re.search(r"(?:1\.)?(\d+)", version_text).group(1))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_class = self._compile_single_class(root / "base", "base")
            ignored_class = self._compile_single_class(root / "ignored", "ignored")
            nested = root / "versioned.jar"
            versioned_entry = f"META-INF/versions/{target_major}/fixture/Versioned.class"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\n\r\nName: fixture/Versioned.class\r\nMulti-Release: true\r\n\r\n",
                )
                archive.write(base_class, "fixture/Versioned.class")
                archive.write(ignored_class, versioned_entry)
            artifact = root / "outer.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(nested, "BOOT-INF/lib/versioned.jar")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertTrue(any(row["caller_member"] == "base" for row in result["edges"]))
        self.assertFalse(any(row["caller_member"] == "ignored" for row in result["edges"]))

    def test_malformed_class_is_recorded_as_an_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "broken.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/fixture/Broken.class", b"not-a-class")
            result = oracle.scan_final_artifact(artifact)

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 1)
        self.assertEqual(len(result["failures"]), 1)
        self.assertIn("BOOT-INF/classes/fixture/Broken.class", result["failures"][0])

    def test_scans_package_classes_in_a_plain_executable_jar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = _write_source(
                root / "src",
                "fixture/Standalone.java",
                "package fixture; public class Standalone { public String text() { return String.valueOf(1); } }",
            )
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, [source])
            artifact = root / "standalone.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(classes / "fixture/Standalone.class", "fixture/Standalone.class")
            result = oracle.scan_final_artifact(artifact)

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["class_count"], 1)
        self.assertTrue(any(
            row["caller_owner"] == "fixture.Standalone" and row["callee_owner"] == "java.lang.String"
            for row in result["edges"]
        ))

    def test_missing_javap_is_recorded_as_an_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = self._build_artifact(Path(temp_dir))
            result = oracle.scan_final_artifact(artifact, javap="missing-javap-command")

        self.assertFalse(result["complete"])
        self.assertEqual(result["class_count"], 3)
        self.assertEqual(len(result["failures"]), 3)
        self.assertTrue(all("missing-javap-command" in failure for failure in result["failures"]))


if __name__ == "__main__":
    unittest.main()
