import hashlib
import io
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import edge_truth  # noqa: E402
import final_artifact_edge_oracle as oracle  # noqa: E402


JDK_TOOLS = shutil.which("javac") and shutil.which("jar") and shutil.which("javap")


def _fake_artifact(path: Path, class_entries: list[str], marker: bytes = b"class") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for index, entry in enumerate(class_entries):
            archive.writestr(entry, marker + str(index).encode("ascii"))
    return path


def _fake_parse_result(entry, artifact_sha256, *, failure: str = "") -> dict:
    member = Path(entry.artifact_entry).stem.lower()
    row = oracle._edge_row(
        artifact_sha256,
        entry.artifact_entry,
        "21.0.1",
        "fixture.Caller",
        member,
        "()V",
        ("fixture.Dependency", member, "()V"),
        "invokestatic",
        0,
    )
    return {
        "rows": [row],
        "failures": [f"{entry.artifact_entry}: {failure}"] if failure else [],
        "completed": True,
        "parsed": True,
    }


class FinalArtifactEdgeOraclePerformanceTest(unittest.TestCase):
    def setUp(self):
        oracle.clear_immutable_oracle_cache()

    def test_boot_archive_ignores_duplicate_root_class_entries(self):
        """Only BOOT-INF/classes is on a Spring Boot archive's application classpath."""
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "boot.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/App.class", b"root-copy")
                archive.writestr("BOOT-INF/classes/sample/App.class", b"runtime-copy")
                archive.writestr("BOOT-INF/classes/sample/OnlyRuntime.class", b"runtime-only")

            with tempfile.TemporaryDirectory() as extracted:
                entries, failures = oracle._extract_packaged_classes(
                    artifact.read_bytes(), Path(extracted), target_major=21
                )

        self.assertEqual(failures, [])
        self.assertEqual(
            [entry.artifact_entry for entry in entries],
            [
                "BOOT-INF/classes/sample/App.class",
                "BOOT-INF/classes/sample/OnlyRuntime.class",
            ],
        )

    def test_sequential_concurrent_and_cached_scans_are_edge_equivalent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "fixture.jar",
                ["fixture/C.class", "fixture/A.class", "fixture/B.class"],
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                sequential = oracle.scan_final_artifact(artifact, max_workers=1)
                oracle.clear_immutable_oracle_cache()
                concurrent = oracle.scan_final_artifact(artifact, max_workers=3)
                cached = oracle.scan_final_artifact(artifact, max_workers=3)

        self.assertEqual(sequential["edges"], concurrent["edges"])
        self.assertEqual(sequential["failures"], concurrent["failures"])
        self.assertEqual(concurrent["edges"], cached["edges"])
        self.assertEqual(concurrent["failures"], cached["failures"])
        self.assertEqual(sequential["parsed_class_count"], 3)
        self.assertEqual(concurrent["parsed_class_count"], 3)
        self.assertEqual(cached["parsed_class_count"], 0)
        self.assertEqual(cached["cached_class_count"], 3)
        self.assertEqual(cached["cache_hits"], 1)

    def test_concurrent_scan_retains_every_class_parse_failure_in_entry_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entries = [f"fixture/Bad{index}.class" for index in range(4)]
            artifact = _fake_artifact(Path(temp_dir) / "broken.jar", entries)

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                time.sleep(0.01 if entry.artifact_entry.endswith("0.class") else 0.001)
                return _fake_parse_result(entry, artifact_sha256, failure="synthetic parse failure")

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=4)

        self.assertFalse(result["complete"])
        self.assertEqual(result["parsed_class_count"], 4)
        self.assertEqual(result["parse_failure_count"], 4)
        self.assertEqual(
            result["failures"],
            [f"{entry}: synthetic parse failure" for entry in entries],
        )

    def test_explicit_worker_count_is_capped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "many.jar",
                [f"fixture/Class{index}.class" for index in range(oracle.MAX_JAVAP_WORKERS + 2)],
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=999)

        self.assertEqual(result["worker_count"], oracle.MAX_JAVAP_WORKERS)

    def test_selected_target_frontier_uses_requested_bounded_workers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "targeted.jar",
                [f"fixture/Caller{index}.class" for index in range(4)],
                marker=b"fixture/Targetchanged()V",
            )

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(
                    artifact,
                    max_workers=4,
                    selected_targets=[{
                        "owner": "fixture.Target",
                        "member": "changed",
                        "descriptor": "()V",
                    }],
                )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["parsed_class_count"], 4)
        self.assertEqual(result["worker_count"], 4)

    def test_immutable_cache_does_not_cross_artifact_sha(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_artifact = _fake_artifact(root / "first.jar", ["fixture/A.class"], b"first")
            second_artifact = _fake_artifact(root / "second.jar", ["fixture/A.class"], b"second")
            parsed_shas = []

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                parsed_shas.append(artifact_sha256)
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                first = oracle.scan_final_artifact(first_artifact, max_workers=1)
                second = oracle.scan_final_artifact(second_artifact, max_workers=1)

        self.assertNotEqual(first["artifact_sha256"], second["artifact_sha256"])
        self.assertEqual(parsed_shas, [first["artifact_sha256"], second["artifact_sha256"]])
        self.assertEqual(first["cache_hits"], 0)
        self.assertEqual(second["cache_hits"], 0)
        self.assertTrue(all(row["artifact_sha256"] == first["artifact_sha256"] for row in first["edges"]))
        self.assertTrue(all(row["artifact_sha256"] == second["artifact_sha256"] for row in second["edges"]))

    def test_missing_javap_command_does_not_reuse_another_command_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "fixture.jar", ["fixture/A.class"])

            first = oracle.scan_final_artifact(artifact, javap="missing-javap-first-command")
            second = oracle.scan_final_artifact(artifact, javap="missing-javap-second-command")

        self.assertFalse(first["complete"])
        self.assertFalse(second["complete"])
        self.assertEqual(first["cache_hits"], 0)
        self.assertEqual(second["cache_hits"], 0)
        self.assertTrue(all("missing-javap-first-command" in failure for failure in first["failures"]))
        self.assertTrue(all("missing-javap-second-command" in failure for failure in second["failures"]))
        self.assertFalse(any("missing-javap-first-command" in failure for failure in second["failures"]))

    def test_time_budget_cancels_concurrent_scan_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(
                Path(temp_dir) / "slow.jar",
                [f"fixture/Slow{index}.class" for index in range(4)],
            )

            def parse_group(entries, artifact_sha256, _javap, _version, cancellation_event, deadline):
                while not cancellation_event.is_set() and time.perf_counter() < deadline:
                    time.sleep(0.005)
                return [
                    {"rows": [], "failures": [], "completed": False, "parsed": False}
                    for _entry in entries
                ]

            started_at = time.perf_counter()
            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_group_with_javap", side_effect=parse_group
            ):
                result = oracle.scan_final_artifact(
                    artifact, max_workers=2, time_budget_seconds=0.05
                )
            elapsed = time.perf_counter() - started_at

        self.assertLess(elapsed, 1.0)
        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["interrupted"])
        self.assertEqual(result["cache_hits"], 0)
        self.assertTrue(any("oracle_time_budget_exceeded" in failure for failure in result["failures"]))

    def test_hung_javap_version_probe_returns_a_structured_incomplete_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "version-hang.jar", ["fixture/A.class"])
            with patch.object(
                oracle.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["javap", "-version"], 0.05),
            ) as mocked_run:
                result = oracle.scan_final_artifact(artifact, time_budget_seconds=0.05)

        self.assertFalse(result["complete"])
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["interrupted"])
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["failures"], ["oracle_javap_version_timeout"])
        timeout = mocked_run.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 0.05)

    def test_version_probe_exception_returns_a_non_cacheable_incomplete_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "version-error.jar", ["fixture/A.class"])
            with patch.object(
                oracle, "_javap_version", side_effect=ValueError("synthetic version failure")
            ) as probe:
                first = oracle.scan_final_artifact(artifact)
                second = oracle.scan_final_artifact(artifact)

        for result in (first, second):
            self.assertFalse(result["complete"])
            self.assertFalse(result["timed_out"])
            self.assertFalse(result["interrupted"])
            self.assertEqual(result["cache_hits"], 0)
            self.assertEqual(result["cache_misses"], 1)
            self.assertEqual(
                result["failures"],
                ["oracle_javap_version_failed:ValueError: synthetic version failure"],
            )
        self.assertEqual(probe.call_count, 2)

    def test_concurrent_worker_exception_is_class_specific_and_does_not_stop_peers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            entries = ["fixture/A.class", "fixture/B.class", "fixture/C.class"]
            artifact = _fake_artifact(Path(temp_dir) / "worker-error.jar", entries)

            def parse_entry(entry, artifact_sha256, *_args, **_kwargs):
                if entry.artifact_entry == "fixture/B.class":
                    raise ValueError("synthetic worker failure")
                return _fake_parse_result(entry, artifact_sha256)

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=parse_entry
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=3)

        self.assertFalse(result["complete"])
        self.assertEqual(result["completed_class_count"], 3)
        self.assertEqual(result["parsed_class_count"], 2)
        self.assertEqual(result["parse_failure_count"], 1)
        self.assertEqual(
            result["failures"],
            ["fixture/B.class: oracle worker failed: ValueError: synthetic worker failure"],
        )
        self.assertEqual(
            [row["artifact_entry"] for row in result["edges"]],
            ["fixture/A.class", "fixture/C.class"],
        )

    def test_interrupted_worker_returns_incomplete_result_without_propagating(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = _fake_artifact(Path(temp_dir) / "interrupted.jar", ["fixture/A.class"])

            def interrupt(*_args, **_kwargs):
                raise KeyboardInterrupt()

            with patch.object(oracle, "_javap_version", return_value="21.0.1"), patch.object(
                oracle, "_parse_entry_with_javap", side_effect=interrupt
            ):
                result = oracle.scan_final_artifact(artifact, max_workers=1)

        self.assertFalse(result["complete"])
        self.assertFalse(result["timed_out"])
        self.assertTrue(result["interrupted"])
        self.assertIn("oracle_interrupted", result["failures"])


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

    def test_selected_api_scan_exhausts_reverse_callers_without_parsing_unrelated_classes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            sources = [
                _write_source(
                    source_root,
                    "fixture/Target.java",
                    "package fixture; public class Target { public void changed() {} }",
                ),
                _write_source(
                    source_root,
                    "fixture/Bridge.java",
                    "package fixture; public class Bridge { public void call(Target target) { target.changed(); } }",
                ),
                _write_source(
                    source_root,
                    "fixture/App.java",
                    "package fixture; public class App { public void run(Bridge bridge, Target target) { bridge.call(target); } }",
                ),
                _write_source(
                    source_root,
                    "fixture/Unrelated.java",
                    "package fixture; public class Unrelated { public String text() { return String.valueOf(1); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file,
                        "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                    )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Target",
                    "member": "changed",
                    "descriptor": "()V",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        self.assertEqual(result["inventory_class_count"], 4)
        self.assertLess(result["parsed_class_count"], result["inventory_class_count"])
        relations = {
            (
                row["caller_owner"], row["caller_member"],
                row["callee_owner"], row["callee_member"],
            )
            for row in result["edges"]
        }
        self.assertIn(("fixture.Bridge", "call", "fixture.Target", "changed"), relations)
        self.assertIn(("fixture.App", "run", "fixture.Bridge", "call"), relations)
        self.assertFalse(any(row["caller_owner"] == "fixture.Unrelated" for row in result["edges"]))

    def test_selected_api_scan_reuses_prior_class_edges_for_intra_class_reverse_hops(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_root = root / "src"
            sources = [
                _write_source(
                    source_root, "fixture/Target.java",
                    "package fixture; public class Target { public static void changed() {} }",
                ),
                _write_source(
                    source_root, "fixture/Bridge.java",
                    "package fixture; public class Bridge { public static void top() { middle(); } public static void middle() { Target.changed(); } }",
                ),
                _write_source(
                    source_root, "fixture/App.java",
                    "package fixture; public class App { public void run() { Bridge.top(); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for class_file in sorted(classes.rglob("*.class")):
                    archive.write(
                        class_file,
                        "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                    )

            result = oracle.scan_final_artifact(
                artifact,
                selected_targets=[{
                    "owner": "fixture.Target", "member": "changed", "descriptor": "()V",
                }],
            )

        self.assertTrue(result["complete"], result["failures"])
        relations = {
            (row["caller_owner"], row["caller_member"], row["callee_owner"], row["callee_member"])
            for row in result["edges"]
        }
        self.assertIn(("fixture.Bridge", "middle", "fixture.Target", "changed"), relations)
        self.assertIn(("fixture.Bridge", "top", "fixture.Bridge", "middle"), relations)
        self.assertIn(("fixture.App", "run", "fixture.Bridge", "top"), relations)

    def test_batched_javap_keeps_each_class_bound_to_its_artifact_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sources = [
                _write_source(
                    root / "src", "fixture/First.java",
                    "package fixture; public class First { public String call() { return String.valueOf(1); } }",
                ),
                _write_source(
                    root / "src", "fixture/Second.java",
                    "package fixture; public class Second { public String call() { return String.valueOf(2); } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            entries = [
                oracle.PackagedClass(
                    f"BOOT-INF/classes/fixture/{name}.class",
                    classes / f"fixture/{name}.class",
                )
                for name in ("First", "Second")
            ]
            results = oracle._parse_entry_group_with_javap(
                entries, "a" * 64, "javap", "24.0.2", oracle.Event(), None
            )

        self.assertTrue(all(result["completed"] and result["parsed"] for result in results))
        self.assertTrue(all(not result["failures"] for result in results))
        for name, result in zip(("First", "Second"), results):
            self.assertTrue(result["rows"])
            self.assertEqual(
                {row["caller_owner"] for row in result["rows"]},
                {f"fixture.{name}"},
            )
            self.assertEqual(
                {row["artifact_entry"] for row in result["rows"]},
                {f"BOOT-INF/classes/fixture/{name}.class"},
            )

    def test_only_invokedynamic_classes_require_verbose_javap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sources = [
                _write_source(
                    root / "src", "fixture/Plain.java",
                    "package fixture; public class Plain { public int value() { return 1; } }",
                ),
                _write_source(
                    root / "src", "fixture/Lambda.java",
                    "package fixture; public class Lambda { public Runnable value() { return () -> {}; } }",
                ),
            ]
            classes = root / "classes"
            classes.mkdir()
            _compile(classes, sources)
            plain = classes / "fixture/Plain.class"
            dynamic = classes / "fixture/Lambda.class"

            plain_entry = oracle.PackagedClass("fixture/Plain.class", plain, plain.read_bytes())
            dynamic_entry = oracle.PackagedClass("fixture/Lambda.class", dynamic, dynamic.read_bytes())

        self.assertFalse(oracle._entry_requires_verbose_javap(plain_entry))
        self.assertTrue(oracle._entry_requires_verbose_javap(dynamic_entry))

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
            ("(Lfixture/Worker;)V", "fixture.App", "lambda$use$0", "()V", "invokedynamic", "BOOT-INF/classes/fixture/App.class", 48),
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

    def test_invokedynamic_uses_lambda_implementation_handle_not_metafactory(self):
        output = """
public class fixture.LambdaCaller {
  java.lang.Runnable call();
    descriptor: ()Ljava/lang/Runnable;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:run:()Ljava/lang/Runnable;
       5: areturn
}
BootstrapMethods:
  0: #20 REF_invokeStatic java/lang/invoke/LambdaMetafactory.metafactory:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 REF_invokeStatic fixture/LambdaCaller.lambda$call$0:()V
"""

        rows, failures = oracle._parse_javap_output(
            output,
            "a" * 64,
            "BOOT-INF/classes/fixture/LambdaCaller.class",
            "24.0.2",
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callee_owner"], "fixture.LambdaCaller")
        self.assertEqual(rows[0]["callee_member"], "lambda$call$0")
        self.assertEqual(rows[0]["callee_descriptor"], "()V")

    def test_invokedynamic_linker_without_method_handle_is_a_valid_empty_edge(self):
        output = """
public class fixture.ConcatCaller {
  java.lang.String call(java.lang.String);
    descriptor: (Ljava/lang/String;)Ljava/lang/String;
    Code:
       0: invokedynamic #7,  0 // InvokeDynamic #0:makeConcatWithConstants:(Ljava/lang/String;)Ljava/lang/String;
       5: areturn
}
BootstrapMethods:
  0: #20 REF_invokeStatic java/lang/invoke/StringConcatFactory.makeConcatWithConstants:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;
    Method arguments:
      #27 value=\u0001
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "fixture/ConcatCaller.class", "24.0.2"
        )

        self.assertEqual(rows, [])
        self.assertEqual(failures, [])

    def test_local_variable_named_record_cannot_replace_the_declared_caller_owner(self):
        output = """
public class com.example.Application {
  public void run();
    descriptor: ()V
    Code:
      LocalVariableTable:
        Start  Length  Slot  Name   Signature
            8      41     2 record   Lcom/example/Dependency;
       0: invokestatic #7 // Method com/example/Dependency.call:()V
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "BOOT-INF/classes/com/example/Application.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["caller_owner"], "com.example.Application")

    def test_array_clone_instruction_is_a_valid_method_edge(self):
        output = """
public class com.example.ArrayOwner {
  public java.lang.Object[] copy(java.lang.Object[]);
    descriptor: ([Ljava/lang/Object;)[Ljava/lang/Object;
    Code:
       0: invokevirtual #7 // Method "[Ljava/lang/Object;".clone:()Ljava/lang/Object;
}
"""

        rows, failures = oracle._parse_javap_output(
            output, "a" * 64, "BOOT-INF/classes/com/example/ArrayOwner.class", "24.0.2"
        )

        self.assertEqual(failures, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callee_owner"], "[Ljava.lang.Object;")
        self.assertEqual(rows[0]["callee_member"], "clone")
        self.assertEqual(rows[0]["callee_descriptor"], "()Ljava/lang/Object;")

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
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["cache_hits"], 0)
        self.assertEqual(len(result["failures"]), 1)
        self.assertTrue(result["failures"][0].startswith("oracle_javap_version_failed:OSError:"))
        self.assertIn("missing-javap-command", result["failures"][0])


if __name__ == "__main__":
    unittest.main()
