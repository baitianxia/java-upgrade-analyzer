import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from jdk_preflight import (  # noqa: E402
    JdkPreflightError,
    jdk_tool_path,
    preflight_jdk_home,
    resolve_jdk_release,
)
import jdk_preflight as preflight  # noqa: E402


def current_jdk_home():
    java = shutil.which("java")
    if not java:
        return None
    completed = subprocess.run(
        [java, "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(
        r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE,
    )
    return Path(match.group(1).strip()).resolve() if match else None


class JdkPreflightTest(unittest.TestCase):
    def test_full_jdk_probe_compiles_disassembles_and_executes(self):
        home = current_jdk_home()
        if (
            home is None
            or not (home / "jmods").is_dir()
            or not jdk_tool_path(home, "javac").is_file()
            or not jdk_tool_path(home, "javap").is_file()
        ):
            self.skipTest("full JDK required")

        result = preflight_jdk_home(home)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["probe"], "compile-javap-execute-v1")
        self.assertEqual(set(result["tools"]), {"java", "javac", "javap"})
        self.assertTrue(result["jdk_preflight_identity"])
        self.assertTrue(result["platform"]["content"])

    def test_missing_javap_is_rejected_before_long_running_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk"
            (home / "bin").mkdir(parents=True)
            (home / "lib").mkdir()
            (home / "jmods").mkdir()
            (home / "release").write_text(
                'JAVA_VERSION="17.0.1"\n', encoding="utf-8",
            )
            (home / "lib" / "modules").write_bytes(b"modules")
            (home / "jmods" / "java.base.jmod").write_bytes(b"jmod")
            for name in ("java", "javac"):
                (home / "bin" / name).write_text("tool", encoding="utf-8")

            with self.assertRaises(JdkPreflightError) as raised:
                preflight_jdk_home(home)

        self.assertEqual(raised.exception.reason_code, "JDK_REQUIRED_TOOL_MISSING")
        self.assertIn("javap", str(raised.exception))

    def test_tool_resolution_accepts_windows_executable_spelling(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "bin").mkdir()
            expected = home / "bin" / "javap.exe"
            expected.write_bytes(b"launcher")

            resolved = jdk_tool_path(home, "javap")

        self.assertEqual(resolved, expected.resolve())


class JdkPreflightBoundaryTest(unittest.TestCase):
    def setUp(self):
        preflight._cached_preflight.cache_clear()

    def tearDown(self):
        preflight._cached_preflight.cache_clear()

    @staticmethod
    def _write_tools(home, names=("java", "javac", "javap")):
        (home / "bin").mkdir(parents=True, exist_ok=True)
        for name in names:
            (home / "bin" / name).write_bytes(f"{name}-tool".encode())

    @classmethod
    def _modern_home(cls, root, *, version="17.0.1"):
        home = root / "jdk"
        (home / "lib").mkdir(parents=True)
        (home / "jmods").mkdir()
        (home / "release").write_text(
            f'JAVA_VERSION="{version}"\nIMPLEMENTOR="Test"\nIGNORED\n',
            encoding="utf-8",
        )
        (home / "lib" / "modules").write_bytes(b"modules")
        (home / "jmods" / "java.base.jmod").write_bytes(b"jmod")
        cls._write_tools(home)
        return home

    @classmethod
    def _legacy_home(cls, root, *, with_optional=True):
        home = root / "jdk8"
        legacy_lib = home / "jre" / "lib"
        legacy_lib.mkdir(parents=True)
        (home / "release").write_text(
            'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
        )
        (legacy_lib / "rt.jar").write_bytes(b"runtime")
        if with_optional:
            (legacy_lib / "resources.jar").write_bytes(b"resources")
            extension = legacy_lib / "ext"
            extension.mkdir()
            (extension / "extension.jar").write_bytes(b"extension")
            (extension / "ignored.txt").write_bytes(b"ignored")
            classes = home / "jre" / "classes" / "demo"
            classes.mkdir(parents=True)
            (classes / "Probe.class").write_bytes(b"class")
        cls._write_tools(home)
        return home

    @staticmethod
    def _successful_tool(command, *, stage, **_kwargs):
        if stage == "jdk.release_metadata_probe":
            return SimpleNamespace(
                stdout="",
                stderr=(
                    "    java.vendor = Fixture Vendor\n"
                    "    java.version = 1.8.0_504\n"
                    "    os.arch = aarch64\n"
                    "    os.name = Test OS\n"
                    'openjdk version "1.8.0_504"\n'
                ),
            )
        if stage == "step0.jdk.compile_probe":
            output = Path(command[command.index("-d") + 1])
            (output / f"{preflight.PROBE_CLASS}.class").write_bytes(b"class")
        if stage == "step0.jdk.javap_probe":
            return SimpleNamespace(
                stdout=f"public class {preflight.PROBE_CLASS}", stderr=""
            )
        if stage == "step0.jdk.java_probe":
            return SimpleNamespace(stdout=preflight.PROBE_OUTPUT, stderr="")
        if stage.endswith("java_version"):
            return SimpleNamespace(stdout="", stderr="java version 17")
        if stage.endswith("javac_version"):
            return SimpleNamespace(stdout="javac 17", stderr="")
        if stage.endswith("javap_version"):
            return SimpleNamespace(stdout="", stderr="")
        return SimpleNamespace(stdout="", stderr="")

    def test_release_reader_and_java_version_parser_cover_all_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release = root / "release"
            release.write_text(
                ' JAVA_VERSION = "21.0.2"\nNO_SEPARATOR\nEMPTY=\n',
                encoding="utf-8",
            )
            self.assertEqual(
                preflight._release_values(release),
                {"JAVA_VERSION": "21.0.2", "EMPTY": ""},
            )
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._release_values(root)
            self.assertEqual(raised.exception.reason_code, "JDK_RELEASE_UNREADABLE")

        for value, expected in (
            ("1.8.0_402", 8),
            ("8u402", 8),
            ("17.0.9+9", 17),
            (21, 21),
        ):
            with self.subTest(value=value):
                self.assertEqual(preflight._java_major(value), expected)
        for value in (None, "", "1", "1.", "garbage"):
            with self.subTest(value=value), self.assertRaises(
                preflight.JdkPreflightError
            ) as raised:
                preflight._java_major(value)
            self.assertEqual(
                raised.exception.reason_code, "JDK_RELEASE_VERSION_INVALID"
            )

    def test_runtime_metadata_probe_supports_a_real_jdk_without_release_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = self._legacy_home(root, with_optional=False)
            (home / "release").unlink()
            with patch.object(
                preflight, "_run_tool", side_effect=self._successful_tool
            ):
                record = resolve_jdk_release(home)
                result = preflight._preflight_jdk_home_uncached(home)

        self.assertEqual(record["source"], "java-properties-probe")
        self.assertEqual(record["values"], {
            "JAVA_VERSION": "1.8.0_504",
            "IMPLEMENTOR": "Fixture Vendor",
            "OS_NAME": "Test OS",
            "OS_ARCH": "aarch64",
        })
        self.assertRegex(record["identity"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["java_major"], 8)
        self.assertEqual(
            result["release_metadata_source"], "java-properties-probe"
        )
        self.assertEqual(result["platform"]["format"], "jdk8-classpath")

    def test_runtime_metadata_parser_and_identity_cover_every_output_shape(self):
        self.assertEqual(preflight._java_properties_from_output(None), {})
        self.assertEqual(
            preflight._java_properties_from_output(
                'banner without properties\njava version "1.8.0_392"\n'
            ),
            {"JAVA_VERSION": "1.8.0_392"},
        )
        self.assertEqual(
            preflight._java_properties_from_output(
                "java.version = 21.0.3\n"
                "java.vendor = Fixture Vendor\n"
                "os.name = Fixture OS\n"
                "os.arch = fixture-arch\n"
            ),
            {
                "JAVA_VERSION": "21.0.3",
                "IMPLEMENTOR": "Fixture Vendor",
                "OS_NAME": "Fixture OS",
                "OS_ARCH": "fixture-arch",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk"
            (home / "bin").mkdir(parents=True)
            java = home / "bin" / "java"
            java.write_bytes(b"first-launcher")
            result = SimpleNamespace(
                stdout="java.version = 17.0.12\njava.vendor = Vendor\n",
                stderr=None,
            )
            with patch.object(preflight, "_run_tool", return_value=result):
                first = resolve_jdk_release(home)
                java.write_bytes(b"second-launcher")
                second = resolve_jdk_release(home)

        self.assertEqual(first["source"], "java-properties-probe")
        self.assertEqual(first["values"]["JAVA_VERSION"], "17.0.12")
        self.assertNotEqual(first["identity"], second["identity"])

    def test_error_diagnostic_and_tool_runner_preserve_failure_evidence(self):
        without = preflight.JdkPreflightError("CODE", "detail")
        with_data = preflight.JdkPreflightError(
            "CODE", "detail", diagnostic={"stage": "probe"}
        )
        self.assertEqual(without.diagnostic, {})
        self.assertEqual(with_data.diagnostic, {"stage": "probe"})

        success = SimpleNamespace(succeeded=True)
        with patch.object(
            preflight, "execute_binary_tool", return_value=success
        ):
            self.assertIs(
                preflight._run_tool(
                    ["tool"], stage="stage", reason_prefix="PREFIX"
                ),
                success,
            )

        diagnostic = {"reason_code": "TOOL_FAILED", "failure_kind": "exit"}
        failure = SimpleNamespace(
            succeeded=False,
            failure=SimpleNamespace(
                reason_code="TOOL_FAILED", to_mapping=lambda: diagnostic
            ),
        )
        with patch.object(
            preflight, "execute_binary_tool", return_value=failure
        ), self.assertRaises(preflight.JdkPreflightError) as raised:
            preflight._run_tool(
                ["tool"], stage="stage", reason_prefix="PREFIX"
            )
        self.assertEqual(raised.exception.reason_code, "TOOL_FAILED")
        self.assertEqual(raised.exception.diagnostic, diagnostic)

    def test_tool_resolution_honors_native_order_and_missing_path_spelling(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "bin").mkdir()
            native = home / "bin" / "java"
            windows = home / "bin" / "java.exe"
            native.write_bytes(b"native")
            windows.write_bytes(b"windows")
            self.assertEqual(preflight.jdk_tool_path(home, "java"), native.resolve())
            native.unlink()
            self.assertEqual(preflight.jdk_tool_path(home, "java"), windows.resolve())
            windows.unlink()
            self.assertEqual(preflight.jdk_tool_path(home, "java"), native.resolve())

            windows.write_bytes(b"windows")
            with patch.object(
                preflight, "os", SimpleNamespace(name="nt")
            ):
                self.assertEqual(
                    preflight.jdk_tool_path(home, "java"), windows.resolve()
                )
                windows.unlink()
                self.assertEqual(
                    preflight.jdk_tool_path(home, "java"), windows.resolve()
                )

    def test_tool_fingerprint_covers_empty_and_bounded_version_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tool"
            path.write_bytes(b"tool-content")
            empty = preflight._tool_fingerprint(path, None)
            long = preflight._tool_fingerprint(path, "x" * 5000)
        self.assertEqual(empty["version_output"], "")
        self.assertEqual(len(long["version_output"]), 4000)
        self.assertEqual(empty["size_bytes"], 12)

    def test_modern_and_legacy_virtual_jdks_complete_all_probes(self):
        for kind in ("modern", "legacy", "legacy-minimal"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                home = (
                    self._modern_home(root)
                    if kind == "modern"
                    else self._legacy_home(
                        root, with_optional=kind == "legacy"
                    )
                )
                with patch.object(
                    preflight, "_run_tool", side_effect=self._successful_tool
                ):
                    result = preflight._preflight_jdk_home_uncached(home)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["java_major"], 17 if kind == "modern" else 8)
            self.assertEqual(
                result["platform"]["format"],
                "jimage-jmods" if kind == "modern" else "jdk8-classpath",
            )
            self.assertRegex(result["jdk_preflight_identity"], r"^[0-9a-f]{64}$")
            if kind == "legacy":
                paths = {Path(row["path"]).name for row in result["platform"]["content"]}
                self.assertTrue({"rt.jar", "resources.jar", "extension.jar", "Probe.class"} <= paths)
            if kind == "legacy-minimal":
                self.assertEqual(
                    {Path(row["path"]).name for row in result["platform"]["content"]},
                    {"rt.jar"},
                )

    def test_home_release_runtime_version_and_tool_failures_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_home = root / "missing"
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._preflight_jdk_home_uncached(missing_home)
            self.assertEqual(raised.exception.reason_code, "JDK_HOME_MISSING")

            home = root / "empty"
            home.mkdir()
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._preflight_jdk_home_uncached(home)
            self.assertEqual(raised.exception.reason_code, "JDK_RELEASE_MISSING")

            legacy = self._legacy_home(root, with_optional=False)
            (legacy / "jre" / "lib" / "rt.jar").unlink()
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._preflight_jdk_home_uncached(legacy)
            self.assertEqual(raised.exception.reason_code, "JDK8_RUNTIME_IMAGE_MISSING")

            unsupported = root / "jdk7"
            unsupported.mkdir()
            (unsupported / "release").write_text(
                'JAVA_VERSION="1.7.0"\n', encoding="utf-8"
            )
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._preflight_jdk_home_uncached(unsupported)
            self.assertEqual(raised.exception.reason_code, "JDK_VERSION_UNSUPPORTED")

            modern = self._modern_home(root / "tool-case")
            (modern / "bin" / "javap").unlink()
            with self.assertRaises(preflight.JdkPreflightError) as raised:
                preflight._preflight_jdk_home_uncached(modern)
            self.assertEqual(raised.exception.reason_code, "JDK_REQUIRED_TOOL_MISSING")
            self.assertIn("missing_tools", raised.exception.diagnostic)

    def test_every_modular_image_incompleteness_shape_fails_closed(self):
        mutators = (
            lambda home: (home / "lib" / "modules").unlink(),
            lambda home: ((home / "lib" / "modules").unlink(), (home / "lib" / "modules").mkdir()),
            lambda home: shutil.rmtree(home / "jmods"),
            lambda home: [path.unlink() for path in (home / "jmods").glob("*.jmod")],
            lambda home: (shutil.rmtree(home / "jmods"), (home / "jmods").write_bytes(b"file")),
        )
        for index, mutate in enumerate(mutators):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                home = self._modern_home(Path(tmp))
                mutate(home)
                with self.assertRaises(preflight.JdkPreflightError) as raised:
                    preflight._preflight_jdk_home_uncached(home)
            self.assertEqual(
                raised.exception.reason_code, "JDK_MODULE_IMAGE_INCOMPLETE"
            )

    def test_probe_output_failures_are_classified_independently(self):
        def run_case(*, compile_output=True, javap_output=None, java_output=None):
            with tempfile.TemporaryDirectory() as tmp:
                home = self._modern_home(Path(tmp))

                def runner(command, *, stage, **_kwargs):
                    if stage == "step0.jdk.compile_probe" and compile_output:
                        output = Path(command[command.index("-d") + 1])
                        (output / f"{preflight.PROBE_CLASS}.class").write_bytes(b"class")
                    if stage == "step0.jdk.javap_probe":
                        return SimpleNamespace(stdout=javap_output, stderr="")
                    if stage == "step0.jdk.java_probe":
                        return SimpleNamespace(stdout=java_output, stderr="")
                    return SimpleNamespace(stdout="", stderr="")

                with patch.object(preflight, "_run_tool", side_effect=runner):
                    return preflight._preflight_jdk_home_uncached(home)

        cases = (
            ({"compile_output": False}, "JDK_JAVAC_PROBE_OUTPUT_MISSING"),
            ({"javap_output": None}, "JDK_JAVAP_PROBE_OUTPUT_INVALID"),
            ({"javap_output": "wrong"}, "JDK_JAVAP_PROBE_OUTPUT_INVALID"),
            (
                {"javap_output": preflight.PROBE_CLASS, "java_output": None},
                "JDK_JAVA_PROBE_OUTPUT_INVALID",
            ),
            (
                {"javap_output": preflight.PROBE_CLASS, "java_output": " wrong "},
                "JDK_JAVA_PROBE_OUTPUT_INVALID",
            ),
        )
        for kwargs, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason), self.assertRaises(
                preflight.JdkPreflightError
            ) as raised:
                run_case(**kwargs)
            self.assertEqual(raised.exception.reason_code, expected_reason)

    def test_input_signature_covers_modular_legacy_optional_and_missing_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modern = self._modern_home(root / "modern")
            modern_signature = preflight._preflight_input_signature(modern)
            self.assertTrue(
                any(path.endswith("java.base.jmod") for path, _size, _mtime in modern_signature)
            )

            legacy = self._legacy_home(root / "legacy")
            legacy_signature = preflight._preflight_input_signature(legacy)
            paths = {Path(path).name for path, _size, _mtime in legacy_signature}
            self.assertTrue({"rt.jar", "extension.jar", "Probe.class"} <= paths)
            self.assertTrue(any(size == -1 for _path, size, _mtime in legacy_signature))

            minimal = self._legacy_home(root / "minimal", with_optional=False)
            minimal_signature = preflight._preflight_input_signature(minimal)
            self.assertNotIn(
                "extension.jar",
                {Path(path).name for path, _size, _mtime in minimal_signature},
            )

    def test_public_cache_key_changes_when_jdk_inputs_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self._modern_home(Path(tmp))
            observed = {"status": "passed"}
            with patch.object(
                preflight, "_preflight_jdk_home_uncached", return_value=observed
            ) as uncached:
                first = preflight.preflight_jdk_home(home)
                second = preflight.preflight_jdk_home(home)
                (home / "release").write_text(
                    'JAVA_VERSION="21.0.1"\n', encoding="utf-8"
                )
                third = preflight.preflight_jdk_home(home)

        self.assertEqual(first, observed)
        self.assertEqual(second, observed)
        self.assertEqual(third, observed)
        self.assertIsNot(first, second)
        first["status"] = "mutated-by-caller"
        self.assertEqual(second["status"], "passed")
        self.assertEqual(uncached.call_count, 2)


if __name__ == "__main__":
    unittest.main()
