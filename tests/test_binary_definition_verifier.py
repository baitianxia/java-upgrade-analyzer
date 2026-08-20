import gc
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_asm_helper import resolve_asm_jar  # noqa: E402
import binary_definition_verifier as verifier  # noqa: E402
from binary_definition_verifier import verify_class_definitions  # noqa: E402
from binary_platform_image import JdkPlatformImage  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip())
    return None


class BinaryDefinitionVerifierTest(unittest.TestCase):
    @staticmethod
    def _successful_helper_compile(command, **_kwargs):
        output = Path(command[command.index("-d") + 1])
        (output / "ClassDefinitionVerifier.class").write_bytes(b"compiled")
        return SimpleNamespace(succeeded=True)

    def test_compiled_helper_directory_follows_cache_and_owner_lifetime(self):
        verifier._compile_helper.cache_clear()
        self.addCleanup(verifier._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            verifier,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            verifier,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            compiled = verifier._compile_helper("javac-cache-test", "a" * 64)
            output = compiled.output
            cached = verifier._compile_helper("javac-cache-test", "a" * 64)
            self.assertIs(cached, compiled)
            self.assertTrue(output.is_dir())

            del cached, compiled
            gc.collect()
            self.assertTrue(output.is_dir())
            verifier._compile_helper.cache_clear()
            gc.collect()
            self.assertFalse(output.exists())

    def test_lru_eviction_removes_only_the_evicted_helper_directory(self):
        verifier._compile_helper.cache_clear()
        self.addCleanup(verifier._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            verifier,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            verifier,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            outputs = []
            for index in range(9):
                compiled = verifier._compile_helper(
                    f"javac-eviction-{index}", f"{index:064x}"
                )
                outputs.append(compiled.output)
                del compiled
            gc.collect()

            self.assertFalse(outputs[0].exists())
            self.assertTrue(all(path.is_dir() for path in outputs[1:]))
            verifier._compile_helper.cache_clear()
            gc.collect()
            self.assertTrue(all(not path.exists() for path in outputs))

    def test_compile_failure_and_incomplete_output_clean_owned_directory(self):
        verifier._compile_helper.cache_clear()
        self.addCleanup(verifier._compile_helper.cache_clear)
        failed = SimpleNamespace(
            succeeded=False,
            failure=SimpleNamespace(
                to_mapping=lambda: {"failure_kind": "exit", "returncode": 1}
            ),
        )
        cases = (
            (failed, "CLASS_DEFINITION_HELPER_COMPILE_FAILED"),
            (
                SimpleNamespace(succeeded=True),
                "CLASS_DEFINITION_HELPER_COMPILE_INCOMPLETE",
            ),
        )
        for index, (completed, expected_reason) in enumerate(cases):
            with (
                self.subTest(expected_reason=expected_reason),
                tempfile.TemporaryDirectory() as tmp,
                patch.object(
                    verifier,
                    "make_short_temp_dir",
                    side_effect=lambda prefix: Path(
                        tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
                    ),
                ),
                patch.object(
                    verifier, "execute_binary_tool", return_value=completed
                ),
            ):
                with self.assertRaises(
                    verifier.ClassDefinitionVerifierError
                ) as raised:
                    verifier._compile_helper(
                        f"javac-failure-{index}", str(index) * 64
                    )
                self.assertEqual(raised.exception.reason_code, expected_reason)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_class_bundle_is_single_file_with_exact_sorted_bytes_and_hashes(self):
        payloads = {
            "alpha/A": b"first-class-bytes",
            "beta/B": b"second-class-bytes",
        }
        names = sorted(payloads)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "classes.bundle"
            hashes = verifier._write_class_bundle(bundle, names, payloads)
            expected = bytearray(verifier._BUNDLE_MAGIC)
            expected.extend(struct.pack(">I", len(names)))
            for name in names:
                name_bytes = name.encode("utf-8")
                content = payloads[name]
                expected.extend(struct.pack(">II", len(name_bytes), len(content)))
                expected.extend(name_bytes)
                expected.extend(content)

            self.assertEqual(bundle.read_bytes(), bytes(expected))
            self.assertEqual(list(root.iterdir()), [bundle])
            self.assertEqual(
                hashes,
                {
                    name: hashlib.sha256(payloads[name]).hexdigest()
                    for name in names
                },
            )

    @unittest.skipUnless(hasattr(os, "fork"), "fork is unavailable")
    def test_forked_child_cache_clear_does_not_remove_parent_helper(self):
        verifier._compile_helper.cache_clear()
        self.addCleanup(verifier._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            verifier,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            verifier,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            compiled = verifier._compile_helper("javac-fork-test", "f" * 64)
            output = compiled.output
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    verifier._compile_helper.cache_clear()
                    del compiled
                    gc.collect()
                    os._exit(0 if output.is_dir() else 2)
                except BaseException:
                    os._exit(1)

            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertTrue(
                (output / "ClassDefinitionVerifier.class").is_file()
            )
            cached = verifier._compile_helper("javac-fork-test", "f" * 64)
            self.assertIs(cached, compiled)

            del cached, compiled
            verifier._compile_helper.cache_clear()
            gc.collect()
            self.assertFalse(output.exists())

    def test_legal_package_info_class_does_not_abort_definition_batch(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "package-info.java"
            source.parent.mkdir(parents=True)
            source.write_text("@Deprecated package demo;\n", encoding="utf-8")
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = (classes / "demo" / "package-info.class").read_bytes()
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {"demo/package-info": payload},
            )
        self.assertIn(outcomes["demo/package-info"]["status"], {
            "definition_ready", "verification_failed",
        })
        self.assertEqual(set(outcomes), {"demo/package-info"})

    def test_optional_nested_class_does_not_change_outer_definition_readiness(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "Outer.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class Outer { "
                "public static class OptionalNested implements Missing {} } "
                "interface Missing {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {"demo/Outer": (classes / "demo" / "Outer.class").read_bytes()},
            )
        self.assertEqual(outcomes["demo/Outer"]["status"], "definition_ready")

    def test_missing_declared_member_type_still_fails_definition_readiness(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "UsesMissing.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class UsesMissing { "
                "public Missing value() { return null; } } class Missing {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {
                    "demo/UsesMissing": (
                        classes / "demo" / "UsesMissing.class"
                    ).read_bytes()
                },
            )
        self.assertEqual(outcomes["demo/UsesMissing"]["status"], "verification_failed")
        self.assertEqual(
            outcomes["demo/UsesMissing"]["failure_phase"], "member_linkage"
        )

    def test_bundle_loader_resolves_selected_class_dependencies_exactly(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "Child.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class Child extends Parent { "
                "public Parent value() { return this; } } "
                "class Parent {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payloads = {
                name: (classes / f"demo/{name}.class").read_bytes()
                for name in ("Child", "Parent")
            }
            selected = {f"demo/{name}": value for name, value in payloads.items()}
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()), selected
            )

        self.assertEqual(set(outcomes), set(selected))
        for name, content in selected.items():
            self.assertEqual(outcomes[name]["status"], "definition_ready")
            self.assertEqual(
                outcomes[name]["class_bytes_sha256"],
                hashlib.sha256(content).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
