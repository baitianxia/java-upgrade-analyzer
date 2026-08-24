import gc
import hashlib
import json
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


def framed_json(*payloads, stray=b""):
    output = bytearray()
    for payload in payloads:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        output.extend(struct.pack(">I", len(encoded)))
        output.extend(encoded)
    output.extend(stray)
    return bytes(output)


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


class DefinitionVerifierBoundaryTest(unittest.TestCase):
    @staticmethod
    def _run_unwrapped_compile(completed):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            verifier,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            verifier, "execute_binary_tool", return_value=completed
        ):
            return verifier._compile_helper.__wrapped__("javac", "a" * 64)

    def test_unwrapped_compile_contract_exposes_success_and_failure_branches(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)

            def compile_success(command, **_kwargs):
                output = Path(command[command.index("-d") + 1])
                (output / "ClassDefinitionVerifier.class").write_bytes(b"compiled")
                return SimpleNamespace(succeeded=True)

            with patch.object(
                verifier,
                "make_short_temp_dir",
                side_effect=lambda prefix: Path(
                    tempfile.mkdtemp(prefix=f"{prefix}-", dir=output_root)
                ),
            ), patch.object(
                verifier, "execute_binary_tool", side_effect=compile_success
            ):
                compiled = verifier._compile_helper.__wrapped__("javac", "a" * 64)
                self.assertTrue(compiled.output.is_dir())
                compiled._temporary_directory.cleanup()

        failed = SimpleNamespace(
            succeeded=False,
            failure=SimpleNamespace(to_mapping=lambda: {"failure_kind": "exit"}),
        )
        with self.assertRaises(verifier.ClassDefinitionVerifierError) as raised:
            self._run_unwrapped_compile(failed)
        self.assertEqual(
            raised.exception.reason_code,
            "CLASS_DEFINITION_HELPER_COMPILE_FAILED",
        )

        with self.assertRaises(verifier.ClassDefinitionVerifierError) as raised:
            self._run_unwrapped_compile(SimpleNamespace(succeeded=True))
        self.assertEqual(
            raised.exception.reason_code,
            "CLASS_DEFINITION_HELPER_COMPILE_INCOMPLETE",
        )

    def test_owned_helper_cleanup_is_process_bound(self):
        path = Path("/owned/helper")
        remover = unittest.mock.Mock()

        verifier._remove_owned_helper_directory(
            path, 17, getpid=lambda: 18, rmtree=remover
        )
        remover.assert_not_called()

        verifier._remove_owned_helper_directory(
            path, 17, getpid=lambda: 17, rmtree=remover
        )
        remover.assert_called_once_with(path, ignore_errors=True)

    def test_bundle_count_name_encoding_and_record_limits_fail_closed(self):
        class OversizedNames:
            def __len__(self):
                return 0x8000_0000

        with self.assertRaises(
            verifier.ClassDefinitionVerifierError
        ) as raised, tempfile.TemporaryDirectory() as tmp:
            verifier._write_class_bundle(
                Path(tmp) / "count.bundle", OversizedNames(), {}
            )
        self.assertEqual(
            raised.exception.reason_code, "CLASS_DEFINITION_BUNDLE_COUNT_INVALID"
        )

        invalid_names = ("", "/absolute", "../parent", "a/../b", "demo.A")
        for index, name in enumerate(invalid_names):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(
                    verifier.ClassDefinitionVerifierError
                ) as raised:
                    verifier._write_class_bundle(
                        Path(tmp) / f"name-{index}.bundle",
                        [name],
                        {name: b"class"},
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "CLASS_DEFINITION_NAME_INVALID",
                )

        surrogate = "demo/\ud800"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(
            verifier.ClassDefinitionVerifierError
        ) as raised:
            verifier._write_class_bundle(
                Path(tmp) / "surrogate.bundle",
                [surrogate],
                {surrogate: b"class"},
            )
        self.assertEqual(
            raised.exception.reason_code, "CLASS_DEFINITION_NAME_INVALID"
        )

        limit_cases = (
            ("demo/Long", b"class", "_MAX_BUNDLE_CLASS_NAME_BYTES", 1),
            ("demo/Empty", b"", "_MAX_BUNDLE_CLASS_BYTES", 100),
            ("demo/Large", b"12", "_MAX_BUNDLE_CLASS_BYTES", 1),
        )
        for index, (name, content, field, limit) in enumerate(limit_cases):
            with (
                self.subTest(name=name),
                tempfile.TemporaryDirectory() as tmp,
                patch.object(verifier, field, limit),
                self.assertRaises(verifier.ClassDefinitionVerifierError) as raised,
            ):
                verifier._write_class_bundle(
                    Path(tmp) / f"record-{index}.bundle",
                    [name],
                    {name: content},
                )
            self.assertEqual(
                raised.exception.reason_code,
                "CLASS_DEFINITION_BUNDLE_RECORD_INVALID",
            )

    def test_verifier_identity_records_jdk8_isolation_only_for_legacy_image(self):
        for image_format, expected_legacy_flag in (
            ("jdk8-classpath", True),
            ("jimage-jmods", False),
        ):
            platform = SimpleNamespace(
                platform_image_format=image_format,
                identity="platform-id",
                java_executable=Path("/jdk/bin/java"),
            )
            with self.subTest(image_format=image_format), patch.object(
                verifier, "_sha256_file", side_effect=("helper-sha", "java-sha")
            ), patch.object(
                verifier, "canonical_identity", return_value="verifier-id"
            ) as identity:
                self.assertEqual(verifier.verifier_identity(platform), "verifier-id")
            flags = identity.call_args.args[1]["verification_flags"]
            self.assertEqual(
                "isolated-jdk8-extension-directory" in flags,
                expected_legacy_flag,
            )

    @staticmethod
    def _platform(root, *, image_format="jimage-jmods"):
        home = root / "jdk"
        (home / "bin").mkdir(parents=True)
        javac = home / "bin" / "javac"
        java = home / "bin" / "java"
        javac.write_bytes(b"javac")
        java.write_bytes(b"java")
        helper = root / "helper"
        helper.mkdir()
        return (
            SimpleNamespace(
                jdk_home=home,
                platform_image_format=image_format,
                legacy_extension_dir=root / "ext" if image_format == "jdk8-classpath" else None,
                java_executable=java,
                identity="platform-id",
            ),
            helper,
        )

    def _verify_with_output(
        self,
        selected,
        stdout,
        *,
        image_format="jimage-jmods",
        completed=None,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            platform, helper = self._platform(Path(tmp), image_format=image_format)
            completed = completed or SimpleNamespace(
                succeeded=True, stdout=stdout
            )
            with patch.object(
                verifier,
                "_compile_helper",
                return_value=SimpleNamespace(output=helper),
            ), patch.object(
                verifier, "execute_binary_tool", return_value=completed
            ) as execute, patch.object(
                verifier, "verifier_identity", return_value="verifier-id"
            ):
                result = verifier.verify_class_definitions(platform, selected)
            return result, execute.call_args.args[0]

    def test_missing_javac_is_rejected_before_helper_compilation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "jdk"
            home.mkdir()
            platform = SimpleNamespace(jdk_home=home)
            with patch.object(verifier, "_compile_helper") as compiler, self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ) as raised:
                verifier.verify_class_definitions(platform, {})
        self.assertEqual(raised.exception.reason_code, "TARGET_JAVAC_MISSING")
        compiler.assert_not_called()

    def test_legacy_verification_command_contains_isolated_extension_directory(self):
        header = {
            "frame_type": "definition_output_header",
            "schema": verifier.SCHEMA,
            "class_count": 0,
        }
        footer = {
            "frame_type": "definition_output_footer",
            "class_count": 0,
            "definition_ready_count": 0,
            "failure_count": 0,
        }
        result, command = self._verify_with_output(
            {}, framed_json(header, footer), image_format="jdk8-classpath"
        )

        self.assertEqual(result, {})
        self.assertTrue(
            any(value.startswith("-Djava.ext.dirs=") for value in command)
        )

        with tempfile.TemporaryDirectory() as tmp:
            platform, helper = self._platform(
                Path(tmp), image_format="jdk8-classpath"
            )
            platform.legacy_extension_dir = None
            with patch.object(
                verifier,
                "_compile_helper",
                return_value=SimpleNamespace(output=helper),
            ), patch.object(
                verifier,
                "execute_binary_tool",
                return_value=SimpleNamespace(
                    succeeded=True, stdout=framed_json(header, footer)
                ),
            ) as execute, patch.object(
                verifier, "verifier_identity", return_value="verifier-id"
            ):
                verifier.verify_class_definitions(platform, {})
        self.assertIn("-Djava.ext.dirs=", execute.call_args.args[0])

    def test_tool_failures_preserve_timeout_taxonomy(self):
        for failure_kind, expected_reason in (
            ("timeout", "CLASS_DEFINITION_VERIFIER_TIMEOUT"),
            ("exit", "CLASS_DEFINITION_VERIFIER_FAILED"),
        ):
            failure = SimpleNamespace(
                failure_kind=failure_kind,
                to_mapping=lambda: {"failure_kind": failure_kind},
            )
            completed = SimpleNamespace(succeeded=False, failure=failure)
            with self.subTest(failure_kind=failure_kind), self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ) as raised:
                self._verify_with_output({}, b"", completed=completed)
            self.assertEqual(raised.exception.reason_code, expected_reason)

    def test_protocol_header_and_frame_failures_are_classified(self):
        name = "demo/A"
        content = b"class"
        header = {
            "frame_type": "definition_output_header",
            "schema": verifier.SCHEMA,
            "class_count": 1,
        }
        valid_record = {
            "frame_type": "class_definition",
            "class_name": name,
            "class_bytes_sha256": hashlib.sha256(content).hexdigest(),
            "status": "definition_ready",
        }
        cases = (
            (b"", "CLASS_DEFINITION_PROTOCOL_HEADER_MISSING"),
            (
                framed_json({**header, "schema": "wrong"}),
                "CLASS_DEFINITION_PROTOCOL_HEADER_INVALID",
            ),
            (framed_json(header), "CLASS_DEFINITION_PROTOCOL_FOOTER_MISSING"),
            (
                framed_json(header, {"frame_type": "unexpected"}),
                "CLASS_DEFINITION_PROTOCOL_FRAME_INVALID",
            ),
            (
                framed_json(
                    header,
                    {
                        "frame_type": "class_definition",
                        "class_bytes_sha256": hashlib.sha256(content).hexdigest(),
                        "status": "definition_ready",
                    },
                ),
                "CLASS_DEFINITION_PROTOCOL_CLASS_SET_INVALID",
            ),
            (
                framed_json(
                    header,
                    {**valid_record, "class_name": "demo/Unknown"},
                ),
                "CLASS_DEFINITION_PROTOCOL_CLASS_SET_INVALID",
            ),
            (
                framed_json(header, valid_record, valid_record),
                "CLASS_DEFINITION_PROTOCOL_CLASS_SET_INVALID",
            ),
            (
                framed_json(
                    header,
                    {**valid_record, "class_bytes_sha256": "0" * 64},
                ),
                "CLASS_DEFINITION_PROTOCOL_SHA_MISMATCH",
            ),
        )
        for stdout, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason), self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ) as raised:
                self._verify_with_output({name: content}, stdout)
            self.assertEqual(raised.exception.reason_code, expected_reason)

    def test_protocol_footer_conservation_and_stray_bytes_are_rejected(self):
        name = "demo/A"
        content = b"class"
        digest = hashlib.sha256(content).hexdigest()
        header = {
            "frame_type": "definition_output_header",
            "schema": verifier.SCHEMA,
            "class_count": 1,
        }
        record = {
            "frame_type": "class_definition",
            "class_name": name,
            "class_bytes_sha256": digest,
            "status": "definition_ready",
        }
        valid_footer = {
            "frame_type": "definition_output_footer",
            "class_count": 1,
            "definition_ready_count": 1,
            "failure_count": 0,
        }
        cases = (
            (
                framed_json(header, record, valid_footer, stray=b"x"),
                "CLASS_DEFINITION_PROTOCOL_STRAY_BYTES",
            ),
            (
                framed_json(header, record, {**valid_footer, "failure_count": 1}),
                "CLASS_DEFINITION_PROTOCOL_CONSERVATION_FAILED",
            ),
            (
                framed_json(
                    header,
                    {
                        "frame_type": "definition_output_footer",
                        "class_count": 1,
                        "definition_ready_count": 0,
                        "failure_count": 1,
                    },
                ),
                "CLASS_DEFINITION_PROTOCOL_CONSERVATION_FAILED",
            ),
        )
        for stdout, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason), self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ) as raised:
                self._verify_with_output({name: content}, stdout)
            self.assertEqual(raised.exception.reason_code, expected_reason)

    def test_successful_protocol_preserves_ready_and_failed_records(self):
        selected = {"demo/A": b"a", "demo/B": b"b"}
        header = {
            "frame_type": "definition_output_header",
            "schema": verifier.SCHEMA,
            "class_count": 2,
        }
        records = [
            {
                "frame_type": "class_definition",
                "class_name": name,
                "class_bytes_sha256": hashlib.sha256(content).hexdigest(),
                "status": status,
            }
            for (name, content), status in zip(
                sorted(selected.items()),
                ("definition_ready", "verification_failed"),
            )
        ]
        footer = {
            "frame_type": "definition_output_footer",
            "class_count": 2,
            "definition_ready_count": 1,
            "failure_count": 1,
        }

        result, command = self._verify_with_output(
            selected, framed_json(header, *records, footer)
        )

        self.assertEqual(set(result), set(selected))
        self.assertEqual(
            {row["class_definition_verifier_identity"] for row in result.values()},
            {"verifier-id"},
        )
        self.assertNotIn("-Djava.ext.dirs=", " ".join(command))


if __name__ == "__main__":
    unittest.main()
