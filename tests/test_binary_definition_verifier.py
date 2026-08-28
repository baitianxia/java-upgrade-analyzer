import gc
import hashlib
import json
import os
from dataclasses import replace
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

    def test_internal_class_name_validation_matches_jvms_unqualified_names(self):
        okio_hyphen_names = (
            "okio/-Base64",
            "okio/-DeflaterSinkExtensions",
            "okio/-DeprecatedOkio",
            "okio/-DeprecatedUpgrade",
            "okio/-DeprecatedUtf8",
            "okio/-GzipSinkExtensions",
            "okio/-GzipSourceExtensions",
            "okio/-InflaterSourceExtensions",
            "okio/-SegmentedByteString",
            "okio/internal/-Buffer",
            "okio/internal/-ByteString",
            "okio/internal/-FileSystem",
            "okio/internal/-FileSystem$collectRecursively$1",
            "okio/internal/-FileSystem$commonDeleteRecursively$sequence$1",
            "okio/internal/-FileSystem$commonListRecursively$1",
            "okio/internal/-Path",
            "okio/internal/-RealBufferedSink",
            "okio/internal/-RealBufferedSource",
            "okio/internal/-SegmentedByteString",
        )
        self.assertEqual(len(okio_hyphen_names), 19)
        for name in okio_hyphen_names:
            with self.subTest(name=name):
                self.assertTrue(verifier._is_valid_internal_class_name(name))
        for name in (
            "", "/demo/A", "demo/A/", "demo//A", "demo.A", "demo/A;B",
            "demo/[A", None, 7,
        ):
            with self.subTest(name=name):
                self.assertFalse(verifier._is_valid_internal_class_name(name))

    def test_hyphen_and_case_distinct_names_define_from_one_bundle(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        renames = {
            "XBase64": "-Base64",
            "AAAAAAAAAAAAAAA": "SLF4JLogFactory",
            "BBBBBBBBBBBBBBB": "Slf4jLogFactory",
        }
        self.assertTrue(all(
            len(source) == len(target) for source, target in renames.items()
        ))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "Fixture.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; class XBase64 {} "
                "class AAAAAAAAAAAAAAA {} class BBBBBBBBBBBBBBB {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            selected = {}
            for original, renamed in renames.items():
                content = (classes / "demo" / f"{original}.class").read_bytes()
                original_name = f"demo/{original}".encode("utf-8")
                renamed_name = f"demo/{renamed}".encode("utf-8")
                self.assertIn(original_name, content)
                selected[f"demo/{renamed}"] = content.replace(
                    original_name, renamed_name
                )
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()), selected
            )

        self.assertEqual(set(outcomes), set(selected))
        self.assertTrue(all(
            outcome["status"] == "definition_ready"
            for outcome in outcomes.values()
        ), outcomes)

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

    def test_verifier_range_deadline_failure_detail_and_timeout_matrix(self):
        failure_timeout = SimpleNamespace(
            failure_kind="timeout",
            to_mapping=lambda: {"failure_kind": "timeout"},
        )
        base = {
            "platform": SimpleNamespace(java_executable=Path("/jdk/bin/java")),
            "helper_dir": Path("/helper"),
            "java_options": [],
            "bundle_path": Path("/classes.bundle"),
            "selected_class_bytes": {"demo/A": b"a", "demo/B": b"b"},
            "expected_hashes": {"demo/A": "a", "demo/B": "b"},
            "deadline": 10.0,
            "invocation_budget_seconds": 1.0,
        }
        with patch.object(
            verifier.time, "perf_counter", side_effect=[0.0, 1.0]
        ), self.assertRaises(verifier.ClassDefinitionVerifierError) as expired:
            verifier._execute_verifier_range(
                **base, names=["demo/A"], start=0, end=1
            )
        self.assertEqual(
            expired.exception.reason_code,
            "CLASS_DEFINITION_VERIFIER_TIMEOUT",
        )

        with patch.object(
            verifier.time, "perf_counter", return_value=0.0
        ), patch.object(
            verifier,
            "execute_binary_tool",
            return_value=SimpleNamespace(succeeded=False, failure=None),
        ), patch.object(
            verifier, "tool_failure_is_retryable", return_value=False
        ), self.assertRaises(verifier.ClassDefinitionVerifierError) as missing:
            verifier._execute_verifier_range(
                **base, names=["demo/A"], start=0, end=1
            )
        self.assertEqual(
            missing.exception.reason_code,
            "CLASS_DEFINITION_VERIFIER_FAILED",
        )
        self.assertIn("missing_failure_detail", str(missing.exception))

        with patch.object(
            verifier.time, "perf_counter", return_value=0.0
        ), patch.object(
            verifier,
            "execute_binary_tool",
            return_value=SimpleNamespace(
                succeeded=False, failure=failure_timeout
            ),
        ), self.assertRaises(verifier.ClassDefinitionVerifierError) as timeout:
            verifier._execute_verifier_range(
                **base, names=["demo/A", "demo/B"], start=0, end=2
            )
        self.assertEqual(
            timeout.exception.reason_code,
            "CLASS_DEFINITION_VERIFIER_TIMEOUT",
        )

    def test_installed_verifier_binding_and_phase_budget_operand_matrix(self):
        empty_protocol = framed_json(
            {
                "frame_type": "definition_output_header",
                "schema": verifier.SCHEMA,
                "class_count": 0,
            },
            {
                "frame_type": "definition_output_footer",
                "class_count": 0,
                "definition_ready_count": 0,
                "failure_count": 0,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            platform, helper = self._platform(Path(tmp))
            source_sha = verifier._sha256_file(verifier.JAVA_HELPER)
            javac = (platform.jdk_home / "bin" / "javac").resolve()
            compiled = SimpleNamespace(output=helper)
            bindings = (
                SimpleNamespace(
                    source_sha256="different", javac_path=str(javac)
                ),
                SimpleNamespace(
                    source_sha256=source_sha, javac_path="different"
                ),
                SimpleNamespace(
                    source_sha256=source_sha, javac_path=str(javac)
                ),
            )
            for index, binding in enumerate(bindings):
                with self.subTest(installed=index), patch.object(
                    verifier,
                    "_INSTALLED_COMPILED_DEFINITION_HELPER",
                    (binding, compiled),
                ), patch.object(
                    verifier, "_compile_helper", return_value=compiled
                ), patch.object(
                    verifier,
                    "execute_binary_tool",
                    return_value=SimpleNamespace(
                        succeeded=True, stdout=empty_protocol
                    ),
                ), patch.object(
                    verifier, "verifier_identity", return_value="verifier-id"
                ):
                    self.assertEqual(
                        verifier.verify_class_definitions(platform, {}), {}
                    )

            for invocation, phase in ((0, 1), (1, 0)):
                with self.subTest(invocation=invocation, phase=phase), patch.object(
                    verifier, "_compile_helper", return_value=compiled
                ), patch.object(
                    verifier, "verifier_identity", return_value="verifier-id"
                ), self.assertRaises(verifier.ClassDefinitionVerifierError):
                    verifier.verify_class_definitions(
                        platform,
                        {},
                        timeout_seconds=invocation,
                        phase_time_budget_seconds=phase,
                    )

            for selected in ({}, {"demo/A": b"a"}):
                with self.subTest(expired_names=tuple(selected)), patch.object(
                    verifier, "_compile_helper", return_value=compiled
                ), patch.object(
                    verifier, "verifier_identity", return_value="verifier-id"
                ), patch.object(
                    verifier.time, "perf_counter", side_effect=[0.0, 2.0]
                ), patch.object(
                    verifier,
                    "execute_binary_tool",
                    side_effect=AssertionError("expired phase cannot spawn JVM"),
                ):
                    result = verifier.verify_class_definitions(
                        platform,
                        selected,
                        timeout_seconds=1,
                        phase_time_budget_seconds=1,
                    )
                if selected:
                    self.assertEqual(
                        result["demo/A"]["status"],
                        "verification_unavailable",
                    )
                else:
                    self.assertEqual(result, {})

    def test_failed_batch_is_bisected_and_only_toxic_class_is_failed(self):
        selected = {
            "demo/A": b"class-a",
            "demo/B": b"class-b",
            "demo.Bad": b"invalid-name",
        }
        valid_names = ["demo/A", "demo/B"]
        calls = []
        process_failure = SimpleNamespace(
            failure_kind="nonzero_exit",
            to_mapping=lambda: {
                "failure_kind": "nonzero_exit",
                "returncode": 2,
            },
        )

        def successful_range(start, end):
            names = valid_names[start:end]
            records = [
                {
                    "frame_type": "class_definition",
                    "class_name": name,
                    "class_bytes_sha256": hashlib.sha256(
                        selected[name]
                    ).hexdigest(),
                    "status": "definition_ready",
                }
                for name in names
            ]
            return SimpleNamespace(
                succeeded=True,
                stdout=framed_json(
                    {
                        "frame_type": "definition_output_header",
                        "schema": verifier.SCHEMA,
                        "class_count": len(names),
                    },
                    *records,
                    {
                        "frame_type": "definition_output_footer",
                        "class_count": len(names),
                        "definition_ready_count": len(names),
                        "failure_count": 0,
                    },
                ),
            )

        def execute(command, **_kwargs):
            start, end = map(int, command[-2:])
            calls.append((start, end))
            if (start, end) in {(0, 2), (1, 2)}:
                return SimpleNamespace(
                    succeeded=False, failure=process_failure
                )
            return successful_range(start, end)

        with tempfile.TemporaryDirectory() as tmp:
            platform, helper = self._platform(Path(tmp))
            with patch.object(
                verifier,
                "_compile_helper",
                return_value=SimpleNamespace(output=helper),
            ), patch.object(
                verifier, "execute_binary_tool", side_effect=execute,
            ), patch.object(
                verifier, "verifier_identity", return_value="verifier-id",
            ):
                result = verifier.verify_class_definitions(platform, selected)

        self.assertEqual(calls, [(0, 2), (0, 1), (1, 2)])
        self.assertEqual(result["demo/A"]["status"], "definition_ready")
        self.assertEqual(result["demo/B"]["status"], "verification_failed")
        self.assertEqual(
            result["demo/B"]["isolation_status"], "single_class_failure"
        )
        self.assertEqual(result["demo.Bad"]["status"], "verification_failed")
        self.assertEqual(
            result["demo.Bad"]["isolation_status"],
            "invalid_name_isolated",
        )
        self.assertEqual(
            result["demo.Bad"]["failure_kind"],
            "CLASS_DEFINITION_NAME_INVALID",
        )

    def test_transient_verifier_start_failure_is_retried_before_isolation(self):
        name = "demo/A"
        content = b"class-a"
        header = {
            "frame_type": "definition_output_header",
            "schema": verifier.SCHEMA,
            "class_count": 1,
        }
        record = {
            "frame_type": "class_definition",
            "class_name": name,
            "class_bytes_sha256": hashlib.sha256(content).hexdigest(),
            "status": "definition_ready",
        }
        footer = {
            "frame_type": "definition_output_footer",
            "class_count": 1,
            "definition_ready_count": 1,
            "failure_count": 0,
        }
        transient = SimpleNamespace(
            succeeded=False,
            failure=SimpleNamespace(
                failure_kind="start_failed",
                to_mapping=lambda: {"failure_kind": "start_failed"},
            ),
        )
        success = SimpleNamespace(
            succeeded=True, stdout=framed_json(header, record, footer)
        )

        with tempfile.TemporaryDirectory() as tmp:
            platform, helper = self._platform(Path(tmp))
            with patch.object(
                verifier,
                "_compile_helper",
                return_value=SimpleNamespace(output=helper),
            ), patch.object(
                verifier,
                "execute_binary_tool",
                side_effect=(transient, success),
            ) as execute, patch.object(
                verifier, "verifier_identity", return_value="verifier-id",
            ):
                result = verifier.verify_class_definitions(
                    platform, {name: content}
                )

        self.assertEqual(execute.call_count, 2)
        self.assertEqual(result[name]["status"], "definition_ready")

    def test_isolated_process_failure_excludes_nondeterministic_tool_detail(self):
        first = verifier._verification_process_failure(
            "demo/A",
            "a" * 64,
            verifier.ClassDefinitionVerifierError(
                "CLASS_DEFINITION_VERIFIER_FAILED",
                "/tmp/run-one/classes.bundle: access denied",
            ),
        )
        second = verifier._verification_process_failure(
            "demo/A",
            "a" * 64,
            verifier.ClassDefinitionVerifierError(
                "CLASS_DEFINITION_VERIFIER_FAILED",
                "C:/Temp/run-two/classes.bundle: WinError 5",
            ),
        )

        self.assertEqual(first, second)
        self.assertNotIn("bundle", first["failure_message"])

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

        with self.assertRaises(
            verifier.ClassDefinitionVerifierError
        ) as missing_expected:
            verifier._parse_verifier_output(
                framed_json(header, valid_record),
                [name],
                {name: content},
                {},
            )
        self.assertEqual(
            missing_expected.exception.reason_code,
            "CLASS_DEFINITION_PROTOCOL_CLASS_SET_INVALID",
        )

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

    def _compiled_binding_fixture(self):
        root = Path(self.temp.name) if hasattr(self, "temp") else None
        if root is None:
            self._binding_temp = tempfile.TemporaryDirectory()
            self.addCleanup(self._binding_temp.cleanup)
            root = Path(self._binding_temp.name)
        case = root / f"binding-{len(list(root.iterdir()))}"
        case.mkdir()
        source = (case / "ClassDefinitionVerifier.java").resolve()
        javac = (case / "javac").resolve()
        output = (case / "compiled").resolve()
        output.mkdir()
        source.write_bytes(b"final class ClassDefinitionVerifier {}")
        javac.write_bytes(b"javac")
        (output / "A.class").write_bytes(b"prefix")
        (output / "ClassDefinitionVerifier.class").write_bytes(b"main")
        nested = output / "nested"
        nested.mkdir()
        (nested / "Helper.class").write_bytes(b"nested")
        with patch.object(verifier, "JAVA_HELPER", source):
            manifest = verifier._compiled_helper_manifest(output)
        binding = verifier.CompiledDefinitionHelperBinding(
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            javac_path=str(javac),
            output_path=output,
            class_files=manifest,
        )
        return case, source, javac, output, binding

    def test_compiled_definition_binding_mapping_manifest_and_reuse_are_exact(self):
        case, source, _javac, output, binding = self._compiled_binding_fixture()
        case = case.resolve()
        mapping = binding.to_mapping()
        self.assertEqual(
            verifier.compiled_definition_helper_binding_from_mapping(mapping),
            binding,
        )
        invalid_mappings = [None, {**mapping, "extra": True}]
        changed = dict(mapping)
        changed["class_files"] = None
        invalid_mappings.append(changed)
        for item in (
            None,
            ["Only", 1],
            [1, 1, "a" * 64],
            ["Only.class", "1", "a" * 64],
            ["Only.class", 1, 1],
        ):
            changed = dict(mapping)
            changed["class_files"] = [item]
            invalid_mappings.append(changed)
        for index, value in enumerate(invalid_mappings):
            with self.subTest(mapping=index), self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ):
                verifier.compiled_definition_helper_binding_from_mapping(value)

        empty = case / "empty"
        empty.mkdir()
        no_main = case / "no-main"
        no_main.mkdir()
        (no_main / "Other.class").write_bytes(b"other")
        unexpected = case / "unexpected"
        unexpected.mkdir()
        (unexpected / "note.txt").write_text("not bytecode", encoding="utf-8")
        regular_file_root = case / "regular-file-root"
        regular_file_root.write_bytes(b"not a directory")
        fifo_root = case / "fifo-root"
        fifo_root.mkdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo_root / "entry.class")
        linked_root = case / "linked-root"
        linked_root.symlink_to(output, target_is_directory=True)
        linked_entry = case / "linked-entry"
        linked_entry.mkdir()
        (linked_entry / "Alias.class").symlink_to(
            output / "ClassDefinitionVerifier.class"
        )
        for value in (
            Path("relative"), case / "missing", empty, no_main, unexpected,
            regular_file_root, linked_root, linked_entry,
            *((fifo_root,) if hasattr(os, "mkfifo") else ()),
        ):
            with self.subTest(manifest=str(value)), self.assertRaises(
                verifier.ClassDefinitionVerifierError
            ):
                verifier._compiled_helper_manifest(value)

        verifier._INSTALLED_COMPILED_DEFINITION_HELPER = None
        self.addCleanup(
            setattr, verifier, "_INSTALLED_COMPILED_DEFINITION_HELPER", None
        )
        with patch.object(verifier, "JAVA_HELPER", source):
            compiled = verifier._compiled_helper_from_binding(binding)
            self.assertEqual(compiled.output, output)
            verifier.install_compiled_definition_helper_binding(binding)
            verifier.verify_compiled_definition_helper_binding(binding)
        self.assertEqual(
            verifier._INSTALLED_COMPILED_DEFINITION_HELPER[0], binding
        )

        invalid = [
            object(),
            replace(binding, source_sha256="bad"),
            replace(binding, source_sha256="g" * 64),
            replace(
                binding,
                class_files=(("ClassDefinitionVerifier.class", 4, "bad"),),
            ),
            replace(binding, output_path=Path("relative")),
            replace(binding, javac_path=str(output / "missing-javac")),
        ]
        for index, value in enumerate(invalid):
            with self.subTest(binding=index), patch.object(
                verifier, "JAVA_HELPER", source
            ), self.assertRaises(verifier.ClassDefinitionVerifierError):
                verifier._compiled_helper_from_binding(value)

        with patch.object(verifier, "JAVA_HELPER", source), patch.object(
            verifier, "_sha256_file", return_value="0" * 64
        ), self.assertRaises(verifier.ClassDefinitionVerifierError):
            verifier._compiled_helper_from_binding(binding)
        with patch.object(verifier, "JAVA_HELPER", source), patch.object(
            verifier, "_compiled_helper_manifest", return_value=()
        ), self.assertRaises(verifier.ClassDefinitionVerifierError):
            verifier._compiled_helper_from_binding(binding)

    def test_compiled_definition_binding_capture_is_source_and_tool_bound(self):
        _case, source, javac, output, binding = self._compiled_binding_fixture()
        platform = SimpleNamespace(jdk_home=Path("/jdk"))
        compiled = verifier._CompiledDefinitionHelper(output, None)
        with patch.object(verifier, "JAVA_HELPER", source), patch.object(
            verifier, "jdk_tool_path", return_value=javac
        ), patch.object(
            verifier, "_compile_helper", return_value=compiled
        ):
            self.assertEqual(
                verifier.capture_compiled_definition_helper_binding(platform),
                binding,
            )
        with patch.object(verifier, "JAVA_HELPER", source), patch.object(
            verifier, "jdk_tool_path", return_value=output / "missing"
        ), self.assertRaises(verifier.ClassDefinitionVerifierError):
            verifier.capture_compiled_definition_helper_binding(platform)


if __name__ == "__main__":
    unittest.main()
