import base64
import gc
import io
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper as helper  # noqa: E402


METHOD_TYPE_CORPUS_CLASS = base64.b64decode(
    "yv66vgAAAD0AEAEAFmF1ZGl0L01ldGhvZFR5cGVDb3JwdXMHAAEBABBqYXZhL2xhbmcvT2JqZWN0"
    "BwADAQANcHJpbWl0aXZlT25seQEAAygpVgEAByhJSltEKVoQAAcBAA9vYmplY3RBbmRBcnJheXMB"
    "AEMoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL3V0aWwvTGlzdDtbW0xhdWRpdC9UaGluZzspTGph"
    "dmEvdXRpbC9NYXA7EAAKAQAJZHVwbGljYXRlAQA5KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9s"
    "YW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7EAANAQAEQ29kZQAhAAIABAAAAAAAAwAJAAUA"
    "BgABAA8AAAAQAAEAAAAAAAQSCFexAAAAAAAJAAkABgABAA8AAAAQAAEAAAAAAAQSC1exAAAAAAAJ"
    "AAwABgABAA8AAAAQAAEAAAAAAAQSDlexAAAAAAAA"
)


class BinaryAsmHelperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("JDK java/javac is required")
        try:
            cls.asm_jar = helper.resolve_asm_jar()
        except helper.BinaryAsmError as error:
            raise unittest.SkipTest(str(error)) from error
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        source = root / "src" / "demo" / "Sample.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            """
            package demo;
            import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) @interface Marker { String value(); }
            @Marker("class")
            public class Sample {
                public static final int CONSTANT = 3;
                @Marker("field") private String value = "x";
                @Marker("method")
                public String choose(int n) {
                    try {
                        return switch (n) { case 1 -> value + CONSTANT; default -> "other"; };
                    } catch (RuntimeException error) {
                        return error.getMessage();
                    }
                }
                public Runnable lambda() { return () -> choose(1); }
                public double positiveInfinity() { return Double.POSITIVE_INFINITY; }
                public float notANumber() { return Float.NaN; }
            }
            """,
            encoding="utf-8",
        )
        classes = root / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)
        cls.class_file = classes / "demo" / "Sample.class"

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def class_input(self, payload=None, entry="demo/Sample.class"):
        return helper.BinaryClassInput(
            "artifact-instance-1",
            entry,
            self.class_file.read_bytes() if payload is None else payload,
        )

    def test_helper_source_remains_java8_source_and_api_compatible(self):
        javac = shutil.which("javac")
        version = subprocess.run(
            [javac, "-version"], capture_output=True, text=True, check=False,
        )
        self.assertEqual(version.returncode, 0, version.stderr)
        version_text = (version.stdout or version.stderr).strip().split()[-1]
        version_parts = version_text.split(".")
        major = int(
            version_parts[1]
            if version_parts[0] == "1" else version_parts[0]
        )
        compatibility_flags = (
            ["--release", "8"]
            if major >= 9 else ["-source", "8", "-target", "8"]
        )
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [
                    javac,
                    *compatibility_flags,
                    "-encoding", "UTF-8",
                    "-cp", str(self.asm_jar),
                    "-d", tmp,
                    str(helper.JAVA_HELPER),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            class_bytes = (Path(tmp) / "BinaryFactExtractor.class").read_bytes()
            self.assertEqual(int.from_bytes(class_bytes[6:8], "big"), 52)

    @staticmethod
    def _successful_helper_compile(command, **_kwargs):
        output = Path(command[command.index("-d") + 1])
        (output / "BinaryFactExtractor.class").write_bytes(b"compiled")
        return SimpleNamespace(succeeded=True)

    def test_compiled_helper_directory_follows_cache_and_owner_lifetime(self):
        helper._compile_helper.cache_clear()
        self.addCleanup(helper._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            helper,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            helper,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            compiled = helper._compile_helper(
                "asm-cache-test.jar", "a" * 64, "javac", "java"
            )
            output = compiled.output
            cached = helper._compile_helper(
                "asm-cache-test.jar", "a" * 64, "javac", "java"
            )
            self.assertIs(cached, compiled)
            self.assertTrue(output.is_dir())

            del cached, compiled
            gc.collect()
            self.assertTrue(output.is_dir())
            helper._compile_helper.cache_clear()
            gc.collect()
            self.assertFalse(output.exists())

    def test_lru_eviction_removes_only_the_evicted_helper_directory(self):
        helper._compile_helper.cache_clear()
        self.addCleanup(helper._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            helper,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            helper,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            outputs = []
            for index in range(9):
                compiled = helper._compile_helper(
                    f"asm-eviction-{index}.jar",
                    f"{index:064x}",
                    "javac",
                    "java",
                )
                outputs.append(compiled.output)
                del compiled
            gc.collect()

            self.assertFalse(outputs[0].exists())
            self.assertTrue(all(path.is_dir() for path in outputs[1:]))
            helper._compile_helper.cache_clear()
            gc.collect()
            self.assertTrue(all(not path.exists() for path in outputs))

    def test_compile_failure_and_incomplete_output_clean_owned_directory(self):
        helper._compile_helper.cache_clear()
        self.addCleanup(helper._compile_helper.cache_clear)
        failed = SimpleNamespace(
            succeeded=False,
            failure=SimpleNamespace(
                to_mapping=lambda: {"failure_kind": "exit", "returncode": 1}
            ),
        )
        cases = (
            (failed, "ASM_HELPER_COMPILE_FAILED"),
            (SimpleNamespace(succeeded=True), "ASM_HELPER_COMPILE_INCOMPLETE"),
        )
        for index, (completed, expected_reason) in enumerate(cases):
            with (
                self.subTest(expected_reason=expected_reason),
                tempfile.TemporaryDirectory() as tmp,
                patch.object(
                    helper,
                    "make_short_temp_dir",
                    side_effect=lambda prefix: Path(
                        tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
                    ),
                ),
                patch.object(
                    helper, "execute_binary_tool", return_value=completed
                ),
            ):
                with self.assertRaises(helper.BinaryAsmError) as raised:
                    helper._compile_helper(
                        f"asm-failure-{index}.jar",
                        str(index) * 64,
                        "javac",
                        "java",
                    )
                self.assertEqual(raised.exception.reason_code, expected_reason)
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_timer_start_failure_reaps_started_helper_tree_and_closes_pipe(self):
        class BrokenTimer:
            daemon = False

            def __init__(self, _seconds, _callback):
                self.cancelled = False

            def start(self):
                raise RuntimeError("timer thread unavailable")

            def cancel(self):
                self.cancelled = True

        stdout = io.BytesIO()
        process = SimpleNamespace(
            pid=43210,
            stdin=None,
            stdout=stdout,
            stderr=None,
            returncode=None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asm = root / "asm.jar"
            asm.write_bytes(b"asm")
            classes = root / "classes"
            classes.mkdir()
            compiled = SimpleNamespace(output=classes, java=sys.executable)
            with patch.object(helper, "resolve_asm_jar", return_value=asm), patch.object(
                helper, "parser_identity", return_value=("identity", "helper-sha")
            ), patch.object(
                helper, "_compile_helper", return_value=compiled
            ), patch.object(
                helper, "managed_popen", return_value=process
            ), patch.object(
                helper.threading, "Timer", BrokenTimer
            ), patch.object(
                helper, "terminate_process_tree"
            ) as terminate, patch.object(
                helper, "release_process_tree"
            ) as release:
                with self.assertRaisesRegex(RuntimeError, "timer thread unavailable"):
                    helper.extract_class_facts([
                        helper.BinaryClassInput("artifact", "Sample.class", b"class")
                    ])

        terminate.assert_called_once_with(process)
        release.assert_called_once_with(process)
        self.assertTrue(stdout.closed)

    def test_late_timer_callback_does_not_kill_completed_helper_and_is_joined(self):
        timers = []

        class LateTimer:
            daemon = False

            def __init__(self, _seconds, callback):
                self.callback = callback
                self.started = False
                self.cancelled = False
                self.joined = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                self.cancelled = True

            def join(self):
                self.joined = True
                # Deterministically model a timer callback that was already
                # queued when cancel() raced with successful helper completion.
                self.callback()

        with patch.object(helper.threading, "Timer", LateTimer), patch.object(
            helper, "terminate_process_tree"
        ) as terminate:
            result = helper.extract_class_facts([self.class_input()])

        self.assertEqual(result.failure_record_count, 0)
        self.assertEqual(len(timers), 1)
        self.assertTrue(timers[0].started)
        self.assertTrue(timers[0].cancelled)
        self.assertTrue(timers[0].joined)
        terminate.assert_not_called()

    def test_cleanup_does_not_remove_directory_owned_by_another_process(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            helper,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ):
            owner = helper._OwnedHelperDirectory("binary-asm-helper")
            output = owner.path
            helper._remove_owned_helper_directory(output, os.getpid() + 1)
            self.assertTrue(output.is_dir())
            owner.cleanup()
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "fork is unavailable")
    def test_forked_child_cache_clear_does_not_remove_parent_helper(self):
        helper._compile_helper.cache_clear()
        self.addCleanup(helper._compile_helper.cache_clear)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            helper,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            helper,
            "execute_binary_tool",
            side_effect=self._successful_helper_compile,
        ):
            compiled = helper._compile_helper(
                "asm-fork-test.jar", "f" * 64, "javac", "java"
            )
            output = compiled.output
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    helper._compile_helper.cache_clear()
                    del compiled
                    gc.collect()
                    os._exit(0 if output.is_dir() else 2)
                except BaseException:
                    os._exit(1)

            waited_pid, status = os.waitpid(child_pid, 0)
            self.assertEqual(waited_pid, child_pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertTrue((output / "BinaryFactExtractor.class").is_file())
            cached = helper._compile_helper(
                "asm-fork-test.jar", "f" * 64, "javac", "java"
            )
            self.assertIs(cached, compiled)

            del cached, compiled
            helper._compile_helper.cache_clear()
            gc.collect()
            self.assertFalse(output.exists())

    def test_concurrent_same_key_compiles_keep_each_owned_directory_live(self):
        helper._compile_helper.cache_clear()
        self.addCleanup(helper._compile_helper.cache_clear)
        barrier = threading.Barrier(2)
        results = []
        failures = []

        def compile_concurrently(command, **_kwargs):
            barrier.wait(timeout=10)
            return self._successful_helper_compile(command)

        def run_compile():
            try:
                results.append(
                    helper._compile_helper(
                        "asm-concurrent-test.jar", "c" * 64, "javac", "java"
                    )
                )
            except BaseException as error:
                failures.append(error)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            helper,
            "make_short_temp_dir",
            side_effect=lambda prefix: Path(
                tempfile.mkdtemp(prefix=f"{prefix}-", dir=tmp)
            ),
        ), patch.object(
            helper, "execute_binary_tool", side_effect=compile_concurrently
        ):
            threads = [threading.Thread(target=run_compile) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertEqual(len(results), 2)
            outputs = [item.output for item in results]
            self.assertEqual(len(set(outputs)), 2)
            self.assertTrue(all(path.is_dir() for path in outputs))

            helper._compile_helper.cache_clear()
            self.assertTrue(all(path.is_dir() for path in outputs))
            results.clear()
            gc.collect()
            self.assertTrue(all(not path.exists() for path in outputs))

    def test_real_helper_compilation_directories_are_removed_on_process_exit(self):
        javac = shutil.which("javac")
        java = shutil.which("java")
        self.assertTrue(javac and java)
        script = """
import json
import sys
from pathlib import Path

import binary_asm_helper as asm
import binary_definition_verifier as definition

asm_jar = Path(sys.argv[1])
javac = sys.argv[2]
java = sys.argv[3]
asm_compiled = asm._compile_helper(
    str(asm_jar), asm._sha256_file(asm.JAVA_HELPER), javac, java
)
definition_compiled = definition._compile_helper(
    javac, definition._sha256_file(definition.JAVA_HELPER)
)
assert asm._compile_helper(
    str(asm_jar), asm._sha256_file(asm.JAVA_HELPER), javac, java
) is asm_compiled
assert definition._compile_helper(
    javac, definition._sha256_file(definition.JAVA_HELPER)
) is definition_compiled
assert asm_compiled.output.is_dir()
assert definition_compiled.output.is_dir()
print(json.dumps([
    str(asm_compiled.output),
    str(definition_compiled.output),
]))
"""
        with tempfile.TemporaryDirectory() as tmp:
            short_root = Path(tmp) / "short-root"
            environment = dict(os.environ)
            existing_pythonpath = environment.get("PYTHONPATH", "")
            environment["PYTHONPATH"] = os.pathsep.join(
                value
                for value in (str(ROOT_DIR / "scripts"), existing_pythonpath)
                if value
            )
            environment["JUA_SHORT_TEMP_ROOT"] = str(short_root)
            completed = subprocess.run(
                [sys.executable, "-c", script, str(self.asm_jar), javac, java],
                cwd=ROOT_DIR,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            compiled_paths = [Path(value) for value in json.loads(completed.stdout)]
            self.assertEqual(len(compiled_paths), 2)
            self.assertTrue(all(not path.exists() for path in compiled_paths))
            self.assertEqual(list(short_root.iterdir()), [])

    def test_parser_identity_binds_exact_helper_asm_and_artifact_diff_contract(self):
        identity, source_sha = helper.parser_identity(asm_jar=self.asm_jar)
        support = json.loads(
            helper.SUPPORT_MANIFEST.read_text(encoding="utf-8")
        )
        support_identity = helper.canonical_identity(
            "artifact_diff_support_manifest_identity",
            support["artifact_diff_support_manifest"],
            schema_version="1",
        )
        expected_paths = (
            "artifact_safety.py",
            "binary_artifact_diff.py",
            "binary_asm_helper.py",
            "binary_first_contract.py",
            "binary_snapshot_cache.py",
            "binary_tool_execution.py",
            "compat.py",
            "jdk_preflight.py",
            "java/BinaryFactExtractor.java",
            "path_runtime.py",
        )
        expected_identity = helper.canonical_identity(
            "binary_asm_parser_identity",
            {
                "protocol_schema": "binary-fact-frame-v1",
                "output_schema": "binary-class-fact-v1",
                "asm_version": helper.ASM_VERSION,
                "asm_jar_sha256": helper.ASM_SHA256,
                "helper_sha256": hashlib.sha256(
                    helper.JAVA_HELPER.read_bytes()
                ).hexdigest(),
                "visitor_policy_version": "asm-lossless-facts-v3",
                "max_supported_class_major": 70,
                "implementation_sources": [
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(
                            (ROOT_DIR / "scripts" / relative).read_bytes()
                        ).hexdigest(),
                    }
                    for relative in expected_paths
                ],
                "artifact_diff_support_manifest_identity": support_identity,
            },
            schema_version="1",
        )

        self.assertEqual(tuple(helper.PARSER_IMPLEMENTATION_SOURCE_PATHS), expected_paths)
        self.assertEqual(identity, expected_identity)
        self.assertEqual(len(identity), 64)
        self.assertEqual(len(source_sha), 64)
        self.assertEqual(helper._sha256_file(self.asm_jar), helper.ASM_SHA256)

    def test_unrelated_gate_metadata_does_not_invalidate_snapshot_cache(self):
        original = json.loads(helper.SUPPORT_MANIFEST.read_text(encoding="utf-8"))
        unrelated = json.loads(json.dumps(original))
        unrelated["performance_gate"]["sha256"] = "f" * 64
        relevant = json.loads(json.dumps(original))
        relevant["artifact_diff_support_manifest"]["artifact_safety_policy"][
            "max_archive_entries"
        ] += 1
        root = Path(self.temp.name)
        original_path = root / "support-original.json"
        unrelated_path = root / "support-unrelated.json"
        relevant_path = root / "support-relevant.json"
        for path, value in (
            (original_path, original),
            (unrelated_path, unrelated),
            (relevant_path, relevant),
        ):
            path.write_text(json.dumps(value), encoding="utf-8")

        with patch.object(helper, "SUPPORT_MANIFEST", original_path):
            original_identity, _ = helper.parser_identity(asm_jar=self.asm_jar)
        with patch.object(helper, "SUPPORT_MANIFEST", unrelated_path):
            unrelated_identity, _ = helper.parser_identity(asm_jar=self.asm_jar)
        with patch.object(helper, "SUPPORT_MANIFEST", relevant_path):
            with self.assertRaises(helper.BinaryAsmError) as changed:
                helper.parser_identity(asm_jar=self.asm_jar)

        self.assertEqual(original_identity, unrelated_identity)
        self.assertEqual(
            changed.exception.reason_code,
            "ASM_IMPLEMENTATION_CHANGED_DURING_RUN",
        )

    def test_parser_dependency_bytes_change_identity_and_fail_closed_mid_run(self):
        original_identity, _ = helper.parser_identity(asm_jar=self.asm_jar)
        changed_sources = dict(
            helper._CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS
        )
        changed_sources["artifact_safety.py"] = "0" * 64
        changed_identity = helper._parser_identity_from_inputs(
            changed_sources,
            helper._CAPTURED_ARTIFACT_DIFF_SUPPORT_IDENTITY,
        )

        self.assertNotEqual(original_identity, changed_identity)
        with patch.object(
            helper,
            "_parser_implementation_source_digests",
            return_value=changed_sources,
        ):
            with self.assertRaises(helper.BinaryAsmError) as raised:
                helper.parser_identity(asm_jar=self.asm_jar)
        self.assertEqual(
            raised.exception.reason_code,
            "ASM_IMPLEMENTATION_CHANGED_DURING_RUN",
        )

    def test_extracts_contract_ir_dynamic_and_raw_attribute_inventory(self):
        run = helper.extract_class_facts([self.class_input()], asm_jar=self.asm_jar)

        self.assertEqual(run.coverage_status, "complete")
        self.assertEqual(run.fact_record_count, 1)
        self.assertEqual(run.failure_record_count, 0)
        fact = run.records[0]
        self.assertEqual(fact["class_name"], "demo/Sample")
        self.assertEqual(fact["class_bytes_sha256"], helper._sha256_file(self.class_file))
        methods = {item["contract"]["name"]: item for item in fact["methods"]}
        self.assertIn("choose", methods)
        self.assertIn("lambda", methods)
        instruction_kinds = {
            instruction[0]
            for method in methods.values()
            for instruction in method["instructions"]
        }
        self.assertIn("invokedynamic", instruction_kinds)
        self.assertIn("lookupswitch", instruction_kinds)
        special_floats = {
            instruction[2]["kind"]
            for method in methods.values()
            for instruction in method["instructions"]
            if instruction[0] == "ldc"
            and len(instruction) > 2
            and isinstance(instruction[2], dict)
            and str(instruction[2].get("kind") or "").startswith("non_finite_")
        }
        self.assertEqual(
            special_floats, {"non_finite_double", "non_finite_float"}
        )
        self.assertTrue(methods["choose"]["try_catch"])
        attributes = {(item["level"], item["name"]) for item in fact["attribute_inventory"]}
        self.assertIn(("method", "Code"), attributes)
        self.assertIn(("code", "LineNumberTable"), attributes)
        self.assertIn(("class", "BootstrapMethods"), attributes)
        self.assertTrue(fact["attribute_inventory_digest"])
        self.assertTrue(fact["class_contract_digest"])

    def test_method_type_ldc_is_not_serialized_as_a_class_literal(self):
        run = helper.extract_class_facts(
            [helper.BinaryClassInput(
                "method-type-instance",
                "audit/MethodTypeCorpus.class",
                METHOD_TYPE_CORPUS_CLASS,
            )],
            asm_jar=self.asm_jar,
        )

        constants = {
            method["contract"]["name"]: instruction[2]
            for method in run.records[0]["methods"]
            for instruction in method["instructions"]
            if instruction[0] == "ldc"
        }
        self.assertEqual(set(constants), {
            "primitiveOnly", "objectAndArrays", "duplicate",
        })
        self.assertTrue(all(
            constant["kind"] == "method_type"
            for constant in constants.values()
        ))
        self.assertEqual(
            constants["objectAndArrays"]["descriptor"],
            "(Ljava/lang/String;[Ljava/util/List;[[Laudit/Thing;)"
            "Ljava/util/Map;",
        )

    def test_normalized_digests_are_deterministic_across_helper_processes(self):
        first = helper.extract_class_facts([self.class_input()], asm_jar=self.asm_jar)
        second = helper.extract_class_facts([self.class_input()], asm_jar=self.asm_jar)

        first_fact, second_fact = first.records[0], second.records[0]
        self.assertEqual(first_fact["class_contract_digest"], second_fact["class_contract_digest"])
        self.assertEqual(first_fact["attribute_inventory_digest"], second_fact["attribute_inventory_digest"])
        self.assertEqual(
            [item["implementation_digest"] for item in first_fact["methods"]],
            [item["implementation_digest"] for item in second_fact["methods"]],
        )
        self.assertEqual(first.fact_output_digest, second.fact_output_digest)

    def test_unsupported_major_is_scoped_failure_not_silent_fallback(self):
        payload = bytearray(self.class_file.read_bytes())
        payload[6:8] = (helper.MAX_SUPPORTED_CLASS_MAJOR + 1).to_bytes(2, "big")

        run = helper.extract_class_facts(
            [self.class_input(bytes(payload))], asm_jar=self.asm_jar
        )

        self.assertEqual(run.coverage_status, "partial")
        self.assertEqual(run.fact_record_count, 0)
        self.assertEqual(run.failure_record_count, 1)
        self.assertEqual(run.records[0]["frame_type"], "class_failure")
        self.assertEqual(run.records[0]["failure_kind"], "UnsupportedClassVersionError")

    def test_streaming_consumer_can_avoid_retaining_fact_records(self):
        consumed = []
        run = helper.extract_class_facts(
            [self.class_input()],
            asm_jar=self.asm_jar,
            record_consumer=consumed.append,
            retain_records=False,
        )

        self.assertEqual(run.records, ())
        self.assertEqual(len(consumed), 1)
        self.assertEqual(consumed[0]["class_name"], "demo/Sample")

    def test_duplicate_and_oversized_inputs_fail_before_helper_execution(self):
        item = self.class_input()
        with self.assertRaises(helper.BinaryAsmError) as duplicate:
            helper.extract_class_facts([item, item], asm_jar=self.asm_jar)
        self.assertEqual(duplicate.exception.reason_code, "ASM_INPUT_CLASS_DUPLICATE")

        with self.assertRaises(helper.BinaryAsmError) as oversized:
            helper.extract_class_facts(
                [item], asm_jar=self.asm_jar, max_class_bytes=len(item.class_bytes) - 1
            )
        self.assertEqual(oversized.exception.reason_code, "ASM_CLASS_SIZE_LIMIT_EXCEEDED")

    def test_frame_reader_rejects_stray_or_unbounded_stdout(self):
        with self.assertRaises(helper.BinaryAsmError) as partial:
            helper._read_frame(io.BytesIO(b"\x00"), max_frame_bytes=100)
        self.assertEqual(partial.exception.reason_code, "ASM_PROTOCOL_STRAY_BYTES")

        with self.assertRaises(helper.BinaryAsmError) as unbounded:
            helper._read_frame(io.BytesIO((101).to_bytes(4, "big")), max_frame_bytes=100)
        self.assertEqual(unbounded.exception.reason_code, "ASM_PROTOCOL_FRAME_LENGTH_INVALID")

    def test_wrong_explicit_asm_jar_is_rejected_by_sha(self):
        wrong = Path(self.temp.name) / "wrong-asm.jar"
        wrong.write_bytes(b"not asm")
        with self.assertRaises(helper.BinaryAsmError) as error:
            helper.resolve_asm_jar(wrong)
        self.assertEqual(error.exception.reason_code, "ASM_PINNED_JAR_SHA256_MISMATCH")


if __name__ == "__main__":
    unittest.main()
