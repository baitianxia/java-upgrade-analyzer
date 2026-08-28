import base64
import gc
import io
import hashlib
import json
import os
from dataclasses import replace
import shutil
import subprocess
import sys
import tempfile
import threading
import time
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

    @staticmethod
    def _frame(payload):
        encoded = helper._canonical_json(payload)
        return len(encoded).to_bytes(4, "big") + encoded

    def _run_fake_protocol(
        self,
        records=(),
        *,
        header_override=None,
        footer_override=None,
        omit_header=False,
        omit_footer=False,
        trailing=b"",
        returncode=0,
        max_records=helper.DEFAULT_MAX_RECORDS,
        stdout_override=Ellipsis,
        timer_type=None,
        process_poll=None,
        inputs=None,
        record_consumer=None,
        retain_records=True,
        raw_records_override=None,
        extract_options=None,
    ):
        identity = "identity"
        helper_sha = "helper-sha"
        asm = Path(self.temp.name) / "fake-protocol-asm.jar"
        asm.write_bytes(b"asm")
        classes = Path(self.temp.name) / "fake-protocol-classes"
        classes.mkdir(exist_ok=True)
        compiled = SimpleNamespace(output=classes, java="java")

        class PassiveTimer:
            daemon = False

            def __init__(self, _seconds, callback):
                self.callback = callback

            def start(self):
                pass

            def cancel(self):
                pass

            def join(self):
                pass

        selected_timer = timer_type or PassiveTimer

        def popen(_command, *, stdin, stdout, stderr):
            del stdout, stderr
            first_raw, first_present = helper._read_frame(
                stdin, max_frame_bytes=helper.DEFAULT_MAX_FRAME_BYTES
            )
            self.assertTrue(first_present)
            input_header = json.loads(first_raw)
            output_header = {
                "frame_type": "output_header",
                "protocol_schema": helper.PROTOCOL_SCHEMA,
                "output_schema": helper.OUTPUT_SCHEMA,
                "parser_identity": identity,
                "helper_sha256": helper_sha,
                "asm_version": helper.ASM_VERSION,
                "max_supported_class_major": helper.MAX_SUPPORTED_CLASS_MAJOR,
            }
            if header_override:
                output_header.update(header_override)
            raw_records = (
                list(raw_records_override)
                if raw_records_override is not None
                else [helper._canonical_json(record) for record in records]
            )
            record_digest = hashlib.sha256()
            for raw in raw_records:
                helper._framed_digest_update(record_digest, raw)
            fact_count = sum(
                record.get("frame_type") == "class_fact" for record in records
            )
            failure_count = sum(
                record.get("frame_type") == "class_failure" for record in records
            )
            output_footer = {
                "frame_type": "output_footer",
                "input_record_count": int(input_header["class_input_count"]),
                "fact_record_count": fact_count,
                "failure_record_count": failure_count,
                "output_record_count": len(records),
                "class_input_digest": input_header["class_input_digest"],
                "fact_output_digest": record_digest.hexdigest(),
                "coverage_status": "complete" if failure_count == 0 else "partial",
            }
            if footer_override:
                output_footer.update(footer_override)
            stream = bytearray()
            if not omit_header:
                stream.extend(self._frame(output_header))
            for raw in raw_records:
                stream.extend(len(raw).to_bytes(4, "big"))
                stream.extend(raw)
            if not omit_footer:
                stream.extend(self._frame(output_footer))
            stream.extend(trailing)
            actual_stdout = (
                io.BytesIO(bytes(stream))
                if stdout_override is Ellipsis
                else stdout_override
            )
            process = SimpleNamespace(
                pid=12345,
                stdout=actual_stdout,
                returncode=None,
                poll=process_poll or (lambda: 0),
            )

            def wait():
                callback = getattr(process, "wait_callback", None)
                if callback:
                    callback()
                process.returncode = returncode
                return returncode

            process.wait = wait
            self._last_fake_process = process
            return process

        with patch.object(helper, "resolve_asm_jar", return_value=asm), patch.object(
            helper, "parser_identity", return_value=(identity, helper_sha)
        ), patch.object(
            helper, "_compile_helper", return_value=compiled
        ), patch.object(
            helper, "managed_popen", side_effect=popen
        ), patch.object(
            helper.threading, "Timer", selected_timer
        ), patch.object(
            helper, "terminate_process_tree"
        ), patch.object(
            helper, "release_process_tree"
        ):
            options = {"max_records": max_records}
            options.update(extract_options or {})
            return helper.extract_class_facts(
                list(inputs) if inputs is not None else [self.class_input(b"class")],
                record_consumer=record_consumer,
                retain_records=retain_records,
                **options,
            )

    @staticmethod
    def _valid_fact_record(
        *,
        artifact="artifact-instance-1",
        entry="demo/Sample.class",
        payload=b"class",
    ):
        return {
            "frame_type": "class_fact",
            "artifact_instance_identity": artifact,
            "class_entry": entry,
            "class_bytes_sha256": hashlib.sha256(payload).hexdigest(),
            "class_name": entry.removesuffix(".class"),
            "class_major": 52,
            "class_access": 1,
            "fields": [],
            "methods": [],
            "attribute_inventory": [],
            "attribute_inventory_digest": "attributes",
            "class_contract_digest": "contract",
        }

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

    def test_live_deadline_callback_invokes_real_process_tree_termination(self):
        class ImmediateTimer:
            daemon = False

            def __init__(self, _seconds, callback):
                self.callback = callback

            def start(self):
                self.callback()

            def cancel(self):
                pass

            def join(self):
                pass

        process = SimpleNamespace(
            pid=987_654_321,
            stdin=None,
            stdout=io.BytesIO(),
            stderr=None,
            returncode=None,
            poll=lambda: None,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asm = root / "asm.jar"
            asm.write_bytes(b"asm")
            classes = root / "classes"
            classes.mkdir()
            compiled = SimpleNamespace(output=classes, java=sys.executable)
            with patch.object(
                helper, "resolve_asm_jar", return_value=asm,
            ), patch.object(
                helper, "parser_identity", return_value=("identity", "helper-sha"),
            ), patch.object(
                helper, "_compile_helper", return_value=compiled,
            ), patch.object(
                helper, "managed_popen", return_value=process,
            ), patch.object(
                helper.threading, "Timer", ImmediateTimer,
            ):
                with self.assertRaises(helper.BinaryAsmError) as raised:
                    helper.extract_class_facts([
                        helper.BinaryClassInput(
                            "artifact", "Sample.class", b"class",
                        ),
                    ])

        self.assertEqual(raised.exception.reason_code, "ASM_HELPER_TIMEOUT")
        self.assertTrue(process.stdout.closed)

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

    def test_run_scoped_parser_binding_reuses_exact_identity_and_reverifies(self):
        ordinary = helper.extract_class_facts(
            [self.class_input()], asm_jar=self.asm_jar
        )
        binding = helper.capture_parser_identity_binding(
            asm_jar=self.asm_jar
        )
        with patch.object(
            helper,
            "resolve_asm_jar",
            side_effect=AssertionError("binding use must not rehash ASM"),
        ), patch.object(
            helper,
            "_parser_implementation_source_digests",
            side_effect=AssertionError("binding use must not rehash sources"),
        ):
            bound = helper.extract_class_facts(
                [self.class_input()],
                asm_jar=self.asm_jar,
                parser_identity_binding=binding,
            )

        self.assertEqual(bound.records, ordinary.records)
        self.assertEqual(bound.parser_identity, ordinary.parser_identity)
        self.assertEqual(bound.helper_sha256, ordinary.helper_sha256)
        self.assertEqual(
            bound.class_input_digest, ordinary.class_input_digest
        )
        self.assertEqual(bound.fact_output_digest, ordinary.fact_output_digest)
        helper.verify_parser_identity_binding(binding)

    def test_run_scoped_parser_binding_fails_closed_on_change_or_mismatch(self):
        binding = helper.capture_parser_identity_binding(
            asm_jar=self.asm_jar
        )
        changed_sources = dict(
            helper._CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS
        )
        changed_sources["binary_asm_helper.py"] = "0" * 64
        with patch.object(
            helper,
            "_parser_implementation_source_digests",
            return_value=changed_sources,
        ):
            with self.assertRaises(helper.BinaryAsmError) as changed:
                helper.verify_parser_identity_binding(binding)
        self.assertEqual(
            changed.exception.reason_code,
            "ASM_IMPLEMENTATION_CHANGED_DURING_RUN",
        )

        with self.assertRaises(helper.BinaryAsmError) as mismatch:
            helper.parser_identity_from_binding(
                binding, asm_jar=Path(self.temp.name) / "different.jar"
            )
        self.assertEqual(
            mismatch.exception.reason_code,
            "ASM_PARSER_IDENTITY_BINDING_MISMATCH",
        )

        invalid_bindings = (
            object(),
            replace(binding, asm_path=Path("relative/asm.jar")),
            replace(binding, parser_identity=object()),
            replace(binding, parser_identity="short"),
            replace(binding, parser_identity="g" * 64),
            replace(binding, helper_sha256=object()),
            replace(binding, helper_sha256="short"),
            replace(binding, helper_sha256="g" * 64),
        )
        for index, invalid in enumerate(invalid_bindings):
            with self.subTest(invalid_binding=index), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper.parser_identity_from_binding(invalid)
            self.assertEqual(
                raised.exception.reason_code,
                "ASM_PARSER_IDENTITY_BINDING_INVALID",
            )

        bound_path = Path(binding.asm_path)
        verify_cases = (
            (bound_path.parent / "different.jar", binding.parser_identity,
             binding.helper_sha256),
            (bound_path, "0" * 64, binding.helper_sha256),
            (bound_path, binding.parser_identity, "0" * 64),
        )
        for index, (resolved, identity, helper_sha) in enumerate(verify_cases):
            with self.subTest(verify_case=index), patch.object(
                helper,
                "parser_identity_from_binding",
                return_value=(
                    bound_path, binding.parser_identity, binding.helper_sha256
                ),
            ), patch.object(
                helper, "resolve_asm_jar", return_value=resolved
            ), patch.object(
                helper,
                "_verified_parser_identity",
                return_value=(identity, helper_sha),
            ), self.assertRaises(helper.BinaryAsmError) as raised:
                helper.verify_parser_identity_binding(binding)
            self.assertEqual(
                raised.exception.reason_code,
                "ASM_PARSER_IDENTITY_BINDING_CHANGED",
            )

    def test_input_value_object_rejects_every_missing_and_type_boundary(self):
        cases = (
            ((None, "Entry.class", b"x"), "ASM_ARTIFACT_IDENTITY_MISSING"),
            (("", "Entry.class", b"x"), "ASM_ARTIFACT_IDENTITY_MISSING"),
            (("   ", "Entry.class", b"x"), "ASM_ARTIFACT_IDENTITY_MISSING"),
            (("artifact", None, b"x"), "ASM_CLASS_ENTRY_MISSING"),
            (("artifact", "", b"x"), "ASM_CLASS_ENTRY_MISSING"),
            (("artifact", "   ", b"x"), "ASM_CLASS_ENTRY_MISSING"),
            (("artifact", "Entry.class", bytearray(b"x")), "ASM_CLASS_BYTES_INVALID"),
            (("artifact", "Entry.class", None), "ASM_CLASS_BYTES_INVALID"),
        )
        for arguments, reason in cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper.BinaryClassInput(*arguments)
            self.assertEqual(raised.exception.reason_code, reason)

    def test_artifact_diff_support_manifest_rejects_every_external_shape(self):
        root = Path(self.temp.name)
        cases = (
            (root / "missing-support.json", "missing"),
            (root / "invalid-utf.json", b"\xff"),
            (root / "invalid-json.json", b"{"),
            (root / "missing-key.json", b"{}"),
            (
                root / "wrong-shape.json",
                b'{"artifact_diff_support_manifest":[]}',
            ),
        )
        for path, content in cases:
            if content != "missing":
                path.write_bytes(content)
            with self.subTest(path=path.name), patch.object(
                helper, "SUPPORT_MANIFEST", path
            ), self.assertRaises(helper.BinaryAsmError) as raised:
                helper._artifact_diff_support_identity()
            self.assertEqual(
                raised.exception.reason_code,
                "ASM_ARTIFACT_DIFF_SUPPORT_MANIFEST_INVALID",
            )

    def test_parser_identity_rejects_missing_and_extra_source_members(self):
        complete = dict(helper._CAPTURED_PARSER_IMPLEMENTATION_SOURCE_DIGESTS)
        variants = (dict(complete), dict(complete))
        variants[0].pop(next(iter(variants[0])))
        variants[1]["unowned.py"] = "0" * 64
        for values in variants:
            with self.subTest(paths=sorted(values)), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper._parser_identity_from_inputs(
                    values, helper._CAPTURED_ARTIFACT_DIFF_SUPPORT_IDENTITY
                )
            self.assertEqual(
                raised.exception.reason_code,
                "ASM_IMPLEMENTATION_SOURCE_SET_INVALID",
            )

    def test_compile_requires_java_and_javac_independently(self):
        cases = (
            ({"javac": None, "java": "java"},),
            ({"javac": "javac", "java": None},),
        )
        for (tools,) in cases:
            with self.subTest(tools=tools), patch.object(
                helper.shutil, "which", side_effect=tools.get
            ), self.assertRaises(helper.BinaryAsmError) as raised:
                helper._compile_helper.__wrapped__("asm.jar", "helper-sha")
            self.assertEqual(
                raised.exception.reason_code, "ASM_JAVA_TOOLCHAIN_MISSING"
            )

    def test_frame_primitives_cover_eof_chunking_truncation_and_length_bounds(self):
        class OneByteReader:
            def __init__(self, payload):
                self.payload = bytearray(payload)

            def read(self, _size):
                if not self.payload:
                    return b""
                return bytes((self.payload.pop(0),))

        self.assertEqual(helper._read_exact(OneByteReader(b"abc"), 3), b"abc")
        with self.assertRaises(helper.BinaryAsmError) as truncated:
            helper._read_exact(OneByteReader(b"a"), 2)
        self.assertEqual(truncated.exception.reason_code, "ASM_PROTOCOL_TRUNCATED")
        self.assertEqual(
            helper._read_frame(io.BytesIO(), max_frame_bytes=10), (b"", False)
        )
        for length in (0, 1):
            with self.subTest(length=length), self.assertRaises(
                helper.BinaryAsmError
            ) as invalid:
                helper._read_frame(
                    io.BytesIO(length.to_bytes(4, "big")), max_frame_bytes=10
                )
            self.assertEqual(
                invalid.exception.reason_code,
                "ASM_PROTOCOL_FRAME_LENGTH_INVALID",
            )
        payload = b"{}"
        framed = len(payload).to_bytes(4, "big") + payload
        self.assertEqual(
            helper._read_frame(io.BytesIO(framed), max_frame_bytes=10),
            (payload, True),
        )

    def test_resolver_covers_environment_and_missing_pinned_jar(self):
        env_jar = Path(self.temp.name) / "env-asm.jar"
        env_jar.write_bytes(b"asm")
        with patch.dict(
            os.environ, {"JUA_ASM_JAR": str(env_jar)}, clear=False
        ), patch.object(
            helper, "_sha256_file", return_value=helper.ASM_SHA256
        ):
            self.assertEqual(helper.resolve_asm_jar(), env_jar.resolve())

        missing = Path(self.temp.name) / "absent-asm.jar"
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(
            helper.BinaryAsmError
        ) as raised:
            helper.resolve_asm_jar(missing)
        self.assertEqual(raised.exception.reason_code, "ASM_PINNED_JAR_MISSING")

    def test_class_record_validator_covers_identity_failure_and_method_matrix(self):
        digest = hashlib.sha256(b"class").hexdigest()
        expected = {("artifact-instance-1", "demo/Sample.class"): digest}
        valid = self._valid_fact_record()
        helper._validate_class_record(valid, expected)

        empty_key = dict(valid)
        empty_key.update(
            artifact_instance_identity=None,
            class_entry=None,
            class_bytes_sha256=digest,
        )
        helper._validate_class_record(empty_key, {("", ""): digest})

        cases = []
        unknown = dict(valid, artifact_instance_identity="unknown")
        cases.append((unknown, expected, "ASM_PROTOCOL_UNKNOWN_CLASS_RECORD"))
        cases.append((dict(valid, class_bytes_sha256="wrong"), expected,
                      "ASM_PROTOCOL_CLASS_SHA_MISMATCH"))
        cases.append((dict(valid, frame_type="class_failure"), expected,
                      "ASM_PROTOCOL_FAILURE_INCOMPLETE"))
        incomplete = dict(valid)
        incomplete.pop("class_name")
        cases.append((incomplete, expected, "ASM_PROTOCOL_CLASS_FACT_INCOMPLETE"))
        cases.append((dict(valid, methods=[None]), expected,
                      "ASM_PROTOCOL_METHOD_FACT_INCOMPLETE"))
        cases.append((dict(valid, methods=[{"contract": {}}]), expected,
                      "ASM_PROTOCOL_METHOD_FACT_INCOMPLETE"))
        for record, known, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper._validate_class_record(record, known)
            self.assertEqual(raised.exception.reason_code, reason)

        failure = dict(
            valid,
            frame_type="class_failure",
            failure_kind="UnsupportedClassVersionError",
        )
        helper._validate_class_record(failure, expected)
        no_methods = dict(valid, methods=None)
        helper._validate_class_record(no_methods, expected)
        complete_method = dict(
            valid,
            methods=[{
                "contract": {},
                "instructions": [],
                "try_catch": [],
                "implementation_digest": "digest",
            }],
        )
        helper._validate_class_record(complete_method, expected)

    def test_extract_rejects_all_resource_and_input_boundaries_before_launch(self):
        direct_cases = (
            ({"max_heap_megabytes": 15}, "ASM_HELPER_HEAP_LIMIT_INVALID"),
            (
                {"max_heap_megabytes": helper.DEFAULT_MAX_HEAP_MEGABYTES + 1},
                "ASM_HELPER_HEAP_LIMIT_INVALID",
            ),
            ({"timeout_seconds": 0}, "ASM_HELPER_TIMEOUT_INVALID"),
            ({"timeout_seconds": -0.1}, "ASM_HELPER_TIMEOUT_INVALID"),
        )
        for options, reason in direct_cases:
            with self.subTest(options=options), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper.extract_class_facts([], **options)
            self.assertEqual(raised.exception.reason_code, reason)

        launch_cases = (
            ([object()], {}, "ASM_INPUT_TYPE_INVALID"),
            ([self.class_input(b"class")], {"max_records": 0},
             "ASM_INPUT_RECORD_LIMIT_EXCEEDED"),
            ([self.class_input(b"class")], {"max_class_bytes": 4},
             "ASM_CLASS_SIZE_LIMIT_EXCEEDED"),
            ([self.class_input(b"class")], {"max_frame_bytes": 2},
             "ASM_INPUT_FRAME_LIMIT_EXCEEDED"),
        )
        for inputs, options, reason in launch_cases:
            with self.subTest(reason=reason), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                self._run_fake_protocol(
                    inputs=inputs,
                    max_records=options.pop("max_records", helper.DEFAULT_MAX_RECORDS),
                    extract_options=options,
                )
            self.assertEqual(raised.exception.reason_code, reason)

    def test_extract_uses_bound_jdk_tools_when_home_is_supplied(self):
        record = self._valid_fact_record()
        with patch.object(
            helper,
            "jdk_tool_path",
            side_effect=(Path("/jdk/bin/javac"), Path("/jdk/bin/java")),
        ) as tool_path:
            run = self._run_fake_protocol(
                [record], extract_options={"jdk_home": "/jdk"}
            )
        self.assertEqual(run.fact_record_count, 1)
        self.assertEqual(
            tool_path.call_args_list,
            [unittest.mock.call("/jdk", "javac"), unittest.mock.call("/jdk", "java")],
        )

    def test_extract_rejects_each_protocol_header_frame_and_footer_violation(self):
        valid = self._valid_fact_record()

        def assert_reason(reason, **options):
            with self.subTest(reason=reason), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                self._run_fake_protocol(**options)
            self.assertEqual(raised.exception.reason_code, reason)

        assert_reason(
            "ASM_PROTOCOL_HEADER_MISSING",
            omit_header=True,
            omit_footer=True,
        )
        assert_reason(
            "ASM_PROTOCOL_HEADER_INVALID",
            header_override={"parser_identity": "wrong"},
        )
        assert_reason(
            "ASM_PROTOCOL_FOOTER_MISSING",
            omit_footer=True,
        )
        assert_reason(
            "ASM_PROTOCOL_JSON_INVALID",
            records=(),
            raw_records_override=[b"\xff\xff"],
        )
        assert_reason(
            "ASM_PROTOCOL_FRAME_TYPE_INVALID",
            records=({"frame_type": "unexpected"},),
        )
        assert_reason(
            "ASM_OUTPUT_RECORD_LIMIT_EXCEEDED",
            records=(valid, valid),
            max_records=1,
        )
        assert_reason(
            "ASM_PROTOCOL_CLASS_RECORD_DUPLICATE",
            records=(valid, valid),
            max_records=2,
        )
        assert_reason(
            "ASM_PROTOCOL_STRAY_BYTES",
            records=(valid,),
            trailing=b"x",
        )
        assert_reason(
            "ASM_HELPER_FAILED",
            records=(valid,),
            returncode=7,
        )
        assert_reason(
            "ASM_PROTOCOL_FOOTER_CONSERVATION_FAILED",
            records=(valid,),
            footer_override={"fact_record_count": 9},
        )
        assert_reason(
            "ASM_PROTOCOL_INPUT_OUTPUT_SET_MISMATCH",
            records=(),
        )

    def test_extract_cleans_up_when_process_has_no_stdout(self):
        with self.assertRaises(AssertionError):
            self._run_fake_protocol(stdout_override=None)
        self.assertIsNone(self._last_fake_process.stdout)

    def test_deadline_distinguishes_stopped_poll_failure_and_live_after_wait(self):
        owner = self

        class ImmediateStoppedTimer:
            daemon = False

            def __init__(self, _seconds, callback):
                self.callback = callback

            def start(self):
                self.callback()

            def cancel(self):
                pass

            def join(self):
                pass

        class AfterWaitTimer(ImmediateStoppedTimer):
            def start(self):
                owner._last_fake_process.wait_callback = self.callback

        valid = self._valid_fact_record()
        stopped = self._run_fake_protocol(
            [valid], timer_type=ImmediateStoppedTimer, process_poll=lambda: 0
        )
        self.assertEqual(stopped.fact_record_count, 1)

        def broken_poll():
            raise OSError("process handle closed")

        poll_failed = self._run_fake_protocol(
            [valid], timer_type=ImmediateStoppedTimer, process_poll=broken_poll
        )
        self.assertEqual(poll_failed.fact_record_count, 1)

        with self.assertRaises(helper.BinaryAsmError) as timed_out:
            self._run_fake_protocol(
                [valid], timer_type=AfterWaitTimer, process_poll=lambda: None
            )
        self.assertEqual(timed_out.exception.reason_code, "ASM_HELPER_TIMEOUT")

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

    def test_persistent_transport_is_exact_and_reuses_one_jvm(self):
        ordinary = helper.extract_class_facts(
            [self.class_input()], asm_jar=self.asm_jar
        )
        helper.close_persistent_asm_sessions()
        self.addCleanup(helper.close_persistent_asm_sessions)

        with patch.object(
            helper, "managed_popen", wraps=helper.managed_popen
        ) as popen:
            first = helper.extract_class_facts(
                [self.class_input()],
                asm_jar=self.asm_jar,
                persistent_session=True,
                persistent_max_sessions=1,
            )
            second = helper.extract_class_facts(
                [self.class_input()],
                asm_jar=self.asm_jar,
                persistent_session=True,
                persistent_max_sessions=1,
            )

        self.assertEqual(popen.call_count, 1)
        for reused in (first, second):
            self.assertEqual(reused.records, ordinary.records)
            self.assertEqual(
                reused.class_input_digest, ordinary.class_input_digest
            )
            self.assertEqual(
                reused.fact_output_digest, ordinary.fact_output_digest
            )
            self.assertEqual(
                (
                    reused.input_record_count,
                    reused.fact_record_count,
                    reused.failure_record_count,
                    reused.coverage_status,
                ),
                (
                    ordinary.input_record_count,
                    ordinary.fact_record_count,
                    ordinary.failure_record_count,
                    ordinary.coverage_status,
                ),
            )

    def test_persistent_transport_failure_uses_exact_one_shot_fallback(self):
        expected = helper.extract_class_facts(
            [self.class_input()], asm_jar=self.asm_jar
        )
        with patch.object(
            helper, "_run_persistent_helper", return_value=None
        ) as persistent, patch.object(
            helper,
            "_run_one_shot_helper",
            wraps=helper._run_one_shot_helper,
        ) as one_shot:
            actual = helper.extract_class_facts(
                [self.class_input()],
                asm_jar=self.asm_jar,
                persistent_session=True,
            )

        persistent.assert_called_once()
        one_shot.assert_called_once()
        self.assertEqual(actual.records, expected.records)
        self.assertEqual(actual.fact_output_digest, expected.fact_output_digest)

    def test_idle_persistent_sessions_use_bounded_protocol_shutdown(self):
        calls = []

        class IdleSession:
            def close(self, *, terminate):
                calls.append(terminate)

        pool = object.__new__(helper._AsmSessionPool)
        pool._condition = threading.Condition()
        pool._idle = helper.queue.LifoQueue()
        pool._idle.put(IdleSession())
        pool._idle.put(IdleSession())
        pool._session_count = 2
        pool._closed = False

        pool.close()

        self.assertEqual(calls, [False, False])
        self.assertEqual(pool._session_count, 0)
        self.assertTrue(pool._closed)

    def test_persistent_session_count_is_strictly_bounded(self):
        for value in (True, False, 0, 9, 1.5, "2"):
            with self.subTest(value=value), self.assertRaises(
                helper.BinaryAsmError
            ) as raised:
                helper.extract_class_facts(
                    [self.class_input()],
                    asm_jar=self.asm_jar,
                    persistent_max_sessions=value,
                )
            self.assertEqual(
                raised.exception.reason_code, "ASM_SESSION_COUNT_INVALID"
            )

    def test_persistent_session_transport_fails_closed_at_every_boundary(self):
        class Process:
            def __init__(self, *, poll_values=(None,), stdin=None, stderr=None):
                self.stdin = io.BytesIO() if stdin is None else stdin
                self.stdout = io.BytesIO(b"response")
                self.stderr = io.BytesIO() if stderr is None else stderr
                self.poll_values = list(poll_values)
                self.wait_calls = []

            def poll(self):
                if len(self.poll_values) > 1:
                    return self.poll_values.pop(0)
                return self.poll_values[0]

            def wait(self, timeout):
                self.wait_calls.append(timeout)
                return 0

        def session(process):
            value = object.__new__(helper._AsmSession)
            value.process = process
            value._closed = False
            value._close_lock = threading.Lock()
            value._stderr_tail = bytearray()
            return value

        with tempfile.TemporaryDirectory() as temporary:
            request = Path(temporary) / "request.bin"
            request.write_bytes(b"request")

            dead = session(Process(poll_values=(1,)))
            with self.assertRaises(helper._AsmSessionError):
                dead.exchange(request, lambda _stream: "parsed", 1)
            pipes = session(Process())
            pipes.process.stdin = None
            with self.assertRaises(helper._AsmSessionError):
                pipes.exchange(request, lambda _stream: "parsed", 1)
            missing_stdout = session(Process())
            missing_stdout.process.stdout = None
            with self.assertRaises(helper._AsmSessionError):
                missing_stdout.exchange(request, lambda _stream: "parsed", 1)

            class PassiveTimer:
                daemon = False

                def __init__(self, _seconds, callback):
                    self.callback = callback

                def start(self):
                    pass

                def cancel(self):
                    pass

                def join(self):
                    pass

            successful = session(Process())
            with patch.object(helper.threading, "Timer", PassiveTimer):
                self.assertEqual(
                    successful.exchange(
                        request, lambda _stream: "parsed", 1
                    ),
                    ("parsed", ""),
                )

            class BrokenWriter(io.BytesIO):
                def write(self, _value):
                    raise BrokenPipeError("expected")

            broken = session(Process(stdin=BrokenWriter()))
            with patch.object(helper.threading, "Timer", PassiveTimer), self.assertRaises(
                helper._AsmSessionError
            ):
                broken.exchange(request, lambda _stream: "parsed", 1)

            class PendingWriter:
                daemon = False

                def __init__(self, **_kwargs):
                    pass

                def start(self):
                    pass

                def join(self, **_kwargs):
                    pass

                def is_alive(self):
                    return True

            pending = session(Process())
            with patch.object(helper.threading, "Timer", PassiveTimer), patch.object(
                helper.threading, "Thread", PendingWriter
            ), self.assertRaises(helper._AsmSessionError):
                pending.exchange(request, lambda _stream: "parsed", 0.01)

            class ImmediateTimer(PassiveTimer):
                def start(self):
                    self.callback()

            timed_out = session(Process())
            timed_out.close = lambda **_kwargs: None
            with patch.object(helper.threading, "Timer", ImmediateTimer), self.assertRaises(
                helper._AsmSessionError
            ):
                timed_out.exchange(request, lambda _stream: "parsed", 1)

            class BrokenStartTimer(PassiveTimer):
                def start(self):
                    raise RuntimeError("timer start")

            start_failed = session(Process())
            with patch.object(
                helper.threading, "Timer", BrokenStartTimer
            ), self.assertRaisesRegex(RuntimeError, "timer start"):
                start_failed.exchange(request, lambda _stream: "parsed", 1)

            exited = session(Process(poll_values=(None, 1)))
            exited._stderr_tail.extend(b"exit-detail")
            with patch.object(helper.threading, "Timer", PassiveTimer), self.assertRaises(
                helper._AsmSessionError
            ):
                exited.exchange(request, lambda _stream: "parsed", 1)

            callback_without_live_process = session(
                Process(poll_values=(None, 1, 1))
            )
            with patch.object(
                helper.threading, "Timer", ImmediateTimer
            ), self.assertRaises(RuntimeError):
                callback_without_live_process.exchange(
                    request, lambda _stream: (_ for _ in ()).throw(
                        RuntimeError("reader")
                    ), 1
                )

        closed = session(Process())
        closed._closed = True
        self.assertFalse(closed.alive)
        closed.close(terminate=True)

        calls = []
        normal = session(Process())
        with patch.object(
            helper, "terminate_process_tree",
            side_effect=lambda _process: calls.append("terminate"),
        ), patch.object(
            helper, "release_process_tree",
            side_effect=lambda _process: calls.append("release"),
        ):
            normal.close(terminate=True)
        self.assertEqual(calls, ["terminate", "release"])

        no_handles = session(Process(poll_values=(1,)))
        no_handles.process.stdin = None
        no_handles.process.stdout = None
        no_handles.process.stderr = None
        with patch.object(helper, "release_process_tree") as release:
            no_handles.close(terminate=False)
        release.assert_called_once()

        for stderr in (None, io.BytesIO(b"x" * (70 * 1024))):
            draining = session(Process(stderr=stderr))
            draining.process.stderr = stderr
            draining._drain_stderr()
            if stderr is not None:
                self.assertEqual(len(draining._stderr_tail), 64 * 1024)

        class BrokenReader:
            def read(self, _size):
                raise OSError("expected")

        draining = session(Process(stderr=BrokenReader()))
        draining._drain_stderr()

    def test_persistent_pool_registry_lease_cleanup_and_fork_matrix(self):
        class FakeSession:
            def __init__(self, *, alive=True, error=None, close_error=None):
                self.alive = alive
                self.error = error
                self.close_error = close_error
                self.closed = []

            def exchange(self, *_args):
                if self.error:
                    raise self.error
                return ("parsed", "")

            def close(self, *, terminate):
                self.closed.append(terminate)
                if self.close_error:
                    raise self.close_error

        pool = object.__new__(helper._AsmSessionPool)
        pool._condition = threading.Condition()
        pool._idle = helper.queue.LifoQueue()
        pool._session_count = 0
        pool.max_sessions = 1
        pool._closed = False
        created = FakeSession()
        pool._new_session = lambda: created
        self.assertIs(pool._acquire(time.perf_counter() + 1), created)
        pool._idle.put(created)
        self.assertIs(pool._acquire(time.perf_counter() + 1), created)
        pool._closed = True
        with self.assertRaises(helper._AsmSessionError):
            pool._acquire(time.perf_counter() + 1)
        pool._closed = False
        pool._session_count = 1
        with self.assertRaises(helper._AsmSessionError):
            pool._acquire(time.perf_counter() - 1)

        class ReleasingCondition:
            def __init__(self, owner, released):
                self.owner = owner
                self.released = released

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def wait(self, *, timeout):
                self.owner._idle.put(self.released)

            def notify(self):
                pass

        waiting_pool = object.__new__(helper._AsmSessionPool)
        waiting_pool._idle = helper.queue.LifoQueue()
        waiting_pool._session_count = 1
        waiting_pool.max_sessions = 1
        waiting_pool._closed = False
        released = FakeSession()
        waiting_pool._condition = ReleasingCondition(waiting_pool, released)
        self.assertIs(
            waiting_pool._acquire(time.perf_counter() + 1), released
        )

        run_pool = object.__new__(helper._AsmSessionPool)
        run_pool._condition = threading.Condition()
        run_pool._idle = helper.queue.LifoQueue()
        run_pool._session_count = 1
        run_pool._closed = False
        reusable = FakeSession(alive=True)
        run_pool._acquire = lambda _deadline: reusable
        self.assertEqual(
            run_pool.run(Path("request"), lambda _stream: None, 1),
            ("parsed", ""),
        )
        self.assertIs(run_pool._idle.get_nowait(), reusable)
        run_pool._closed = True
        closed_reusable = FakeSession(alive=True)
        run_pool._acquire = lambda _deadline: closed_reusable
        run_pool._session_count = 1
        run_pool.run(Path("request"), lambda _stream: None, 1)
        self.assertEqual(closed_reusable.closed, [True])
        run_pool._closed = False
        failed = FakeSession(alive=False, error=helper._AsmSessionError("expected"))
        run_pool._acquire = lambda _deadline: failed
        run_pool._session_count = 1
        with self.assertRaises(helper._AsmSessionError):
            run_pool.run(Path("request"), lambda _stream: None, 1)
        self.assertEqual(failed.closed, [True])

        elapsed = FakeSession()
        run_pool._acquire = lambda _deadline: elapsed
        run_pool._session_count = 1
        with patch.object(
            helper.time, "perf_counter", side_effect=[0.0, 2.0]
        ), self.assertRaises(helper._AsmSessionError):
            run_pool.run(Path("request"), lambda _stream: None, 1)
        self.assertEqual(elapsed.closed, [True])

        already_closed = object.__new__(helper._AsmSessionPool)
        already_closed._condition = threading.Condition()
        already_closed._idle = helper.queue.LifoQueue()
        already_closed._session_count = 0
        already_closed._closed = True
        already_closed.close()
        close_failure = object.__new__(helper._AsmSessionPool)
        close_failure._condition = threading.Condition()
        close_failure._idle = helper.queue.LifoQueue()
        close_failure._idle.put(
            FakeSession(close_error=RuntimeError("close"))
        )
        close_failure._session_count = 1
        close_failure._closed = False
        with self.assertRaisesRegex(RuntimeError, "close"):
            close_failure.close()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            asm = root / "asm.jar"
            asm.write_bytes(b"asm")
            compiled = helper._CompiledAsmHelper(root, "java", None)
            calls = []

            class RegistryPool:
                def __init__(self, *_args):
                    calls.append("created")

                def run(self, *_args):
                    calls.append("run")
                    return ("parsed", "")

                def close(self):
                    calls.append("closed")

            helper._ASM_SESSION_POOLS.clear()
            arguments = dict(
                protocol_input=root / "request",
                compiled_helper=compiled,
                asm_path=asm,
                identity="identity",
                helper_sha="a" * 64,
                max_heap_megabytes=256,
                max_sessions=1,
                timeout_seconds=1,
                response_reader=lambda _stream: None,
            )
            with patch.object(helper, "_AsmSessionPool", RegistryPool):
                self.assertEqual(
                    helper._run_persistent_helper(**arguments),
                    ("parsed", ""),
                )
                self.assertEqual(
                    helper._run_persistent_helper(**arguments),
                    ("parsed", ""),
                )
            self.assertEqual(calls.count("created"), 1)
            helper.close_persistent_asm_sessions()
            helper.close_persistent_asm_sessions()
            self.assertIn("closed", calls)

            with patch.object(
                helper, "_persistent_pool_key",
                side_effect=helper._AsmSessionError("expected"),
            ):
                self.assertIsNone(helper._run_persistent_helper(**arguments))

        helper._ASM_SESSION_POOLS = {("old",): object()}
        old_lock = helper._ASM_SESSION_POOLS_LOCK
        helper._forget_persistent_asm_sessions_after_fork()
        self.assertEqual(helper._ASM_SESSION_POOLS, {})
        self.assertIsNot(helper._ASM_SESSION_POOLS_LOCK, old_lock)

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

    def _compiled_binding_fixture(self):
        root = Path(self.temp.name) / f"binding-{len(list(Path(self.temp.name).iterdir()))}"
        root.mkdir()
        asm = (root / "asm.jar").resolve()
        java = (root / "java").resolve()
        javac = (root / "javac").resolve()
        source = (root / "BinaryFactExtractor.java").resolve()
        output = (root / "compiled").resolve()
        output.mkdir()
        asm.write_bytes(b"asm")
        java.write_bytes(b"java")
        javac.write_bytes(b"javac")
        source.write_bytes(b"final class BinaryFactExtractor {}")
        (output / "A.class").write_bytes(b"prefix")
        (output / "BinaryFactExtractor.class").write_bytes(b"main")
        nested = output / "nested"
        nested.mkdir()
        (nested / "Helper.class").write_bytes(b"nested")
        with patch.object(helper, "JAVA_HELPER", source):
            manifest = helper._compiled_helper_manifest(output)
        binding = helper.CompiledAsmHelperBinding(
            asm_path=asm,
            helper_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            javac_path=str(javac),
            java_path=str(java),
            output_path=output,
            class_files=manifest,
        )
        return root, asm, java, javac, source, output, binding

    def test_compiled_helper_manifest_and_mapping_are_exact(self):
        root, _asm, _java, _javac, source, output, binding = (
            self._compiled_binding_fixture()
        )
        root = root.resolve()
        with patch.object(helper, "JAVA_HELPER", source):
            manifest = helper._compiled_helper_manifest(output)
        self.assertEqual(manifest, binding.class_files)
        mapping = binding.to_mapping()
        self.assertEqual(
            helper.compiled_asm_helper_binding_from_mapping(mapping), binding
        )

        invalid_mappings = [None, {**mapping, "extra": True}]
        no_files = dict(mapping)
        no_files["class_files"] = None
        invalid_mappings.append(no_files)
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
                helper.BinaryAsmError
            ):
                helper.compiled_asm_helper_binding_from_mapping(value)

        missing = root / "missing"
        empty = root / "empty"
        empty.mkdir()
        no_main = root / "no-main"
        no_main.mkdir()
        (no_main / "Other.class").write_bytes(b"other")
        unexpected = root / "unexpected"
        unexpected.mkdir()
        (unexpected / "note.txt").write_text("not bytecode", encoding="utf-8")
        regular_file_root = root / "regular-file-root"
        regular_file_root.write_bytes(b"not a directory")
        fifo_root = root / "fifo-root"
        fifo_root.mkdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(fifo_root / "entry.class")
        linked_root = root / "linked-root"
        linked_root.symlink_to(output, target_is_directory=True)
        linked_entry = root / "linked-entry"
        linked_entry.mkdir()
        (linked_entry / "Alias.class").symlink_to(
            output / "BinaryFactExtractor.class"
        )
        for value in (
            Path("relative"), missing, empty, no_main, unexpected,
            regular_file_root, linked_root, linked_entry,
            *((fifo_root,) if hasattr(os, "mkfifo") else ()),
        ):
            with self.subTest(manifest=str(value)), self.assertRaises(
                helper.BinaryAsmError
            ):
                helper._compiled_helper_manifest(value)

    def test_extract_installed_binding_operand_and_timeout_matrix(self):
        valid = self._valid_fact_record()
        asm = Path(self.temp.name) / "fake-protocol-asm.jar"
        javac = Path(shutil.which("javac")).resolve()
        java = Path(shutil.which("java")).resolve()
        compiled = SimpleNamespace(
            output=Path(self.temp.name) / "fake-protocol-classes",
            java="java",
        )

        def binding(**changes):
            values = {
                "asm_path": asm,
                "helper_sha256": "helper-sha",
                "javac_path": str(javac),
                "java_path": str(java),
            }
            values.update(changes)
            return SimpleNamespace(**values)

        installed_cases = (
            binding(asm_path=asm.parent / "other.jar"),
            binding(helper_sha256="different"),
            binding(javac_path="different"),
            binding(java_path="different"),
            binding(),
        )
        for index, installed_binding in enumerate(installed_cases):
            with self.subTest(installed=index), patch.object(
                helper,
                "_INSTALLED_COMPILED_ASM_HELPER",
                (installed_binding, compiled),
            ):
                run = self._run_fake_protocol([valid])
            self.assertEqual(run.fact_record_count, 1)

        for index, (tools, installed_binding) in enumerate((
            (
                {"javac": None, "java": str(java)},
                binding(javac_path=""),
            ),
            (
                {"javac": str(javac), "java": None},
                binding(java_path=""),
            ),
        )):
            with self.subTest(tool_case=index), patch.object(
                helper.shutil, "which", side_effect=tools.get
            ), patch.object(
                helper,
                "_INSTALLED_COMPILED_ASM_HELPER",
                (installed_binding, compiled),
            ):
                run = self._run_fake_protocol([valid])
            self.assertEqual(run.fact_record_count, 1)

        consumed = []
        with patch.object(
            helper, "_run_persistent_helper",
            side_effect=AssertionError("consumer must retain one-shot transport"),
        ):
            run = self._run_fake_protocol(
                [valid],
                record_consumer=consumed.append,
                retain_records=False,
                extract_options={"persistent_session": True},
            )
        self.assertEqual(run.fact_record_count, 1)
        self.assertEqual(consumed, [valid])

        with patch.object(
            helper, "_run_persistent_helper", return_value=None
        ), patch.object(
            helper.time, "perf_counter", side_effect=[0.0, 2.0]
        ), self.assertRaises(helper.BinaryAsmError) as timed_out:
            self._run_fake_protocol(
                [valid],
                extract_options={
                    "persistent_session": True,
                    "timeout_seconds": 1,
                },
            )
        self.assertEqual(timed_out.exception.reason_code, "ASM_HELPER_TIMEOUT")

    def test_compiled_binding_reuse_rejects_every_byte_and_path_change(self):
        _root, asm, _java, _javac, source, output, binding = (
            self._compiled_binding_fixture()
        )
        helper._INSTALLED_COMPILED_ASM_HELPER = None
        self.addCleanup(setattr, helper, "_INSTALLED_COMPILED_ASM_HELPER", None)
        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper, "resolve_asm_jar", return_value=asm
        ):
            compiled = helper._compiled_helper_from_binding(binding)
            self.assertEqual(compiled.output, output)
            self.assertIsNone(compiled._temporary_directory)
            helper.install_compiled_asm_helper_binding(binding)
            helper.verify_compiled_asm_helper_binding(binding)
        self.assertEqual(helper._INSTALLED_COMPILED_ASM_HELPER[0], binding)

        invalid = [
            object(),
            replace(binding, helper_sha256="bad"),
            replace(binding, helper_sha256="g" * 64),
            replace(
                binding,
                class_files=(("BinaryFactExtractor.class", 4, "bad"),),
            ),
            replace(binding, output_path=Path("relative")),
            replace(binding, java_path=str(output / "missing-java")),
            replace(binding, javac_path=str(output / "missing-javac")),
        ]
        for index, value in enumerate(invalid):
            with self.subTest(invalid=index), patch.object(
                helper, "JAVA_HELPER", source
            ), patch.object(
                helper, "resolve_asm_jar", return_value=asm
            ), self.assertRaises(helper.BinaryAsmError):
                helper._compiled_helper_from_binding(value)

        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper, "resolve_asm_jar", return_value=output / "different.jar"
        ), self.assertRaises(helper.BinaryAsmError):
            helper._compiled_helper_from_binding(binding)
        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper, "resolve_asm_jar", return_value=asm
        ), patch.object(
            helper, "_sha256_file", return_value="0" * 64
        ), self.assertRaises(helper.BinaryAsmError):
            helper._compiled_helper_from_binding(binding)
        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper, "resolve_asm_jar", return_value=asm
        ), patch.object(
            helper, "_compiled_helper_manifest", return_value=()
        ), self.assertRaises(helper.BinaryAsmError):
            helper._compiled_helper_from_binding(binding)

    def test_compiled_binding_capture_supports_both_toolchain_sources(self):
        _root, asm, java, javac, source, output, binding = (
            self._compiled_binding_fixture()
        )
        compiled = helper._CompiledAsmHelper(output, str(java), None)
        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper, "resolve_asm_jar", return_value=asm
        ), patch.object(
            helper, "parser_identity", return_value=("identity", binding.helper_sha256)
        ), patch.object(
            helper, "jdk_tool_path", side_effect=lambda _home, name: java if name == "java" else javac
        ), patch.object(
            helper, "_compile_helper", return_value=compiled
        ):
            captured = helper.capture_compiled_asm_helper_binding(
                asm_jar=asm, jdk_home=Path("/jdk")
            )
        self.assertEqual(captured, binding)

        parser_binding = object()
        with patch.object(helper, "JAVA_HELPER", source), patch.object(
            helper,
            "parser_identity_from_binding",
            return_value=(asm, "identity", binding.helper_sha256),
        ), patch.object(
            helper.shutil,
            "which",
            side_effect=lambda name: str(javac if name == "javac" else java),
        ), patch.object(helper, "_compile_helper", return_value=compiled):
            captured = helper.capture_compiled_asm_helper_binding(
                asm_jar=asm, parser_identity_binding=parser_binding
            )
        self.assertEqual(captured, binding)

        for tools in (
            {"javac": None, "java": str(java)},
            {"javac": str(javac), "java": None},
        ):
            with self.subTest(tools=tools), patch.object(
                helper, "resolve_asm_jar", return_value=asm
            ), patch.object(
                helper, "parser_identity", return_value=("identity", "a" * 64)
            ), patch.object(
                helper.shutil, "which", side_effect=tools.get
            ), self.assertRaises(helper.BinaryAsmError):
                helper.capture_compiled_asm_helper_binding(asm_jar=asm)


if __name__ == "__main__":
    unittest.main()
