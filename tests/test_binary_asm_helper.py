import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper as helper  # noqa: E402


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

    def test_parser_identity_binds_exact_helper_asm_and_support_manifest(self):
        identity, source_sha = helper.parser_identity(asm_jar=self.asm_jar)

        self.assertEqual(len(identity), 64)
        self.assertEqual(len(source_sha), 64)
        self.assertEqual(helper._sha256_file(self.asm_jar), helper.ASM_SHA256)

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
        self.assertTrue(methods["choose"]["try_catch"])
        attributes = {(item["level"], item["name"]) for item in fact["attribute_inventory"]}
        self.assertIn(("method", "Code"), attributes)
        self.assertIn(("code", "LineNumberTable"), attributes)
        self.assertIn(("class", "BootstrapMethods"), attributes)
        self.assertTrue(fact["attribute_inventory_digest"])
        self.assertTrue(fact["class_contract_digest"])

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
