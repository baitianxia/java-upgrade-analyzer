import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import xml.etree.ElementTree as ET

from tests.blackbox.harness import (
    compile_fixture,
    package_variant,
    pipeline_config,
    required_tools,
)


ROOT = Path(__file__).resolve().parents[2]
CASE_ROOT = ROOT / "tests" / "fixtures" / "blackbox" / "implementation-change-v1"
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "artifact_safety_public_contract_v1.json"
).read_text(encoding="utf-8"))


def rewrite_archive(
    source: Path,
    target: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    additions: tuple[tuple[str, bytes], ...] = (),
) -> Path:
    replacements = replacements or {}
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(
        target, "w", compression=zipfile.ZIP_DEFLATED
    ) as new:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for info in old.infolist():
                if info.is_dir():
                    continue
                new.writestr(
                    info.filename, replacements.get(info.filename, old.read(info))
                )
            for name, payload in additions:
                new.writestr(name, payload)
    return target


def zip_observation(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        names = [item.filename for item in infos]
        return {
            "entry_count": len(infos),
            "duplicate_names": sorted({name for name in names if names.count(name) > 1}),
            "total_uncompressed_bytes": sum(item.file_size for item in infos),
            "maximum_expansion_ratio": max(
                (item.file_size / max(item.compress_size, 1) for item in infos),
                default=0,
            ),
        }


class PublicArtifactSafetyBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = required_tools()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.case = json.loads((CASE_ROOT / "case.json").read_text(encoding="utf-8"))
        cls.compiled = compile_fixture(CASE_ROOT, cls.root / "compiled", cls.tools)
        cls.baseline = package_variant(
            cls.compiled, cls.root / "compiled", variant="artifact-safety"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def invoke(
        self,
        name: str,
        artifacts: dict[str, Path],
        *,
        limits: dict[str, object] | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess, dict[str, object], Path]:
        run_root = self.root / "runs" / name
        run_root.mkdir(parents=True)
        config = pipeline_config(self.case, artifacts, java=self.tools["java"])
        if limits is not None:
            config["artifact_safety_limits"] = limits
        config_path = run_root / "config.json"
        result_path = run_root / "result.json"
        output_root = run_root / "output"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "binary_pipeline.py"),
                "--config", str(config_path),
                "--output-root", str(output_root),
                "--result-json", str(result_path),
            ],
            cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False, timeout=180,
            env=env,
        )
        public = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(public, json.loads(completed.stdout or completed.stderr))
        self.assertNotIn("Traceback", completed.stderr)
        return completed, public, output_root

    def assert_failed(
        self, completed: subprocess.CompletedProcess, public: dict[str, object],
        output_root: Path, *, reason: str, detail_marker: str,
    ) -> None:
        self.assertEqual(completed.returncode, 1, completed.stderr[-4000:])
        self.assertEqual(public["schema"], TRUTH["failure_schema"])
        self.assertEqual(public["reason_code"], reason)
        if detail_marker:
            self.assertIn(detail_marker, public["detail"])
        self.assertTrue(public["fail_closed"])
        self.assertFalse((output_root / "active_binary_generation.json").exists())

    def changed_artifacts(self, name: str, jar: Path) -> dict[str, Path]:
        result = dict(self.baseline)
        result[name] = jar
        return result

    def test_duplicate_corrupt_unsupported_and_partial_resource_are_public(self):
        class_name = "contract/BehaviorApi.class"
        with zipfile.ZipFile(self.baseline["current"]) as archive:
            original = archive.read(class_name)

        duplicate = rewrite_archive(
            self.baseline["current"], self.root / "mutated" / "duplicate.jar",
            additions=((class_name, original),),
        )
        self.assertEqual(zip_observation(duplicate)["duplicate_names"], [class_name])
        completed, public, output = self.invoke(
            "duplicate", self.changed_artifacts("current", duplicate)
        )
        self.assert_failed(
            completed, public, output,
            reason=TRUTH["blocking_reason"], detail_marker="ARCHIVE_DUPLICATE_ENTRY",
        )

        corrupt_bytes = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"broken-classfile"
        corrupt = rewrite_archive(
            self.baseline["current"], self.root / "mutated" / "corrupt-class.jar",
            replacements={class_name: corrupt_bytes},
        )
        jvm = subprocess.run(
            [
                self.tools["java"], "-cp",
                os.pathsep.join(map(str, (corrupt, self.baseline["business"], self.baseline["oracle"]))),
                self.case["oracle_main_class"], "reachable",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=30,
        )
        self.assertNotEqual(jvm.returncode, 0)
        self.assertIn(TRUTH["corrupt_class_jvm_error"], jvm.stderr)
        completed, public, output = self.invoke(
            "corrupt-class", self.changed_artifacts("current", corrupt)
        )
        self.assertEqual(completed.returncode, 1, completed.stderr[-4000:])
        self.assertTrue(public["fail_closed"])
        self.assertIn("class", public["detail"].lower())
        self.assertFalse((output / "active_binary_generation.json").exists())

        unsupported_bytes = bytearray(original)
        unsupported_bytes[6:8] = (71).to_bytes(2, "big")
        unsupported = rewrite_archive(
            self.baseline["current"], self.root / "mutated" / "unsupported-class.jar",
            replacements={class_name: bytes(unsupported_bytes)},
        )
        self.assertEqual(int.from_bytes(unsupported_bytes[6:8], "big"), 71)
        jvm = subprocess.run(
            [
                self.tools["java"], "-cp",
                os.pathsep.join(map(str, (unsupported, self.baseline["business"], self.baseline["oracle"]))),
                self.case["oracle_main_class"], "reachable",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=30,
        )
        self.assertNotEqual(jvm.returncode, 0)
        self.assertIn(TRUTH["unsupported_class_jvm_error"], jvm.stderr)
        completed, public, output = self.invoke(
            "unsupported-class", self.changed_artifacts("current", unsupported)
        )
        self.assertEqual(completed.returncode, 1, completed.stderr[-4000:])
        self.assertEqual(
            public["reason_code"], "BINARY_INDEPENDENT_VALIDATION_FAILED"
        )
        self.assertTrue(public["fail_closed"])
        self.assertTrue(public["cause"])
        self.assertFalse((output / "active_binary_generation.json").exists())

        malformed_xml = b"<beans><bean id='broken'"
        with self.assertRaises(ET.ParseError):
            ET.fromstring(malformed_xml)
        malformed = rewrite_archive(
            self.baseline["business"], self.root / "mutated" / "malformed-resource.jar",
            additions=(("META-INF/spring/context.xml", malformed_xml),),
        )
        completed, public, output = self.invoke(
            "malformed-resource", self.changed_artifacts("business", malformed)
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        self.assertEqual(public["validation_status"], "passed")
        self.assertEqual(public["trace_coverage_status"], "partial")
        coverage = json.loads((
            Path(public["generation_directory"]) / "binary_coverage.json"
        ).read_text(encoding="utf-8"))
        self.assertTrue(any(
            str(gap).endswith(TRUTH["malformed_xml_gap_suffix"])
            for gap in coverage["trace_coverage_gaps"]
        ), coverage["trace_coverage_gaps"])
        self.assertTrue((output / "active_binary_generation.json").is_file())

    def test_every_archive_and_helper_budget_is_enforced_publicly(self):
        nested_payload = io.BytesIO()
        with zipfile.ZipFile(nested_payload, "w") as nested:
            nested.writestr("marker.txt", b"nested archive marker" * 4)
        nested = rewrite_archive(
            self.baseline["current"], self.root / "mutated" / "nested.jar",
            additions=(("BOOT-INF/lib/nested.jar", nested_payload.getvalue()),),
        )
        with zipfile.ZipFile(self.baseline["current"]) as archive:
            original_class = archive.read("contract/BehaviorApi.class")
        two_classes = rewrite_archive(
            self.baseline["current"], self.root / "mutated" / "two-classes.jar",
            additions=(("contract/Second.class", original_class),),
        )
        cases = (
            ("entries", self.changed_artifacts("current", nested), {"max_archive_entries": 1}, "max_archive_entries"),
            ("bytes", self.baseline, {"max_total_uncompressed_bytes": 10}, "max_total_uncompressed_bytes"),
            ("ratio", self.baseline, {"max_expansion_ratio": 1}, "max_expansion_ratio"),
            ("depth", self.changed_artifacts("current", nested), {"max_nested_depth": 0}, "max_nested_depth"),
            ("nested-bytes", self.changed_artifacts("current", nested), {"max_nested_archive_bytes": 10}, "max_nested_archive_bytes"),
            ("class-bytes", self.baseline, {"max_class_bytes": 16}, "max_class_bytes"),
            ("frame-bytes", self.baseline, {"max_protocol_frame_bytes": 64}, "max_protocol_frame_bytes"),
            ("records", self.changed_artifacts("current", two_classes), {"max_fact_records": 1}, "max_fact_records"),
        )
        for name, artifacts, limits, truth_key in cases:
            with self.subTest(limit=name):
                completed, public, output = self.invoke(name, artifacts, limits=limits)
                expected = TRUTH["limit_cases"][truth_key]
                reason = (
                    TRUTH["blocking_reason"]
                    if expected.startswith("ARCHIVE_") else expected
                )
                self.assert_failed(
                    completed, public, output,
                    reason=reason,
                    detail_marker=expected if expected.startswith("ARCHIVE_") else "",
                )

        completed, public, output = self.invoke(
            "cannot-loosen", self.baseline,
            limits={"max_archive_entries": 100001},
        )
        self.assert_failed(
            completed, public, output,
            reason="BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            detail_marker="max_archive_entries",
        )

    def test_helper_heap_and_deadline_are_applied_by_the_public_cli(self):
        wrapper_root = self.root / "java-wrapper"
        wrapper_root.mkdir()
        log_path = wrapper_root / "java-args.jsonl"
        wrapper = wrapper_root / "java"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys, time\n"
            f"real={self.tools['java']!r}\n"
            f"log=pathlib.Path({str(log_path)!r})\n"
            "with log.open('a', encoding='utf-8') as out: out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "if os.environ.get('JUA_TEST_SLEEP_HELPER') == '1' and 'BinaryFactExtractor' in sys.argv:\n"
            "    time.sleep(1)\n"
            "os.execv(real, [real, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = str(wrapper_root) + os.pathsep + environment.get("PATH", "")

        completed, public, _output = self.invoke(
            "heap", self.baseline,
            limits={"helper_max_heap": f"{TRUTH['minimum_helper_heap_megabytes']}m"},
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
        logged = [json.loads(line) for line in log_path.read_text().splitlines()]
        helper_calls = [args for args in logged if "BinaryFactExtractor" in args]
        self.assertTrue(helper_calls)
        self.assertTrue(any(
            f"-Xmx{TRUTH['minimum_helper_heap_megabytes']}m" in args
            for args in helper_calls
        ))
        self.assertEqual(
            public["artifact_safety_policy"]["helper_max_heap"],
            f"{TRUTH['minimum_helper_heap_megabytes']}m",
        )

        environment["JUA_TEST_SLEEP_HELPER"] = "1"
        completed, public, output = self.invoke(
            "timeout", self.baseline,
            limits={"helper_timeout_seconds": 0.05}, env=environment,
        )
        self.assert_failed(
            completed, public, output,
            reason="ASM_HELPER_TIMEOUT", detail_marker="0.05",
        )


if __name__ == "__main__":
    unittest.main()
