import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
    / "tool_failure_public_contract_v1.json"
).read_text(encoding="utf-8"))


def jdk_home(java: str) -> Path:
    completed = subprocess.run(
        [java, "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False, timeout=30,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            candidate = Path(line.split("=", 1)[1].strip()).resolve()
            if (candidate / "jmods").is_dir():
                return candidate
    raise AssertionError("a full JDK home is required")


class PublicFailureContractsBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = required_tools()
        cls.home = jdk_home(cls.tools["java"])
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.case = json.loads((CASE_ROOT / "case.json").read_text(encoding="utf-8"))
        compiled = compile_fixture(CASE_ROOT, cls.root / "compiled", cls.tools)
        cls.artifacts = package_variant(
            compiled, cls.root / "compiled", variant="failure-contract"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def fake_jdk(self, mode: str) -> Path:
        target = self.root / f"jdk-{mode}"
        target.mkdir()
        (target / "bin").mkdir()
        os.symlink(self.home / "release", target / "release")
        os.symlink(self.home / "lib", target / "lib", target_is_directory=True)
        os.symlink(self.home / "jmods", target / "jmods", target_is_directory=True)
        os.symlink(self.tools["javac"], target / "bin" / "javac")
        os.symlink(self.tools["javap"], target / "bin" / "javap")
        wrapper = target / "bin" / "java"
        wrapper.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys, time\n"
            f"real = {str(self.tools['java'])!r}\n"
            f"mode = {mode!r}\n"
            "args = sys.argv[1:]\n"
            "if 'RuntimeOutcomeOracle' in args:\n"
            "    if mode == 'nonzero':\n"
            "        print('injected nonzero', file=sys.stderr); raise SystemExit(17)\n"
            "    if mode == 'timeout': time.sleep(1); raise SystemExit(0)\n"
            "    if mode == 'empty': raise SystemExit(0)\n"
            "    if mode == 'malformed': print('{not-json'); raise SystemExit(0)\n"
            "os.execv(real, [real, *args])\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        if mode == "missing":
            (target / "bin" / "javap").unlink()
        elif mode == "permission":
            wrapper.chmod(0o644)
        return target

    def test_environment_failures_are_preflighted_and_only_transient_failures_retry(self):
        for mode, expected in TRUTH["cases"].items():
            with self.subTest(mode=mode):
                fake_home = self.fake_jdk(mode)
                config = pipeline_config(
                    self.case, self.artifacts, java=self.tools["java"]
                )
                config["base"]["jdk_home"] = str(fake_home)
                config["current"]["jdk_home"] = str(fake_home)
                config["tool_execution_policy"] = {
                    "oracle_runtime_timeout_seconds": 0.05,
                    "oracle_max_attempts": TRUTH["max_attempts"],
                }
                run_root = self.root / f"run-{mode}"
                run_root.mkdir()
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
                    encoding="utf-8", errors="replace", check=False,
                    timeout=180,
                )
                self.assertEqual(completed.returncode, 1, completed.stderr[-4000:])
                self.assertEqual(completed.stdout, "")
                self.assertNotIn("Traceback", completed.stderr)
                public_failure = json.loads(completed.stderr)
                self.assertNotIn("traceback", public_failure)
                failure = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    public_failure,
                    {
                        key: value
                        for key, value in failure.items()
                        if key != "traceback"
                    },
                )
                self.assertEqual(failure["schema"], TRUTH["public_failure_schema"])
                self.assertEqual(failure["reason_code"], expected["reason_code"])
                self.assertTrue(failure["fail_closed"])
                self.assertIn("Traceback", failure["traceback"])
                cause = failure["cause"]
                if expected["phase"] == "static_preflight":
                    self.assertEqual(
                        cause["reason_code"], expected["cause_reason_code"]
                    )
                    self.assertEqual(failure["failed_phase"], "")
                else:
                    self.assertEqual(failure["failed_phase"], "independent_validation")
                    self.assertEqual(cause["failure_kind"], expected["failure_kind"])
                    self.assertEqual(cause["attempt_count"], expected["attempt_count"])
                    self.assertEqual(cause["max_attempts"], TRUTH["max_attempts"])
                    self.assertEqual(cause["retryable"], expected["retryable"])
                    self.assertEqual(
                        cause["retry_exhausted"], expected["retry_exhausted"]
                    )
                self.assertFalse(
                    (output_root / "active_binary_generation.json").exists(),
                    "a failed Oracle run activated an unvalidated generation",
                )


if __name__ == "__main__":
    unittest.main()
