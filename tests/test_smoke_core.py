import json
import os
import subprocess
import sys
import tempfile
import zipfile
import io
from pathlib import Path

try:
    from .smoke_test_base import SmokeRegressionTestCase
except ImportError:  # pragma: no cover - direct unittest discovery imports as top-level module
    from smoke_test_base import SmokeRegressionTestCase

from scripts import smoke_regression


class SmokeCoreTest(SmokeRegressionTestCase):
    def test_fake_maven_packages_dependency_from_explicit_repository_not_platform_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "HEAD").write_text("ref: refs/heads/current\n", encoding="utf-8")
            script = root / "fake-mvn"
            script.write_text(smoke_regression.fake_maven_script_text(), encoding="utf-8")
            repository = root / "fixture-repository"
            dependency = repository / "com" / "example" / "demo-lib" / "2.0.0" / "demo-lib-2.0.0.jar"
            dependency.parent.mkdir(parents=True)
            with zipfile.ZipFile(dependency, "w") as archive:
                archive.writestr("META-INF/spring.factories", "fixture=true\n")

            env = dict(os.environ)
            env["HOME"] = str(root / "wrong-home")
            env["MAVEN_REPO_LOCAL"] = str(repository)
            completed = subprocess.run(
                [sys.executable, str(script), "package"],
                cwd=str(root),
                env=env,
                capture_output=True,
            )

            artifact = root / "target" / "demo-app-2.0.0.jar"
            with zipfile.ZipFile(artifact) as outer:
                nested_bytes = outer.read("BOOT-INF/lib/demo-lib-2.0.0.jar")
            with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested:
                names = set(nested.namelist())

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        self.assertIn("META-INF/spring.factories", names)

    def test_checkpoint_distinguishes_gate_stage(self):
        self.assertEqual(
            smoke_regression.smoke_script_checkpoint(
                "gate.py", ["--step", "step1_scope", "--report-dir", "report"]
            ),
            "script-gate-step1_scope",
        )

    def test_gate_failure_reason_lists_missing_artifacts_without_localized_text(self):
        reason = smoke_regression.gate_failure_reason(
            "门控未通过：以下扫描文件缺失："
            "['s3_dependency_compat.csv', 's3_dependency_classfile.csv']"
        )

        self.assertEqual(
            reason,
            "missing-s3_dependency_classfile-s3_dependency_compat",
        )

    def test_successful_child_command_advances_checkpoint_to_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            smoke_regression.run_script(
                "gate.py", ["--step", "scan", "--report-dir", tmp]
            )

        self.assertEqual(
            smoke_regression._SMOKE_CHECKPOINT,
            "script-gate-scan-passed",
        )

    def test_failed_smoke_assertion_records_callsite(self):
        try:
            smoke_regression.assert_true(False, "expected failure")
        except AssertionError:
            pass
        else:
            self.fail("assert_true should fail")

        self.assertRegex(
            smoke_regression._SMOKE_CHECKPOINT,
            r"^assert-test_failed_smoke_assertion_records_callsite-line-\d+$",
        )

    def test_failure_writes_machine_readable_last_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "smoke-result.json"
            env = dict(os.environ)
            env["PATH"] = ""
            completed = subprocess.run(
                [
                    sys.executable,
                    str(smoke_regression.SCRIPT_DIR / "smoke_regression.py"),
                    "--group",
                    "core",
                    "--json-out",
                    str(output),
                ],
                cwd=str(smoke_regression.SCRIPT_DIR.parent),
                env=env,
                capture_output=True,
            )

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(payload["status"], "failed")
        self.assertRegex(payload["checkpoint"], r"^[a-z0-9._-]+$")
        self.assertTrue(payload["checkpoint"].startswith("external-git"))

    def test_fixture_exposes_windows_maven_launcher_and_explicit_local_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = smoke_regression.create_smoke_workspace(Path(tmp))
            smoke_regression.initialize_smoke_project(workspace)
            env = smoke_regression.build_smoke_dep_env(workspace)

            self.assertTrue((workspace.fake_bin / "mvn.cmd").is_file())
            self.assertEqual(
                env["MAVEN_REPO_LOCAL"],
                str(workspace.fake_home / ".m2" / "repository"),
            )

    def test_core_group(self):
        self.run_smoke_group("core")
