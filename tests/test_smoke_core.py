import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from .smoke_test_base import SmokeRegressionTestCase
except ImportError:  # pragma: no cover - direct unittest discovery imports as top-level module
    from smoke_test_base import SmokeRegressionTestCase

from scripts import smoke_regression


class SmokeCoreTest(SmokeRegressionTestCase):
    def test_checkpoint_distinguishes_gate_stage(self):
        self.assertEqual(
            smoke_regression.smoke_script_checkpoint(
                "gate.py", ["--step", "step1_scope", "--report-dir", "report"]
            ),
            "script-gate-step1_scope",
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
