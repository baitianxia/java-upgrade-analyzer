import os
import subprocess
import sys
from pathlib import Path
import unittest


ROOT_DIR = Path(__file__).resolve().parents[1]
SMOKE_SCRIPT = ROOT_DIR / "scripts" / "smoke_regression.py"


class SmokeRegressionTestCase(unittest.TestCase):
    maxDiff = None

    def run_smoke_group(self, group):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CI"] = "true"
        result = subprocess.run(
            [sys.executable, str(SMOKE_SCRIPT), "--group", group],
            cwd=ROOT_DIR,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"group={group}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn(f"SMOKE PASS [{group}]", result.stdout)
