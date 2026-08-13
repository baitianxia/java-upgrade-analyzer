import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "public_cli_surface_v1.json"
).read_text(encoding="utf-8"))
OPTION = re.compile(r"(?<![A-Za-z0-9_-])--[a-z][a-z0-9-]*")


class PublicCliSurfaceBlackboxTest(unittest.TestCase):
    def test_every_public_command_has_exact_help_and_invalid_option_contract(self):
        invalid = TRUTH["invalid_option_contract"]
        declared_paths = []
        for command in TRUTH["commands"]:
            with self.subTest(command=command["id"], mode="help"):
                relative = command["path"]
                declared_paths.append(relative)
                completed = subprocess.run(
                    [sys.executable, str(ROOT / relative), "--help"],
                    cwd=str(ROOT), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", check=False,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(
                    sorted(set(OPTION.findall(completed.stdout))),
                    command["expected_options"],
                )
                for marker in command["required_help_markers"]:
                    self.assertIn(marker, completed.stdout)

            with self.subTest(command=command["id"], mode="invalid-option"):
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / command["path"]),
                        *command.get("invalid_option_prefix", []),
                        invalid["argument"],
                    ],
                    cwd=str(ROOT), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", check=False,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, invalid["exit_code"])
                for marker in invalid["stderr_markers"]:
                    self.assertIn(marker, completed.stderr)
                for marker in invalid["forbidden_stderr_markers"]:
                    self.assertNotIn(marker, completed.stderr)

        self.assertEqual(len(declared_paths), len(set(declared_paths)))


if __name__ == "__main__":
    unittest.main()
