import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "user_scenario_regression.py"
sys.path.insert(0, str(ROOT / "scripts"))

import user_scenario_regression as scenarios  # noqa: E402


class UserScenarioRegressionTest(unittest.TestCase):
    def test_java_classpath_uses_platform_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "Example.java").write_text(
                "class Example {}\n", encoding="utf-8",
            )
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr="",
            )
            with patch.object(
                scenarios, "_run", return_value=completed,
            ) as runner, patch.object(scenarios.os, "pathsep", ";"):
                scenarios._compile_java(
                    source,
                    root / "classes",
                    [root / "first.jar", root / "second.jar"],
                )

        command = runner.call_args.args[0]
        classpath = command[command.index("-cp") + 1]
        self.assertEqual(
            classpath,
            f"{root / 'first.jar'};{root / 'second.jar'}",
        )

    def test_default_workspace_uses_platform_temp_directory(self):
        args = scenarios.parse_args([])

        self.assertEqual(
            Path(args.workspace),
            Path(tempfile.gettempdir()) / "java-upgrade-user-scenario-regression",
        )

    def test_generated_user_scenarios_pass_and_cover_key_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "result.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--scenario",
                    "all",
                    "--workspace",
                    str(Path(tmp) / "workspace"),
                    "--json-out",
                    str(json_out),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            payload = json.loads(json_out.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "passed")
        by_name = {item["name"]: item for item in payload["results"]}
        self.assertEqual(
            by_name["transitive_deleted_dependency"]["details"]["summary"]["reachable"],
            1,
        )
        self.assertEqual(
            by_name["jar_primary_source_auxiliary"]["details"]["accepted"],
            [["com.example.Service.run", "BEHAVIOR_CHANGED"]],
        )
        self.assertIn(
            "com.example:dep-b:com.depb.BridgeB.call(String)",
            by_name["query_after_step5"]["details"]["query_stdout"],
        )
        delivery = by_name["delivery_output_journey"]
        self.assertEqual(delivery["status"], "passed")
        self.assertTrue(delivery["details"]["report"].endswith("deliverables/report.md"))


if __name__ == "__main__":
    unittest.main()
