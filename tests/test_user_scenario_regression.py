import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "user_scenario_regression.py"


class UserScenarioRegressionTest(unittest.TestCase):
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
