import math
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_test_health_gate import (  # noqa: E402
    _run_gate_command,
    branch_probe,
    mutation_probe,
    repeat_health_probe,
)


class BinaryTestHealthGateTest(unittest.TestCase):
    def test_core_branch_alternatives_are_exercised(self):
        result = branch_probe()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["coverage_ratio"], 1.0)
        self.assertEqual(result["uncovered_lines"], [])

    def test_contract_mutants_are_killed(self):
        result = mutation_probe()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["mutation_count"], result["killed_count"])

    def test_repeat_health_requires_same_test_count_and_time_budget(self):
        result = repeat_health_probe(
            ("tests.test_binary_tool_execution",),
            repeats=2,
            timeout_seconds=30,
        )
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(result["stable_test_count"])

    @unittest.skipIf(os.name == "nt", "POSIX process-group semantics only")
    def test_gate_worker_timeout_terminates_descendant_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child_pid_path = root / "child.pid"
            helper = root / "gate_parent.py"
            helper.write_text(
                """import subprocess
import sys
import time
from pathlib import Path

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
time.sleep(60)
""",
                encoding="utf-8",
            )
            _completed, timed_out = _run_gate_command(
                [sys.executable, str(helper), str(child_pid_path)],
                cwd=root,
                timeout_seconds=0.5,
            )

            self.assertTrue(timed_out)
            self.assertTrue(child_pid_path.is_file())
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 3
            child_alive = True
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    child_alive = False
                    break
                proc_stat = Path(f"/proc/{child_pid}/stat")
                if proc_stat.is_file():
                    fields = proc_stat.read_text(encoding="utf-8").split()
                    if len(fields) > 2 and fields[2] == "Z":
                        child_alive = False
                        break
                time.sleep(0.05)

        self.assertFalse(child_alive, "timed-out gate descendant remained alive")


if __name__ == "__main__":
    unittest.main()
