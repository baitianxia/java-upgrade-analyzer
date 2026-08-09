import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from oracle_independence import BoundaryPolicy, audit_oracle_boundaries, validate_oracle_rows  # noqa: E402


class OracleIndependenceTest(unittest.TestCase):
    def test_rejects_direct_aliased_and_dynamic_production_engine_dependencies(self):
        sources = {
            "direct.py": "import binary_decision_engine\n",
            "alias.py": "from binary_artifact_diff import snapshot_archive as scan\n",
            "dynamic.py": "import importlib\nimportlib.import_module('binary_trace_engine')\n",
            "dunder.py": "__import__('binary_runtime_reconciler')\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, source in sources.items():
                (root / name).write_text(source, encoding="utf-8")
            policy = BoundaryPolicy(
                tuple(sources),
                ("binary_decision_engine", "binary_artifact_diff",
                 "binary_trace_engine", "binary_runtime_reconciler"),
                (),
            )
            report = audit_oracle_boundaries(root, policy)
        self.assertEqual(report.status, "failed")
        self.assertEqual(len(report.violations), 4)

    def test_runtime_rows_require_independent_producer_and_artifact_sha(self):
        errors = validate_oracle_rows(
            [{"identity": "x", "producer": "binary_trace_engine", "artifact_sha256": "bad"}],
            forbidden_producers={"binary_trace_engine"},
        )
        self.assertEqual(len(errors), 2)

    def test_repository_binary_oracle_policy_is_clean(self):
        payload = json.loads((ROOT / "tests/fixtures/oracle_boundary.json").read_text())
        report = audit_oracle_boundaries(ROOT, BoundaryPolicy.from_dict(payload))
        self.assertEqual(report.status, "passed", report.violations)


if __name__ == "__main__":
    unittest.main()
