import ast
from pathlib import Path
import unittest


ROOT_DIR = Path(__file__).resolve().parents[1]


class EvidenceCompletenessVisibilityInvariantTest(unittest.TestCase):
    def test_critical_evidence_paths_have_no_bare_or_pass_handlers(self):
        paths = (
            "scripts/confidence_weighted_tracer.py",
            "scripts/exhaustive_api_oracle.py",
            "scripts/final_artifact_edge_oracle.py",
            "scripts/real_project_regression.py",
            "scripts/s5_call_chain_engine_integrated.py",
            "scripts/step5_evidence_ingestion.py",
        )
        violations = []
        for relative_path in paths:
            tree = ast.parse(
                (ROOT_DIR / relative_path).read_text(encoding="utf-8"),
                filename=relative_path,
            )
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                if node.type is None:
                    violations.append(f"{relative_path}:{node.lineno}:bare-except")
                if node.body and all(isinstance(item, ast.Pass) for item in node.body):
                    violations.append(f"{relative_path}:{node.lineno}:pass-handler")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
