import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from oracle_independence import (  # noqa: E402
    BoundaryPolicy,
    audit_oracle_boundaries,
    validate_oracle_rows,
)


class OracleIndependenceTest(unittest.TestCase):
    def test_rejects_direct_aliased_and_dynamic_analyzer_dependencies(self):
        sources = {
            "direct.py": "import confidence_weighted_tracer\n",
            "alias.py": "from s4_jar_compare import run_japicmp as compare\n",
            "dynamic.py": "import importlib\nimportlib.import_module('step5_evidence_ingestion')\n",
            "dunder.py": "__import__('confidence_weighted_tracer')\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, source in sources.items():
                (root / name).write_text(source, encoding="utf-8")
            policy = BoundaryPolicy(
                oracle_files=tuple(sources),
                forbidden_modules=(
                    "confidence_weighted_tracer",
                    "s4_jar_compare",
                    "step5_evidence_ingestion",
                ),
                allowed_schema_modules=(),
            )

            report = audit_oracle_boundaries(root, policy)

        self.assertEqual(report.status, "failed")
        self.assertEqual(len(report.violations), 4)

    def test_allows_data_only_schema_import_but_not_calls_into_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "allowed.py").write_text(
                "from step5_evidence_model import EvidenceIdentity\n",
                encoding="utf-8",
            )
            policy = BoundaryPolicy(
                oracle_files=("allowed.py",),
                forbidden_modules=("step5_evidence_model",),
                allowed_schema_modules=("step5_evidence_model",),
            )
            report = audit_oracle_boundaries(root, policy)

        self.assertEqual(report.status, "passed")

    def test_runtime_rows_require_independent_producer_and_artifact_sha(self):
        rows = [
            {"identity": "a", "producer": "javap", "artifact_sha256": "a" * 64},
            {"identity": "b", "producer": "analyzer", "artifact_sha256": "b" * 64},
            {"identity": "c", "producer": "jdeps", "artifact_sha256": ""},
        ]

        errors = validate_oracle_rows(rows, forbidden_producers={"analyzer"})

        self.assertEqual(
            errors,
            (
                "forbidden_oracle_producer:b:analyzer",
                "missing_oracle_artifact_sha:c",
            ),
        )

    def test_repository_oracle_policy_is_clean(self):
        policy_data = json.loads(
            (ROOT / "tests" / "fixtures" / "oracle_boundary.json").read_text(encoding="utf-8")
        )
        report = audit_oracle_boundaries(ROOT, BoundaryPolicy.from_dict(policy_data))

        self.assertEqual(report.violations, ())


if __name__ == "__main__":
    unittest.main()
