import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_report import _product_change_row, _product_change_type  # noqa: E402
from s6_report import _change_summary, _human_change_type  # noqa: E402


class BinaryReportLabelsTest(unittest.TestCase):
    def test_added_method_is_not_described_as_behavior_change(self):
        decision = {
            "fact_kind": "method",
            "fact_scope": {"member_change_kind": "added"},
        }
        self.assertEqual(_product_change_type(decision), "METHOD_ADDED")
        self.assertEqual(_human_change_type("METHOD_ADDED", "method"), "新增方法")

    def test_added_class_is_not_described_as_method(self):
        decision = {
            "fact_kind": "class",
            "fact_scope": {"member_change_kind": "added"},
        }
        self.assertEqual(_product_change_type(decision), "CLASS_ADDED")
        self.assertEqual(_human_change_type("CLASS_ADDED", "class"), "新增类")

    def test_annotation_contract_change_is_not_described_as_signature_change(self):
        contract = {"access": 1, "descriptor": "(I)I"}
        decision = {
            "fact_kind": "method",
            "fact_scope": {"member_change_kind": "contract_changed"},
            "evidence": {
                "base_contract": contract,
                "current_contract": {**contract, "annotations": ["Ljava/lang/Deprecated;"]},
            },
        }
        self.assertEqual(_product_change_type(decision), "CONTRACT_CHANGED")
        self.assertEqual(_human_change_type("CONTRACT_CHANGED", "method"), "API 契约变化")

    def test_member_resolution_row_exposes_old_and_new_owners(self):
        decision = {
            "decision_identity": "decision-1",
            "change_fact_identity": "fact-1",
            "fact_kind": "member_resolution",
            "fact_scope": {
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "demo/Child",
                "member_kind": "method",
                "member_name": "value",
                "descriptor": "()I",
                "member_change_kind": "resolution_changed",
            },
            "reason_code": "RUNTIME_MEMBER_RESOLUTION_CHANGED",
            "dependency_artifacts": [{
                "side": "base",
                "logical_dependency_lineage": "com.acme:hierarchy",
                "coord": "com.acme:hierarchy:1",
            }, {
                "side": "current",
                "logical_dependency_lineage": "com.acme:hierarchy",
                "coord": "com.acme:hierarchy:2",
            }],
            "evidence": {
                "base_resolution": {"resolved_owner": "demo/ParentA"},
                "current_resolution": {"resolved_owner": "demo/ParentB"},
            },
        }
        row = _product_change_row(
            decision,
            {"analysis_projection_status": "targetable", "projection_coverage_status": "complete"},
            evidence_path="evidence.json",
        )
        self.assertEqual(row["change_type"], "MEMBER_RESOLUTION_CHANGED")
        self.assertEqual(row["old_value"], "demo/ParentA")
        self.assertEqual(row["new_value"], "demo/ParentB")
        self.assertIn(
            "解析目标：demo.ParentA → demo.ParentB",
            _change_summary(row),
        )


if __name__ == "__main__":
    unittest.main()
