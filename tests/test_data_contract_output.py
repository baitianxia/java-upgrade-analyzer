import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import enhanced_output_formatter as formatter
import s6_report


class DataContractOutputTest(unittest.TestCase):
    def test_step6_change_summary_explains_added_dto_field(self):
        summary = s6_report._change_summary({
            "change_type": "DATA_FIELD_ADDED",
            "symbol_kind": "field",
            "api_name": "com.vendor.dto.CustomerDTO.status",
            "api_simple": "status",
            "old_value": "",
            "new_value": "java.lang.String",
            "severity": "P2",
        })

        self.assertIn("DTO 字段新增", summary)
        self.assertIn("java.lang.String", summary)

    def test_reachable_alert_states_runtime_contract_risk_without_claiming_db_mismatch(self):
        result = SimpleNamespace(
            symbol_kind="field",
            change_type="DATA_FIELD_TYPE_CHANGED",
            api_name="com.vendor.dto.CustomerDTO.status",
            api_signature="",
            coord="com.vendor:customer-api",
            severity="P1",
        )
        detail = {
            "path_status": "reachable",
            "consumer_coord": "BUSINESS",
            "consumer_class": "com.acme.CustomerJob",
            "consumer_method": "refresh()",
        }
        evidence = [{"evidence_type": "data_contract_owner_reachability"}]

        conclusion = formatter._alert_conclusion_text(
            result, detail, "reachable", "confirmed", "SYSTEM_CODE_TOUCHED"
        )
        reason = formatter._alert_review_reason(
            result, detail, evidence, {}, "SYSTEM_CODE_TOUCHED"
        )

        self.assertIn("DTO 数据契约变化", conclusion)
        self.assertIn("系统运行路径", conclusion)
        self.assertIn("未判断数据库字段", reason)
        self.assertNotIn("数据库不匹配已确认", conclusion + reason)

    def test_data_contract_evidence_has_human_label(self):
        self.assertEqual(
            formatter._human_evidence_type("data_contract_owner_reachability"),
            "DTO 类型进入系统运行路径",
        )


if __name__ == "__main__":
    unittest.main()
