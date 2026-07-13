import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s3_scan as step3  # noqa: E402


class Step3SpringConfigTest(unittest.TestCase):
    def test_yaml_anchor_on_mapping_keeps_nested_key_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "application.yml").write_text(
                "spring:\n"
                "  profiles: &profiles\n"
                "    active: dev\n"
                "other: *profiles\n",
                encoding="utf-8",
            )
            output = root / "out.csv"

            step3.scan_sb_config(str(root), str(output))
            with output.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        keys = {row["配置键"] for row in rows}
        self.assertIn("spring.profiles.active", keys)

    def test_flow_style_or_tab_indentation_is_marked_incomplete_not_silently_misparsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "application.yml").write_text(
                "spring: { datasource: { url: jdbc:h2:mem:test } }\n"
                "\tmanagement:\n"
                "\t  endpoint: health\n",
                encoding="utf-8",
            )
            output = root / "out.csv"

            step3.scan_sb_config(str(root), str(output))
            with output.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertTrue(any(row.get("扫描状态") == "未完成" for row in rows))

    def test_yaml_leaf_keys_keep_full_indentation_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "application.yml").write_text(
                """
spring:
  datasource:
    url: jdbc:h2:mem:test
    hikari:
      maximum-pool-size: 8
management:
  endpoints:
    web:
      exposure:
        include: health,info
""",
                encoding="utf-8",
            )
            output = root / "out.csv"

            step3.scan_sb_config(str(root), str(output))
            with output.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        keys = {row["配置键"] for row in rows}
        self.assertIn("spring.datasource.url", keys)
        self.assertIn("spring.datasource.hikari.maximum-pool-size", keys)
        self.assertIn("management.endpoints.web.exposure.include", keys)


if __name__ == "__main__":
    unittest.main()
