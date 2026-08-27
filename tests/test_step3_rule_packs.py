import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s3_scan


class Step3RulePacksTest(unittest.TestCase):
    def test_jdk_javax_matching_uses_exact_package_boundaries(self):
        self.assertTrue(s3_scan.is_jdk_javax("javax.sql.rowset"))
        self.assertTrue(
            s3_scan.is_jdk_javax("javax.annotation.processing.Processor")
        )
        self.assertTrue(s3_scan.is_jdk_javax("javax.tools.JavaCompiler"))
        self.assertFalse(s3_scan.is_jdk_javax("javax.sqlx.NotAPlatformPackage"))
        self.assertFalse(s3_scan.is_jdk_javax("javax.servlet.Filter"))

    def test_grouped_pattern_scan_walks_the_source_tree_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Demo.java").write_text(
                "class Demo { String hit = \"HIT\"; }\n", encoding="utf-8"
            )
            with patch.object(
                s3_scan, "walk_files", wraps=s3_scan.walk_files
            ) as walk:
                grouped = s3_scan.scan_patterns(
                    root,
                    [("hit", "HIT"), ("class", r"\bclass\b")],
                    skip_comment=False,
                    skip_test=True,
                )

        self.assertEqual(walk.call_count, 1)
        self.assertTrue(grouped["hit"])
        self.assertTrue(grouped["class"])

    def test_jdk_rules_are_filtered_by_upgrade_interval(self):
        active = s3_scan.active_jdk_removed_rules(11, 17)
        ids = {rule["id"] for rule, _pack in active}
        self.assertIn("jdk15-nashorn", ids)
        self.assertIn("jdk17-applet", ids)
        self.assertNotIn("jdk11-jaxb", ids)
        self.assertNotIn("jdk20-url-constructor", ids)

    def test_scan_writes_rule_pack_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "Demo.java").write_text("class Demo { Object x = new JApplet(); }", encoding="utf-8")
            output = root / "hits.csv"
            old_base, old_target = s3_scan.BASE_JDK, s3_scan.TARGET_JDK
            try:
                s3_scan.BASE_JDK, s3_scan.TARGET_JDK = 11, 17
                s3_scan.scan_jdk_removed(str(source), str(output))
            finally:
                s3_scan.BASE_JDK, s3_scan.TARGET_JDK = old_base, old_target
            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["规则ID"], "jdk17-applet")
            self.assertEqual(rows[0]["规则包"], "jdk-core@2026.07")

    def test_javax_scan_uses_versioned_jakarta_namespace_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "Demo.java").write_text(
                "import javax.servlet.Filter; class Demo {}", encoding="utf-8"
            )
            output = root / "javax.csv"

            s3_scan.scan_javax(str(source), str(output))

            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["规则ID"], "jakarta-servlet")
            self.assertEqual(rows[0]["规则包"], "jakarta-namespace@2026.07")
            self.assertEqual(rows[0]["建议命名空间"], "jakarta.servlet")

    def test_javax_config_scan_keeps_jdk_annotation_processing_non_migrating(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            (source / "processor.xml").write_text(
                "type=javax.annotation.processing.Processor\n", encoding="utf-8"
            )
            output = root / "javax.csv"

            s3_scan.scan_javax(str(source), str(output))

            with output.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertTrue(any(
            "javax.annotation.processing.Processor" in row["内容"]
            and row["需迁移"] == "N"
            and row["规则ID"] == "jdk-javax-no-migration"
            for row in rows
        ))

    def test_spring_boot_scan_records_rule_pack_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            output = root / "spring.txt"

            s3_scan.scan_sb_autoconfig(str(source), str(output))

            self.assertIn("spring-boot-migration@2026.07", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
