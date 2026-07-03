import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analysis_contract import aggregate_coverage_status, build_project_scope, derive_coverage_report, discover_maven_modules


def write_pom(path, artifact, packaging="jar", modules=None, dependencies=None, plugin=""):
    modules_xml = "".join(f"<module>{item}</module>" for item in (modules or []))
    deps_xml = "".join(
        f"<dependency><groupId>com.acme</groupId><artifactId>{item}</artifactId></dependency>"
        for item in (dependencies or [])
    )
    plugin_xml = f"<build><plugins><plugin><artifactId>{plugin}</artifactId></plugin></plugins></build>" if plugin else ""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "<project><modelVersion>4.0.0</modelVersion><groupId>com.acme</groupId>"
        f"<artifactId>{artifact}</artifactId><version>1</version><packaging>{packaging}</packaging>"
        f"<modules>{modules_xml}</modules><dependencies>{deps_xml}</dependencies>{plugin_xml}</project>",
        encoding="utf-8",
    )


class AnalysisContractTest(unittest.TestCase):
    def test_project_scope_uses_confirmed_target_reactor_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root", "pom", ["common", "service-a", "service-b"])
            write_pom(root / "common/pom.xml", "common")
            write_pom(root / "service-a/pom.xml", "service-a", dependencies=["common"], plugin="spring-boot-maven-plugin")
            write_pom(root / "service-b/pom.xml", "service-b", plugin="spring-boot-maven-plugin")
            (root / "common/src/main/java").mkdir(parents=True)
            (root / "service-a/src/main/java").mkdir(parents=True)
            (root / "service-a/src/main/resources").mkdir(parents=True)
            (root / "service-b/src/main/java").mkdir(parents=True)

            scope = build_project_scope(root, "service-a")

            self.assertEqual(scope["status"], "complete")
            self.assertEqual(scope["target_module"], "service-a")
            self.assertEqual(scope["included_modules"], ["service-a", "common"])
            self.assertEqual(scope["excluded_modules"], [".", "service-b"])
            self.assertEqual(len(scope["source_roots"]), 2)
            self.assertTrue(scope["scope_hash"])

    def test_discovery_reports_deploy_hints_but_does_not_choose_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root", "pom", ["app"])
            write_pom(root / "app/pom.xml", "app", plugin="spring-boot-maven-plugin")
            result = discover_maven_modules(root)
            app = next(item for item in result["modules"] if item["module"] == "app")
            self.assertIn("spring-boot-maven-plugin", app["deploy_hints"])
            self.assertNotIn("target_module", result)

    def test_unresolved_target_is_insufficient(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root")
            scope = build_project_scope(root, "missing")
            self.assertEqual(scope["status"], "insufficient")
            self.assertIn("target_module_unresolved", scope["reason_codes"])

    def test_project_scope_reads_nonstandard_maven_and_build_helper_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <properties><generated.root>generated/main</generated.root></properties>
                <build><sourceDirectory>source/java</sourceDirectory>
                  <resources><resource><directory>conf</directory></resource></resources>
                  <plugins><plugin><artifactId>build-helper-maven-plugin</artifactId>
                    <executions><execution><goals><goal>add-source</goal></goals>
                      <configuration><sources><source>${generated.root}</source></sources></configuration>
                    </execution></executions>
                  </plugin></plugins>
                </build></project>""",
                encoding="utf-8",
            )
            for relative in ("source/java", "generated/main", "conf"):
                (root / relative).mkdir(parents=True)

            scope = build_project_scope(root, ".")

            self.assertEqual(scope["status"], "complete")
            self.assertEqual(
                set(scope["source_roots"]),
                {str((root / "source/java").resolve()), str((root / "generated/main").resolve())},
            )
            self.assertEqual(scope["resource_roots"], [str((root / "conf").resolve())])

    def test_coverage_aggregation_prefers_worst_applicable_status(self):
        self.assertEqual(aggregate_coverage_status(["complete", "partial"]), "partial")
        self.assertEqual(aggregate_coverage_status(["complete", "insufficient"]), "insufficient")
        self.assertEqual(aggregate_coverage_status(["not_applicable"]), "not_applicable")

    def test_coverage_report_marks_ambiguous_pairing_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            (report / "s1_dep_changes.csv").write_text(
                "coord,resolution_status,pairing_reason_code\n"
                "com.acme:shared,unresolved,ambiguous_artifact_migration_candidates\n",
                encoding="utf-8",
            )
            coverage = derive_coverage_report(
                report,
                project_scope={"status": "complete", "reason_codes": []},
            )
            dependency = next(item for item in coverage["components"] if item["id"] == "dependency_diff")
            self.assertEqual(dependency["status"], "partial")
            self.assertIn("dependency_pairing_ambiguous", dependency["reason_codes"])


if __name__ == "__main__":
    unittest.main()
