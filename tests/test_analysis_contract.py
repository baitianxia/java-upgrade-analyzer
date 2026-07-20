import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from analysis_contract import (
    aggregate_coverage_status,
    build_project_scope,
    build_provenance,
    derive_coverage_report,
    discover_maven_modules,
)


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
    def test_inactive_profile_modules_are_not_reactor_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><modules><module>app</module></modules>
                <profiles><profile><id>never-active</id><modules><module>hidden</module></modules>
                </profile></profiles></project>""",
                encoding="utf-8",
            )
            write_pom(root / "app/pom.xml", "app")
            write_pom(root / "hidden/pom.xml", "hidden")

            result = discover_maven_modules(root)

        self.assertEqual(
            [item["module"] for item in result["modules"]], [".", "app"]
        )

    def test_explicitly_active_profile_modules_are_reactor_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging>
                <profiles><profile><id>boot</id><modules><module>application</module></modules>
                </profile></profiles></project>""",
                encoding="utf-8",
            )
            write_pom(root / "application/pom.xml", "application")

            result = discover_maven_modules(root, active_profiles={"boot"})

        self.assertEqual(
            [item["module"] for item in result["modules"]],
            [".", "application"],
        )

    def test_active_profile_dependencies_join_target_reactor_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root", "pom", ["app", "lib"])
            (root / "app/pom.xml").parent.mkdir(parents=True)
            (root / "app/pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <profiles><profile><id>boot</id><dependencies><dependency>
                <groupId>com.acme</groupId><artifactId>lib</artifactId>
                </dependency></dependencies></profile></profiles></project>""",
                encoding="utf-8",
            )
            write_pom(root / "lib/pom.xml", "lib")
            (root / "app/src/main/java").mkdir(parents=True)
            (root / "lib/src/main/java").mkdir(parents=True)

            scope = build_project_scope(
                root, "app", active_profiles={"boot"}
            )

        self.assertEqual(scope["included_modules"], ["app", "lib"])
        self.assertEqual(
            scope["included_module_coords"], ["com.acme:app", "com.acme:lib"]
        )

    def test_active_by_default_is_suppressed_by_another_explicit_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><profiles>
                <profile><id>default</id><activation><activeByDefault>true</activeByDefault>
                </activation><modules><module>default-app</module></modules></profile>
                <profile><id>boot</id><modules><module>boot-app</module></modules></profile>
                </profiles></project>""",
                encoding="utf-8",
            )
            write_pom(root / "default-app/pom.xml", "default-app")
            write_pom(root / "boot-app/pom.xml", "boot-app")

            default_modules = discover_maven_modules(root)["modules"]
            explicit_modules = discover_maven_modules(
                root, active_profiles={"boot"}
            )["modules"]

        self.assertEqual(
            [item["module"] for item in default_modules], [".", "default-app"]
        )
        self.assertEqual(
            [item["module"] for item in explicit_modules], [".", "boot-app"]
        )

    def test_inactive_profile_build_helper_does_not_add_source_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <profiles><profile><id>inactive</id><build><plugins><plugin>
                <artifactId>build-helper-maven-plugin</artifactId><executions><execution>
                <goals><goal>add-source</goal></goals><configuration><sources>
                <source>inactive-src</source></sources></configuration></execution></executions>
                </plugin></plugins></build></profile></profiles></project>""",
                encoding="utf-8",
            )
            (root / "src/main/java").mkdir(parents=True)
            (root / "inactive-src").mkdir()

            scope = build_project_scope(root, ".")

        self.assertNotIn(str((root / "inactive-src").resolve()), scope["source_roots"])

    def test_reactor_closure_uses_resolved_runtime_dependencies_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root", "pom", ["app", "runtime-lib", "test-lib", "optional-lib"])
            (root / "app/pom.xml").parent.mkdir(parents=True)
            (root / "app/pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <properties><reactor.group>${project.groupId}</reactor.group></properties>
                <dependencies>
                  <dependency><groupId>${reactor.group}</groupId><artifactId>runtime-lib</artifactId><scope>runtime</scope></dependency>
                  <dependency><groupId>com.acme</groupId><artifactId>test-lib</artifactId><scope>test</scope></dependency>
                  <dependency><groupId>com.acme</groupId><artifactId>optional-lib</artifactId><optional>true</optional></dependency>
                </dependencies></project>""",
                encoding="utf-8",
            )
            for module in ("runtime-lib", "test-lib", "optional-lib"):
                write_pom(root / module / "pom.xml", module)
                (root / module / "src/main/java").mkdir(parents=True)
            (root / "app/src/main/java").mkdir(parents=True)

            scope = build_project_scope(root, "app")

        self.assertEqual(
            scope["included_modules"], ["app", "runtime-lib", "optional-lib"]
        )

    def test_reactor_closure_does_not_propagate_optional_dependency_of_internal_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(
                root / "pom.xml", "root", "pom",
                ["app", "library", "optional-provider"],
            )
            write_pom(root / "app/pom.xml", "app", dependencies=["library"])
            (root / "library/pom.xml").parent.mkdir(parents=True)
            (root / "library/pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>library</artifactId><version>1</version>
                <dependencies><dependency><groupId>com.acme</groupId>
                <artifactId>optional-provider</artifactId><optional>true</optional>
                </dependency></dependencies></project>""",
                encoding="utf-8",
            )
            write_pom(root / "optional-provider/pom.xml", "optional-provider")
            for module in ("app", "library", "optional-provider"):
                (root / module / "src/main/java").mkdir(parents=True)

            scope = build_project_scope(root, "app")

        self.assertEqual(scope["included_modules"], ["app", "library"])

    def test_project_scope_source_state_changes_for_dirty_pom_at_same_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "app")
            (root / "src/main/java").mkdir(parents=True)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "pom.xml"], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", "fixture",
                ],
                cwd=root,
                check=True,
            )
            clean_scope = build_project_scope(root, ".")
            revision = clean_scope["source_revision"]
            (root / "pom.xml").write_text(
                (root / "pom.xml").read_text(encoding="utf-8").replace(
                    "</project>",
                    "<properties><dirty.flag>true</dirty.flag></properties></project>",
                ),
                encoding="utf-8",
            )

            dirty_scope = build_project_scope(root, ".")

        self.assertEqual(dirty_scope["source_revision"], revision)
        self.assertTrue(clean_scope.get("maven_model_hash"))
        self.assertTrue(clean_scope.get("source_state_hash"))
        self.assertNotEqual(
            dirty_scope.get("source_state_hash"), clean_scope.get("source_state_hash")
        )

    def test_project_scope_source_state_changes_with_active_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <profiles>
                  <profile><id>blue</id><properties><color>blue</color></properties></profile>
                  <profile><id>green</id><properties><color>green</color></properties></profile>
                </profiles></project>""",
                encoding="utf-8",
            )
            (root / "src/main/java").mkdir(parents=True)

            blue = build_project_scope(root, ".", active_profiles={"blue"})
            green = build_project_scope(root, ".", active_profiles={"green"})

        self.assertNotEqual(blue.get("maven_model_hash"), green.get("maven_model_hash"))
        self.assertNotEqual(blue.get("source_state_hash"), green.get("source_state_hash"))

    def test_project_scope_source_state_ignores_unrelated_module_pom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(root / "pom.xml", "root", "pom", ["app", "unrelated"])
            write_pom(root / "app/pom.xml", "app")
            write_pom(root / "unrelated/pom.xml", "unrelated")
            (root / "app/src/main/java").mkdir(parents=True)
            initial = build_project_scope(root, "app")
            (root / "unrelated/pom.xml").write_text(
                (root / "unrelated/pom.xml").read_text(encoding="utf-8").replace(
                    "</project>",
                    "<properties><unrelated.change>true</unrelated.change>"
                    "</properties></project>",
                ),
                encoding="utf-8",
            )

            changed = build_project_scope(root, "app")

        self.assertEqual(changed["maven_model_hash"], initial["maven_model_hash"])
        self.assertEqual(changed["source_state_hash"], initial["source_state_hash"])

    def test_reactor_closure_inherits_parent_runtime_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pom(
                root / "pom.xml", "root", "pom", ["app", "lib"],
                dependencies=["lib"],
            )
            for module in ("app", "lib"):
                pom = root / module / "pom.xml"
                pom.parent.mkdir(parents=True)
                pom.write_text(
                    "<project><modelVersion>4.0.0</modelVersion>"
                    "<parent><groupId>com.acme</groupId><artifactId>root</artifactId>"
                    "<version>1</version></parent>"
                    f"<artifactId>{module}</artifactId></project>",
                    encoding="utf-8",
                )
            (root / "app/src/main/java").mkdir(parents=True)
            (root / "lib/src/main/java").mkdir(parents=True)

            scope = build_project_scope(root, "app")

        self.assertEqual(scope["included_modules"], ["app", "lib"])

    def test_active_profile_resources_join_effective_resource_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <profiles><profile><id>prod</id><build><resources><resource>
                <directory>src/prod/resources</directory>
                </resource></resources></build></profile></profiles></project>""",
                encoding="utf-8",
            )
            (root / "src/main/java").mkdir(parents=True)
            (root / "src/prod/resources").mkdir(parents=True)

            scope = build_project_scope(root, ".", active_profiles={"prod"})

        self.assertEqual(
            scope["resource_roots"],
            [str((root / "src/prod/resources").resolve())],
        )


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

    def test_project_scope_discovers_target_module_declared_inside_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><modules><module>library</module></modules>
                <profiles><profile><id>boot</id><modules><module>application</module></modules>
                </profile></profiles></project>""",
                encoding="utf-8",
            )
            write_pom(root / "library/pom.xml", "library")
            write_pom(root / "application/pom.xml", "application", dependencies=["library"])
            (root / "library/src/main/java").mkdir(parents=True)
            (root / "application/src/main/java").mkdir(parents=True)

            scope = build_project_scope(
                root, "application", active_profiles={"boot"}
            )

            self.assertEqual(scope["status"], "complete")
            self.assertEqual(scope["included_modules"], ["application", "library"])
            self.assertEqual(len(scope["source_roots"]), 2)

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
            dependencies_dir = report / "evidence" / "dependencies"
            dependencies_dir.mkdir(parents=True, exist_ok=True)
            (dependencies_dir / "dep_changes.csv").write_text(
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

    def test_build_provenance_rejects_dirty_pom_at_same_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report = Path(tmp) / "report"
            write_pom(root / "pom.xml", "app")
            (root / "src/main/java").mkdir(parents=True)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "pom.xml"], cwd=root, check=True)
            subprocess.run(
                [
                    "git", "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", "fixture",
                ],
                cwd=root,
                check=True,
            )
            built_scope = build_project_scope(root, ".")
            (root / "pom.xml").write_text(
                (root / "pom.xml").read_text(encoding="utf-8").replace(
                    "</project>",
                    "<properties><dirty.flag>true</dirty.flag></properties></project>",
                ),
                encoding="utf-8",
            )
            current_scope = build_project_scope(root, ".")
            self._write_bound_provenance(report, built_scope)

            coverage = derive_coverage_report(report, project_scope=current_scope)

        provenance = next(
            item for item in coverage["components"]
            if item["id"] == "build_provenance"
        )
        self.assertEqual(provenance["status"], "insufficient")
        self.assertIn("build_source_state_mismatch", provenance["reason_codes"])

    def test_build_provenance_rejects_different_active_profile_at_same_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report = Path(tmp) / "report"
            (root / "pom.xml").parent.mkdir(parents=True)
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>app</artifactId><version>1</version>
                <profiles>
                  <profile><id>blue</id><properties><color>blue</color></properties></profile>
                  <profile><id>green</id><properties><color>green</color></properties></profile>
                </profiles></project>""",
                encoding="utf-8",
            )
            (root / "src/main/java").mkdir(parents=True)
            built_scope = build_project_scope(root, ".", active_profiles={"blue"})
            current_scope = build_project_scope(root, ".", active_profiles={"green"})
            self._write_bound_provenance(report, built_scope)

            coverage = derive_coverage_report(report, project_scope=current_scope)

        provenance = next(
            item for item in coverage["components"]
            if item["id"] == "build_provenance"
        )
        self.assertEqual(provenance["status"], "insufficient")
        self.assertIn("build_active_profiles_mismatch", provenance["reason_codes"])

    def test_build_provenance_accepts_and_records_exact_source_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report = Path(tmp) / "report"
            artifact = Path(tmp) / "app.jar"
            write_pom(root / "pom.xml", "app")
            (root / "src/main/java").mkdir(parents=True)
            artifact.write_bytes(b"artifact")
            scope = build_project_scope(root, ".", active_profiles={"prod"})
            current = build_provenance(
                root,
                "current",
                "HEAD",
                ".",
                "mvn -Pprod package",
                artifact_path=artifact,
                project_scope=scope,
            )
            dependencies = report / "evidence" / "dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v1",
                "both_builds_succeeded": True,
                "sides": [
                    {**current, "side": "base"},
                    current,
                ],
            }), encoding="utf-8")

            coverage = derive_coverage_report(report, project_scope=scope)

        self.assertEqual(current["project_scope_hash"], scope["scope_hash"])
        self.assertEqual(current["source_state_hash"], scope["source_state_hash"])
        self.assertEqual(current["maven_model_hash"], scope["maven_model_hash"])
        self.assertEqual(current["active_maven_profiles"], ["prod"])
        provenance = next(
            item for item in coverage["components"]
            if item["id"] == "build_provenance"
        )
        self.assertEqual(provenance["status"], "complete")
        self.assertEqual(provenance["reason_codes"], [])

    def test_build_provenance_requires_explicit_empty_active_profiles_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report = Path(tmp) / "report"
            write_pom(root / "pom.xml", "app")
            (root / "src/main/java").mkdir(parents=True)
            scope = build_project_scope(root, ".")
            self._write_bound_provenance(report, scope)
            provenance_path = (
                report / "evidence" / "dependencies" / "build_provenance.json"
            )
            payload = json.loads(provenance_path.read_text(encoding="utf-8"))
            for side in payload["sides"]:
                side.pop("active_maven_profiles")
            provenance_path.write_text(json.dumps(payload), encoding="utf-8")

            coverage = derive_coverage_report(report, project_scope=scope)

        provenance = next(
            item for item in coverage["components"]
            if item["id"] == "build_provenance"
        )
        self.assertEqual(provenance["status"], "insufficient")
        self.assertIn("build_active_profiles_missing", provenance["reason_codes"])

    @staticmethod
    def _write_bound_provenance(report, scope):
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True, exist_ok=True)
        sides = []
        for side in ("base", "current"):
            sides.append({
                "side": side,
                "revision": scope["source_revision"],
                "artifact_sha256": "a" * 64,
                "project_scope_hash": scope["scope_hash"],
                "source_state_hash": scope["source_state_hash"],
                "maven_model_hash": scope["maven_model_hash"],
                "active_maven_profiles": scope["active_maven_profiles"],
            })
        (dependencies / "build_provenance.json").write_text(json.dumps({
            "schema": "java-upgrade-analyzer.build-provenance.v1",
            "both_builds_succeeded": True,
            "sides": sides,
        }), encoding="utf-8")

    def test_indirect_usage_partial_is_a_critical_coverage_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            summary = report / "evidence" / "call_chain" / "summary.json"
            summary.parent.mkdir(parents=True)
            summary.write_text(json.dumps({
                "total_apis": 1,
                "not_analyzed": 1,
                "graph_stats": {
                    "indirect_usage": {
                        "status": "partial",
                        "reason_codes": ["reflection_source_partial"],
                    }
                },
            }), encoding="utf-8")

            coverage = derive_coverage_report(
                report,
                project_scope={"status": "complete", "reason_codes": []},
            )

        self.assertIn("indirect_usage_matrix", coverage["critical_incomplete"])
        indirect = next(item for item in coverage["components"] if item["id"] == "indirect_usage_matrix")
        self.assertEqual(indirect["reason_codes"], ["reflection_source_partial"])


if __name__ == "__main__":
    unittest.main()
