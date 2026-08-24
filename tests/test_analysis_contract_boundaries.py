from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import analysis_contract as contract  # noqa: E402


class AnalysisContractBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write(path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def pom(self, relative: str, body: str) -> Path:
        return self.write(
            self.root / relative / "pom.xml",
            "<project xmlns='http://maven.apache.org/POM/4.0.0'>"
            + body
            + "</project>",
        )

    @staticmethod
    def module(
        root: Path,
        name: str,
        *,
        coord: str = "",
        artifact: str = "",
        dependencies=None,
        dependency_edges=None,
        sources=None,
        resources=None,
        properties=None,
        packaging="jar",
    ):
        module_dir = root if name == "." else root / name
        return {
            "module": name,
            "gradle_path": ":" if name == "." else ":" + name.replace("/", ":"),
            "module_dir": str(module_dir),
            "coord": coord,
            "group_id": coord.split(":", 1)[0] if ":" in coord else "",
            "artifact_id": artifact or (coord.split(":", 1)[-1] if coord else module_dir.name),
            "version": "1",
            "packaging": packaging,
            "dependencies": list(dependencies or []),
            "dependency_edges": list(dependency_edges or []),
            "deploy_hints": [],
            "properties": dict(properties or {}),
            "declared_source_paths": list(sources or []),
            "declared_resource_paths": list(resources or []),
            "pom_sha256": "pom-hash",
            "build_sha256": "build-hash",
        }

    def test_text_and_pom_inheritance_profile_dependency_and_build_helper_matrix(self):
        self.assertEqual(contract._text(None, "x"), "")
        empty = contract.ET.fromstring("<root><x/></root>")
        self.assertEqual(contract._text(empty, "x"), "")
        self.assertEqual(contract._text(empty, "missing"), "")

        pom = self.pom("child", """
          <parent><groupId>${parent.group}</groupId><artifactId>parent</artifactId><version>${parent.version}</version></parent>
          <artifactId>${artifact.name}</artifactId>
          <packaging>war</packaging>
          <properties>
            <artifact.name>child</artifact.name><empty/><nested>${base.name}</nested>
          </properties>
          <modules><module> a </module><module>a</module><module/></modules>
          <dependencies>
            <dependency><groupId>g</groupId><artifactId>compile</artifactId></dependency>
            <dependency><artifactId>runtime</artifactId><scope>runtime</scope><optional>true</optional></dependency>
            <dependency><artifactId>test</artifactId><scope>test</scope></dependency>
            <dependency><scope>compile</scope></dependency>
          </dependencies>
          <build>
            <sourceDirectory>${project.basedir}/custom-java</sourceDirectory>
            <resources><resource><directory>custom-resources</directory></resource><resource/></resources>
            <plugins>
              <plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin><plugin/>
              <plugin><artifactId>build-helper-maven-plugin</artifactId><executions>
                <execution><goals><goal>add-source</goal></goals><configuration><sources><source>generated</source><source/></sources></configuration></execution>
                <execution><goals><goal>add-resource</goal></goals><configuration><resources><resource><directory>generated-res</directory></resource></resources></configuration></execution>
                <execution><goals><goal>other</goal></goals><configuration><sources><source>ignored</source></sources></configuration></execution>
                <execution><goals><goal/></goals><configuration/></execution>
                <execution><goals><goal>add-source</goal></goals></execution>
              </executions></plugin>
            </plugins>
          </build>
          <profiles>
            <profile><id>default</id><activation><activeByDefault>true</activeByDefault></activation><properties><base.name>default-name</base.name></properties><modules><module>default-module</module></modules></profile>
            <profile><id>chosen</id><properties><base.name>chosen-name</base.name><blank/></properties><modules><module>chosen-module</module></modules><dependencies><dependency><artifactId>profile-dep</artifactId></dependency></dependencies><build><sourceDirectory>profile-java</sourceDirectory></build></profile>
          </profiles>
        """)
        inherited_dependencies = [{"coord": "g:parent-dep", "optional": False, "scope": "runtime"}]
        model = contract._pom_model(
            pom,
            inherited_group="g.parent",
            inherited_version="1.2.3",
            inherited_properties={
                "parent.group": "g.parent",
                "parent.version": "1.2.3",
                "base.name": "base",
            },
            active_profiles={"", " chosen "},
            inherited_artifact="parent",
            inherited_dependencies=inherited_dependencies,
            inherited_plugins=["parent-plugin"],
            inherited_source_paths=["parent-source"],
            inherited_resource_paths=["parent-resource"],
        )
        self.assertEqual(model["group_id"], "g.parent")
        self.assertEqual(model["artifact_id"], "child")
        self.assertEqual(model["version"], "1.2.3")
        self.assertEqual(model["packaging"], "war")
        self.assertEqual(model["module_paths"], ["a", "chosen-module"])
        self.assertEqual(
            [edge["coord"] for edge in model["dependency_edges"]],
            ["g:parent-dep", "g:compile", "runtime", "profile-dep"],
        )
        self.assertTrue(model["dependency_edges"][2]["optional"])
        self.assertEqual(model["properties"]["base.name"], "chosen-name")
        self.assertEqual(
            model["source_paths"],
            ["parent-source", "${project.basedir}/custom-java", "profile-java", "generated"],
        )
        self.assertEqual(
            model["resource_paths"],
            ["parent-resource", "custom-resources", "generated-res"],
        )
        self.assertEqual(
            model["plugins"],
            ["build-helper-maven-plugin", "parent-plugin", "spring-boot-maven-plugin"],
        )

        default_model = contract._pom_model(
            pom,
            inherited_group="wrong",
            inherited_version="0",
            inherited_properties={},
            active_profiles=set(),
            inherited_artifact="different",
            inherited_dependencies=inherited_dependencies,
        )
        self.assertIn("default-module", default_model["module_paths"])
        self.assertNotIn("g:parent-dep", [row["coord"] for row in default_model["dependency_edges"]])

    def test_pom_parent_match_requires_artifact_group_and_version(self):
        templates = (
            ("wrong-artifact", "g", "1", "other"),
            ("wrong-group", "other", "1", "parent"),
            ("wrong-version", "g", "2", "parent"),
            ("empty-parent-fields", "", "", "parent"),
        )
        for name, group, version, artifact in templates:
            with self.subTest(name=name):
                parent = (
                    f"<parent><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
                    f"<version>{version}</version></parent>"
                )
                pom = self.pom(name, parent + "<artifactId>child</artifactId>")
                model = contract._pom_model(
                    pom,
                    inherited_group="g",
                    inherited_version="1",
                    inherited_artifact="parent",
                    inherited_properties={"loop.a": "${loop.b}", "loop.b": "${loop.a}"},
                    inherited_dependencies=[{"coord": "inherited"}],
                )
                inherits = name == "empty-parent-fields"
                self.assertEqual(bool(model["dependency_edges"]), inherits)

    def test_pom_resolution_iteration_boundaries_and_empty_coordinate(self):
        inherited = {f"p{index}": f"${{p{index + 1}}}" for index in range(9)}
        inherited["p9"] = "g"
        inherited.update({
            f"q{index}": f"${{q{index + 1}}}" for index in range(9)
        })
        inherited["q9"] = "artifact"
        pom = self.pom("long-chain", """
          <parent><groupId>${p0}</groupId><artifactId>parent</artifactId></parent>
          <artifactId>${q0}</artifactId>
        """)
        model = contract._pom_model(
            pom,
            inherited_group="${p8}",
            inherited_version="1",
            inherited_properties=inherited,
            inherited_artifact="parent",
        )
        self.assertEqual(model["group_id"], "${p8}")
        self.assertEqual(model["artifact_id"], "${q8}")

        standalone = self.pom("no-coordinate", "<version>1</version>")
        result = contract.discover_maven_modules(standalone.parent)
        self.assertEqual(result["modules"][0]["coord"], "")

    def test_maven_discovery_missing_cycle_unreadable_and_deploy_hints(self):
        missing = contract.discover_maven_modules(self.root / "missing")
        self.assertEqual(missing["status"], "insufficient")

        self.pom("reactor", """
          <groupId>g</groupId><artifactId>root</artifactId><version>1</version><packaging>war</packaging>
          <modules><module>.</module><module>missing</module><module>broken</module><module>app</module></modules>
          <build><plugins><plugin><artifactId>maven-shade-plugin</artifactId></plugin><plugin><artifactId>maven-assembly-plugin</artifactId></plugin></plugins></build>
        """)
        self.write(self.root / "reactor" / "broken" / "pom.xml", "<project>")
        self.write(self.root / "reactor" / "app" / "pom.xml", """
          <project><parent><groupId>g</groupId><artifactId>root</artifactId><version>1</version></parent><artifactId>app</artifactId><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>
        """)
        result = contract.discover_maven_modules(
            self.root / "reactor", active_profiles={"", " profile "}
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["modules"]), 2)
        self.assertTrue(any(code.startswith("module_pom_missing:") for code in result["reason_codes"]))
        self.assertTrue(any(code.startswith("module_pom_unreadable:") for code in result["reason_codes"]))
        root_module = result["modules"][0]
        self.assertEqual(root_module["module"], ".")
        self.assertEqual(
            root_module["deploy_hints"],
            ["war_packaging", "maven-shade-plugin", "maven-assembly-plugin"],
        )
        self.assertEqual(len(result["maven_model_hash"]), 64)

    def test_gradle_comment_quote_block_source_and_dependency_helpers(self):
        text = (
            "'single // literal' \"double /* literal */ and \\\" quote\" "
            "// line comment\nkeep / slash\n/* block\ncomment */tail/"
        )
        stripped = contract._strip_gradle_comments(text)
        self.assertIn("single // literal", stripped)
        self.assertIn("double /* literal */", stripped)
        self.assertNotIn("line comment", stripped)
        self.assertNotIn("block\ncomment", stripped)
        self.assertTrue(stripped.endswith("tail/"))
        self.assertEqual(contract._strip_gradle_comments("/* unterminated"), "")
        self.assertEqual(contract._strip_gradle_comments("'trailing\\"), "'trailing\\")
        self.assertEqual(contract._strip_gradle_comments("keep// eof"), "keep")
        self.assertEqual(contract._gradle_quoted_values(None), [])
        self.assertEqual(contract._gradle_quoted_values("'a' \"b\""), ["a", "b"])
        self.assertEqual(contract._gradle_assignment("x = ' y '", ("x",)), "y")
        self.assertEqual(contract._gradle_assignment("none", ("x",)), "")

        for block in (
            "sourceSets { main { java.srcDir 'one'; nested { value = '}' }; value = \"escaped\\\"quote\"; resources.srcDirs('res') } }",
            "sourceSets { named('main') { java.srcDirs('two') } }",
            "sourceSets { getByName(\"main\") { java.setSrcDirs(['three']) } }",
        ):
            self.assertTrue(contract._gradle_main_source_block(block))
        self.assertEqual(contract._gradle_main_source_block("sourceSets {}"), "")
        self.assertEqual(contract._gradle_main_source_block("main { unterminated"), "")

        sources, resources = contract._gradle_declared_source_paths("""
          sourceSets { main {
            java.srcDirs 'src/custom', 'src/custom', ''
            resources.srcDir 'res/custom'
            ignored 'not-a-source'
          } }
        """)
        self.assertEqual(sources, ["src/custom"])
        self.assertEqual(resources, ["res/custom"])
        self.assertEqual(contract._gradle_declared_source_paths("plugins {}"), ([], []))

        edges = contract._gradle_project_dependencies("""
          implementation project(':core')
          api(project(path: ':nested:api'))
          runtimeOnly project(':core')
          runtime project('::::')
          testImplementation project(':ignored')
        """)
        self.assertEqual([row["module"] for row in edges], ["core", "nested/api"])

    def test_gradle_settings_build_model_and_root_config_hash_matrix(self):
        empty = contract._gradle_settings_model(self.root / "none")
        self.assertEqual(empty["path"], "")
        self.assertEqual(empty["module_paths"], [])

        gradle = self.root / "gradle-project"
        self.write(gradle / "settings.gradle", """
          // ignored include ':bad'
          rootProject.name = 'root-name'
          include ':app', ':nested:lib', ':app', ':'
          include(':kotlin')
          project(':nested:lib').projectDir = file('custom/lib')
          project(':app').name = 'renamed-app'
        """)
        self.write(gradle / "settings.gradle.kts", "include(\":ignored-kts\")")
        settings = contract._gradle_settings_model(gradle)
        self.assertEqual(settings["module_paths"], ["app", "nested/lib", "kotlin"])
        self.assertEqual(settings["project_dirs"][":nested:lib"], "custom/lib")
        self.assertEqual(settings["project_names"][":app"], "renamed-app")
        self.assertEqual(settings["root_name"], "root-name")

        build = self.write(gradle / "build.gradle", """
          group = 'g'; version = '1'
          archivesBaseName = 'archive-name'
          plugins { id 'war'; id 'org.springframework.boot'; id 'com.github.johnrengelman.shadow' }
          dependencies { implementation project(':app') }
          sourceSets { main { java.srcDir 'custom'; resources.srcDir 'res' } }
        """)
        model = contract._gradle_build_model(build)
        self.assertEqual(model["artifact_id"], "archive-name")
        self.assertEqual(model["packaging"], "war")
        self.assertEqual(
            model["deploy_hints"],
            ["war_plugin", "org.springframework.boot", "shadow_plugin"],
        )

        fallback_build = self.write(
            gradle / "fallback" / "build.gradle.kts",
            "plugins { id(\"com.gradleup.shadow\") }",
        )
        fallback = contract._gradle_build_model(
            fallback_build,
            inherited_group="inherited.g",
            inherited_version="2",
        )
        self.assertEqual(fallback["artifact_id"], "fallback")
        self.assertEqual(fallback["packaging"], "jar")
        self.assertEqual(fallback["deploy_hints"], ["shadow_plugin"])

        settings_only = {"sha256": "settings-only"}
        self.assertEqual(
            contract._gradle_root_config_hash(self.root / "empty-root", settings_only),
            "settings-only",
        )
        self.write(gradle / "gradle.properties", "x=1")
        self.write(gradle / "gradle" / "libs.versions.toml", "[versions]\njava='17'")
        self.write(gradle / "buildSrc" / "src" / "Plugin.kt", "class Plugin")
        self.write(gradle / "buildSrc" / "build" / "ignored", "ignored")
        self.write(gradle / "buildSrc" / ".gradle" / "ignored", "ignored")
        first_hash = contract._gradle_root_config_hash(gradle, settings)
        self.assertEqual(len(first_hash), 64)
        self.write(gradle / "buildSrc" / "src" / "Plugin.kt", "class Changed")
        self.assertNotEqual(first_hash, contract._gradle_root_config_hash(gradle, settings))

    def test_gradle_discovery_root_settings_only_and_scriptless_modules(self):
        missing = contract.discover_gradle_modules(self.root / "missing")
        self.assertEqual(missing["status"], "insufficient")

        project = self.root / "settings-only"
        self.write(project / "settings.gradle", """
          rootProject.name = 'root'
          include ':local', ':renamed', ':custom'
          project(':renamed').name = 'public-name'
          project(':custom').projectDir = file('elsewhere')
        """)
        self.write(project / "local" / "build.gradle", "version='3'")
        result = contract.discover_gradle_modules(project)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [row["module"] for row in result["modules"]],
            ["custom", "local", "renamed"],
        )
        self.assertEqual(
            next(row for row in result["modules"] if row["module"] == "renamed")["artifact_id"],
            "public-name",
        )

        root_only = self.root / "root-only"
        self.write(root_only / "build.gradle", "group='g'; version='1'")
        root_result = contract.discover_gradle_modules(root_only)
        self.assertEqual([row["module"] for row in root_result["modules"]], ["."])

    def test_build_tool_dispatch_and_target_resolution_alias_matrix(self):
        self.write(self.root / "pom.xml", "<project/>")
        self.assertEqual(contract.detect_project_build_tool(self.root), "maven")
        (self.root / "pom.xml").unlink()
        for name in ("build.gradle", "settings.gradle.kts", "gradlew.bat"):
            path = self.write(self.root / name, "")
            self.assertEqual(contract.detect_project_build_tool(self.root), "gradle")
            path.unlink()
        self.assertEqual(contract.detect_project_build_tool(self.root), "maven")

        with mock.patch.object(
            contract, "discover_gradle_modules", return_value={"tool": "gradle"}
        ) as gradle:
            self.assertEqual(
                contract.discover_project_modules(self.root, build_tool=" Gradle "),
                {"tool": "gradle"},
            )
            gradle.assert_called_once()
        with mock.patch.object(
            contract, "detect_project_build_tool", return_value="maven"
        ) as detect, mock.patch.object(
            contract, "discover_maven_modules", return_value={"tool": "maven"}
        ) as maven:
            self.assertEqual(
                contract.discover_project_modules(
                    self.root, active_profiles={"p"}
                ),
                {"tool": "maven"},
            )
            detect.assert_called_once()
            maven.assert_called_once_with(self.root, active_profiles={"p"})

        modules = [
            self.module(self.root, ".", coord="g:root", artifact="root"),
            self.module(self.root, "a/b", coord="g:child", artifact="child"),
            self.module(self.root, "other", coord="x:child", artifact="child"),
        ]
        for selector in (None, "", "root", "__root__", "./"):
            self.assertEqual(contract._resolve_target(modules, selector)["module"], ".")
        self.assertEqual(contract._resolve_target(modules, "a\\b")["module"], "a/b")
        self.assertEqual(contract._resolve_target(modules, ":a:b")["module"], "a/b")
        self.assertEqual(contract._resolve_target(modules, "g:child")["module"], "a/b")
        self.assertIsNone(contract._resolve_target(modules, "child"))
        self.assertIsNone(contract._resolve_target(modules, "missing"))

    def test_project_scope_unresolved_profile_and_dependency_closure_matrix(self):
        modules = [self.module(self.root, ".", coord="g:root")]
        discovery = {"status": "complete", "reason_codes": [], "modules": modules}
        with mock.patch.object(contract, "discover_project_modules", return_value=discovery):
            unresolved_maven = contract.build_project_scope(
                self.root, "missing", active_profiles={"", "p"}, build_tool="maven"
            )
            unresolved_gradle = contract.build_project_scope(
                self.root, "missing", active_profiles={"p"}, build_tool="gradle"
            )
        self.assertEqual(unresolved_maven["active_maven_profiles"], ["p"])
        self.assertEqual(unresolved_gradle["active_maven_profiles"], [])

        for relative in (
            "app/src/main/java",
            "app/src/main/resources",
            "optional/src/main/kotlin",
            "coord/src/main/groovy",
            "artifact/custom-source",
            "artifact/custom-resource",
        ):
            (self.root / relative).mkdir(parents=True)
        absolute_source = self.root / "absolute-source"
        absolute_source.mkdir()
        modules = [
            self.module(
                self.root,
                ".",
                coord="g:root",
                artifact="root",
                dependency_edges=[{"module": "app", "coord": "", "optional": False}],
            ),
            self.module(
                self.root,
                "app",
                coord="g:app",
                dependency_edges=[
                    {"module": "optional", "coord": "", "optional": True},
                    {"coord": "g:coord", "optional": False},
                    {"coord": "artifact", "optional": False},
                    {"coord": "duplicate", "optional": False},
                    {"coord": "missing", "optional": False},
                    {"coord": "x:missing", "optional": False},
                ],
                sources=[
                    "",
                    "missing-declared",
                    "${custom.source}",
                    "${p0}",
                    str(absolute_source),
                ],
                properties={
                    "custom.source": "${nested.source}",
                    "nested.source": "src/main/java",
                    "p0": "${p1}",
                    "p1": "${p2}",
                    "p2": "${p3}",
                    "p3": "${p4}",
                    "p4": "${p5}",
                    "p5": "missing-chain",
                },
            ),
            self.module(self.root, "optional", coord="g:optional"),
            self.module(self.root, "coord", coord="g:coord"),
            self.module(
                self.root,
                "artifact",
                coord="",
                artifact="artifact",
                sources=["custom-source"],
                resources=["", "custom-resource"],
            ),
            self.module(self.root, "dup1", artifact="duplicate"),
            self.module(self.root, "dup2", artifact="duplicate"),
            self.module(self.root, "excluded", coord="g:excluded"),
        ]
        discovery = {
            "status": "complete",
            "reason_codes": ["discovery_warning"],
            "root_config_hash": "gradle-root",
            "modules": modules,
        }
        with mock.patch.object(
            contract, "discover_project_modules", return_value=discovery
        ), mock.patch.object(contract, "git_revision", return_value="revision"):
            scope = contract.build_project_scope(
                self.root, "app", active_profiles={"ignored"}, build_tool="gradle"
            )
        self.assertEqual(
            scope["included_modules"], ["app", "optional", "coord", "artifact"]
        )
        self.assertIn("declared_source_roots_missing", scope["reason_codes"])
        self.assertEqual(scope["status"], "partial")
        self.assertIn(str(absolute_source.resolve()), scope["source_roots"])
        self.assertIn("excluded", scope["excluded_modules"])
        self.assertEqual(scope["active_maven_profiles"], [])
        self.assertEqual(scope["source_revision"], "revision")

        no_root_dir = self.root / "standalone"
        (no_root_dir / "src" / "main" / "java").mkdir(parents=True)
        no_root = self.module(self.root, "standalone", coord="g:standalone")
        with mock.patch.object(
            contract,
            "discover_project_modules",
            return_value={
                "status": "complete",
                "reason_codes": [],
                "modules": [no_root],
            },
        ), mock.patch.object(contract, "git_revision", return_value="revision"):
            no_root_scope = contract.build_project_scope(
                self.root, "standalone", build_tool="maven"
            )
        self.assertEqual(no_root_scope["status"], "complete")

        with mock.patch.object(
            contract,
            "discover_project_modules",
            return_value={"status": "complete", "reason_codes": [], "modules": []},
        ):
            unresolved_empty = contract.build_project_scope(
                self.root, None, build_tool="maven"
            )
        self.assertEqual(unresolved_empty["target_module"], "")

    def test_project_scope_legacy_dependencies_optional_root_and_no_sources(self):
        target = self.module(
            self.root,
            ".",
            coord="g:root",
            dependencies=["child", "optional"],
        )
        child = self.module(
            self.root,
            "child",
            coord="g:child",
            dependency_edges=[{"coord": "optional", "optional": True}],
        )
        optional = self.module(self.root, "optional", coord="g:optional")
        discovery = {
            "status": "complete",
            "reason_codes": [],
            "modules": [target, child, optional],
        }
        with mock.patch.object(
            contract, "discover_project_modules", return_value=discovery
        ), mock.patch.object(contract, "git_revision", return_value=""):
            scope = contract.build_project_scope(
                self.root, ".", active_profiles={"p"}, build_tool="maven"
            )
        self.assertEqual(scope["included_modules"], [".", "child", "optional"])
        self.assertEqual(scope["status"], "insufficient")
        self.assertIn("system_source_roots_missing", scope["reason_codes"])
        self.assertEqual(scope["active_maven_profiles"], ["p"])

    def test_coverage_status_provenance_fields_and_error_matrix(self):
        self.assertEqual(contract.aggregate_coverage_status([]), "not_applicable")
        self.assertEqual(
            contract.aggregate_coverage_status(["invalid", "not_applicable"]),
            "not_applicable",
        )
        self.assertEqual(
            contract.aggregate_coverage_status(["complete", "partial", "insufficient"]),
            "insufficient",
        )

        self.assertEqual(
            contract.project_scope_provenance_fields(None),
            {
                "project_scope_hash": "",
                "source_state_hash": "",
                "build_tool": "maven",
                "build_model_hash": "",
                "maven_model_hash": "",
                "gradle_model_hash": "",
                "active_maven_profiles": [],
            },
        )
        gradle_fields = contract.project_scope_provenance_fields({
            "scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "gradle",
            "gradle_model_hash": "gradle",
            "active_maven_profiles": ["", " z ", "a", "a"],
        })
        self.assertEqual(gradle_fields["build_model_hash"], "gradle")
        self.assertEqual(gradle_fields["active_maven_profiles"], ["a", "z"])

        base_scope = {
            "scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "maven",
            "build_model_hash": "model",
            "maven_model_hash": "model",
            "active_maven_profiles": ["p"],
        }
        matching = {
            "project_scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "maven",
            "build_model_hash": "model",
            "maven_model_hash": "model",
            "active_maven_profiles": ["p"],
        }
        self.assertEqual(contract.project_scope_provenance_errors(base_scope, matching), [])

        missing_expected = dict(base_scope)
        missing_expected.update(scope_hash="", source_state_hash="", build_model_hash="", maven_model_hash="")
        errors = contract.project_scope_provenance_errors(missing_expected, {})
        self.assertIn("project_project_scope_hash_missing", errors)
        self.assertIn("project_source_state_hash_missing", errors)
        self.assertIn("project_build_model_hash_missing", errors)

        missing_actual = contract.project_scope_provenance_errors(base_scope, {
            "build_tool": "maven", "active_maven_profiles": ["p"]
        })
        self.assertIn("build_project_scope_hash_missing", missing_actual)
        self.assertIn("build_source_state_hash_missing", missing_actual)
        self.assertIn("build_build_model_hash_missing", missing_actual)

        mismatching = dict(matching)
        mismatching.update(
            project_scope_hash="other",
            source_state_hash="other",
            build_model_hash="other",
            build_tool="gradle",
        )
        mismatch_errors = contract.project_scope_provenance_errors(base_scope, mismatching)
        self.assertIn("build_project_scope_mismatch", mismatch_errors)
        self.assertIn("build_source_state_mismatch", mismatch_errors)
        self.assertIn("build_model_mismatch", mismatch_errors)
        self.assertIn("build_tool_mismatch", mismatch_errors)

        scope_no_profiles = dict(base_scope)
        scope_no_profiles.pop("active_maven_profiles")
        self.assertIn(
            "project_active_profiles_missing",
            contract.project_scope_provenance_errors(scope_no_profiles, matching),
        )
        provenance_no_profiles = dict(matching)
        provenance_no_profiles.pop("active_maven_profiles")
        self.assertIn(
            "build_active_profiles_missing",
            contract.project_scope_provenance_errors(base_scope, provenance_no_profiles),
        )
        profile_mismatch = dict(matching, active_maven_profiles=["other"])
        self.assertIn(
            "build_active_profiles_mismatch",
            contract.project_scope_provenance_errors(base_scope, profile_mismatch),
        )

        gradle_scope = {
            "scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "gradle",
            "gradle_model_hash": "gradle-model",
        }
        gradle_provenance_without_tool = {
            "project_scope_hash": "scope",
            "source_state_hash": "state",
            "gradle_model_hash": "gradle-model",
        }
        self.assertEqual(
            contract.project_scope_provenance_errors(
                gradle_scope, gradle_provenance_without_tool
            ),
            [],
        )
        self.assertIn(
            "project_active_profiles_missing",
            contract.project_scope_provenance_errors(None, None),
        )

    def test_build_provenance_artifact_and_execution_status_matrix(self):
        artifact = self.write(self.root / "app.jar", "artifact")
        scope = {
            "scope_hash": "scope",
            "source_state_hash": "state",
            "build_model_hash": "model",
            "build_tool": "gradle",
        }
        with mock.patch.object(contract, "git_revision", return_value="revision"):
            succeeded = contract.build_provenance(
                self.root,
                "current",
                "main",
                "app",
                "./gradlew build",
                artifact,
                "/jdk",
                project_scope=scope,
            )
            failed = contract.build_provenance(
                self.root, "base", "", "", "build", self.root / "missing.jar"
            )
            not_executed = contract.build_provenance(
                self.root, "base", None, None, "", ""
            )
        self.assertEqual(succeeded["build_execution_status"], "succeeded")
        self.assertTrue(succeeded["artifact_available"])
        self.assertEqual(len(succeeded["artifact_sha256"]), 64)
        self.assertEqual(failed["build_execution_status"], "failed")
        self.assertEqual(not_executed["build_execution_status"], "not_executed")

        derived_scope = {"status": "complete", "scope_hash": "derived"}
        with mock.patch.object(
            contract, "build_project_scope", return_value=derived_scope
        ) as build_scope, mock.patch.object(contract, "git_revision", return_value="revision"):
            payload = contract.build_provenance(
                self.root,
                "current",
                "main",
                "app",
                "",
                active_profiles=["p"],
            )
        build_scope.assert_called_once_with(self.root, "app", active_profiles={"p"})
        self.assertEqual(payload["project_scope_hash"], "derived")

        with mock.patch.object(
            contract, "build_project_scope", return_value=derived_scope
        ) as no_profile_scope, mock.patch.object(
            contract, "git_revision", return_value="revision"
        ):
            contract.build_provenance(
                self.root,
                "current",
                "main",
                "app",
                "",
                active_profiles=None,
            )
        no_profile_scope.assert_called_once_with(
            self.root, "app", active_profiles=set()
        )

    def test_csv_rows_and_empty_coverage_report(self):
        self.assertEqual(contract._csv_rows(self.root / "missing.csv"), [])
        csv_path = self.write(self.root / "rows.csv", "a,b\n1,2\n")
        self.assertEqual(contract._csv_rows(csv_path), [{"a": "1", "b": "2"}])

        report = self.root / "empty-report"
        payload = contract.derive_coverage_report(report)
        components = {row["id"]: row for row in payload["components"]}
        self.assertEqual(components["project_scope"]["status"], "insufficient")
        self.assertEqual(components["dependency_diff"]["status"], "not_applicable")
        self.assertEqual(components["build_provenance"]["status"], "not_applicable")
        self.assertEqual(components["static_scan"]["status"], "not_applicable")
        self.assertEqual(components["binary_authority_decision"]["status"], "not_applicable")
        self.assertEqual(components["business_reachability"]["status"], "not_applicable")
        self.assertEqual(payload["overall_status"], "insufficient")
        scoped = contract.derive_coverage_report(
            report,
            project_scope={
                "status": "partial",
                "reason_codes": ["explicit_scope_warning"],
            },
        )
        project_component = next(
            row for row in scoped["components"] if row["id"] == "project_scope"
        )
        self.assertEqual(
            project_component["reason_codes"], ["EXPLICIT_SCOPE_WARNING"]
        )

    def test_coverage_report_dependency_static_and_binary_state_matrix(self):
        report = self.root / "report"
        dep_path = report / "evidence" / "dependencies" / "dep_changes.csv"
        self.write(
            dep_path,
            "pairing_reason_code,resolution_status\nambiguous,unresolved\n,unresolved\n",
        )
        static_path = report / ".runtime" / "coverage" / "s3_coverage.json"
        self.write(static_path, "{invalid")
        api_dir = report / "evidence" / "api_changes"
        self.write(api_dir / "all_changed_apis.csv", "api\nA\n")
        self.write(api_dir / "summary.json", "{invalid")
        self.write(api_dir / "changed_dependencies.md", "changed")
        payload = contract.derive_coverage_report(
            report,
            project_scope={"status": "complete", "reason_codes": []},
        )
        components = {row["id"]: row for row in payload["components"]}
        self.assertEqual(
            components["dependency_diff"]["reason_codes"],
            ["DEPENDENCY_PAIRING_AMBIGUOUS"],
        )
        self.assertEqual(components["static_scan"]["status"], "insufficient")
        self.assertEqual(
            components["binary_authority_decision"]["status"], "insufficient"
        )
        self.assertEqual(
            len(components["binary_authority_decision"]["evidence"]), 3
        )

        self.write(dep_path, "pairing_reason_code,resolution_status\n,unresolved\n")
        self.write(static_path, json.dumps({
            "status": "complete", "reason_codes": [], "metrics": {"rules": 1}
        }))
        self.write(api_dir / "summary.json", json.dumps({
            "authority": "binary_first",
            "decision_coverage_status": "complete",
            "coverage": {"decision_coverage_gaps": []},
            "dependency_count": "2",
            "authoritative_change_fact_count": "3",
        }))
        complete = contract.derive_coverage_report(
            report,
            project_scope={"status": "complete", "reason_codes": []},
        )
        complete_components = {row["id"]: row for row in complete["components"]}
        self.assertEqual(
            complete_components["dependency_diff"]["reason_codes"],
            ["DEPENDENCY_COORDINATES_UNRESOLVED"],
        )
        self.assertEqual(complete_components["static_scan"]["status"], "complete")
        self.assertEqual(
            complete_components["binary_authority_decision"]["status"], "complete"
        )

        self.write(dep_path, "pairing_reason_code,resolution_status\n,resolved\n")
        self.write(static_path, "{}")
        self.write(api_dir / "summary.json", json.dumps({
            "authority": "binary_first",
            "decision_coverage_status": "partial",
        }))
        fallback_fields = contract.derive_coverage_report(
            report,
            project_scope={"status": "complete", "reason_codes": []},
            api_changes_dir=api_dir,
            call_chain_dir=report / "explicit-call-chain",
        )
        fallback_components = {
            row["id"]: row for row in fallback_fields["components"]
        }
        self.assertEqual(fallback_components["dependency_diff"]["status"], "complete")
        self.assertEqual(fallback_components["static_scan"]["status"], "insufficient")
        self.assertEqual(
            fallback_components["binary_authority_decision"]["reason_codes"], []
        )
        self.assertEqual(fallback_components["project_scope"]["reason_codes"], [])

        (api_dir / "all_changed_apis.csv").unlink()
        absent_api = contract.derive_coverage_report(report)
        absent_components = {row["id"]: row for row in absent_api["components"]}
        self.assertEqual(
            absent_components["binary_authority_decision"]["status"],
            "not_applicable",
        )

        static_path.unlink()
        self.write(report / "evidence" / "static_scan" / "s3_anything.txt", "x")
        missing_static = contract.derive_coverage_report(report)
        missing_components = {row["id"]: row for row in missing_static["components"]}
        self.assertEqual(missing_components["static_scan"]["status"], "partial")

    def test_coverage_report_provenance_state_matrix(self):
        report = self.root / "provenance-report"
        path = report / "evidence" / "dependencies" / "build_provenance.json"
        scope = {
            "status": "complete",
            "scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "maven",
            "build_model_hash": "model",
            "maven_model_hash": "model",
            "active_maven_profiles": [],
        }

        def component(payload):
            self.write(path, json.dumps(payload))
            result = contract.derive_coverage_report(report, scope)
            return next(row for row in result["components"] if row["id"] == "build_provenance")

        self.assertEqual(component({
            "both_builds_succeeded": False,
            "sides": [],
        })["status"], "insufficient")
        self.assertEqual(component({
            "both_builds_succeeded": True,
            "sides": [{"side": "base", "artifact_sha256": ""}],
        })["reason_codes"], ["ARTIFACT_HASH_MISSING"])
        self.assertEqual(component({
            "both_builds_succeeded": True,
            "sides": [
                {"artifact_sha256": "hash"},
                {"side": "base", "artifact_sha256": "hash"},
            ],
        })["status"], "insufficient")
        current = {
            "side": "current",
            "artifact_sha256": "hash",
            "project_scope_hash": "scope",
            "source_state_hash": "state",
            "build_tool": "maven",
            "build_model_hash": "model",
            "maven_model_hash": "model",
            "active_maven_profiles": [],
        }
        self.assertEqual(component({
            "both_builds_succeeded": True,
            "sides": [dict(current, side="base"), current],
        })["status"], "complete")

    def test_coverage_report_binary_partial_and_reachability_status_matrix(self):
        report = self.root / "reachability-report"
        api_dir = report / "evidence" / "api_changes"
        self.write(api_dir / "all_changed_apis.csv", "api\nA\n")
        self.write(api_dir / "summary.json", json.dumps({
            "authority": "binary_first",
            "decision_coverage_status": "partial",
            "coverage": {"decision_coverage_gaps": ["gap"]},
        }))
        step5 = report / "evidence" / "call_chain" / "summary.json"

        cases = (
            ({"total_apis": 2, "reachable": 1, "uncertain": 1}, "complete", []),
            ({"total_apis": 2, "reachable": 1, "not_analyzed": 1}, "partial", ["STEP5_NOT_ANALYZED_TARGETS"]),
            ({"total_apis": 3, "reachable": 1}, "partial", ["STEP5_TARGET_COUNT_MISMATCH"]),
            ({"total_apis": 3}, "insufficient", ["STEP5_TARGET_COUNT_MISMATCH"]),
            ({"total_apis": 0}, "not_applicable", []),
            ({"total_apis": 1, "not_found_in_static_analysis": 1}, "complete", []),
        )
        for state, expected_status, expected_reasons in cases:
            with self.subTest(state=state):
                self.write(step5, json.dumps(state))
                result = contract.derive_coverage_report(
                    report,
                    api_changes_dir=api_dir,
                    call_chain_dir=step5.parent,
                )
                components = {row["id"]: row for row in result["components"]}
                reachability = components["business_reachability"]
                self.assertEqual(reachability["status"], expected_status)
                self.assertEqual(reachability["reason_codes"], expected_reasons)
                self.assertEqual(
                    components["binary_authority_decision"]["status"], "partial"
                )

        self.write(step5, "{invalid")
        invalid = contract.derive_coverage_report(report)
        invalid_reachability = next(
            row for row in invalid["components"] if row["id"] == "business_reachability"
        )
        self.assertEqual(invalid_reachability["status"], "not_applicable")

    def test_write_coverage_report_executes_derivation_and_enforcement_matrix(self):
        payload = {
            "schema": "coverage",
            "components": [],
        }
        with mock.patch.object(
            contract, "derive_coverage_report", side_effect=lambda *_args, **_kwargs: dict(payload)
        ) as derive:
            advisory = contract.write_coverage_report(self.root / "advisory")
            required = contract.write_coverage_report(
                self.root / "required", {"status": "partial"}
            )
            insufficient = contract.write_coverage_report(
                self.root / "insufficient", {"status": "insufficient"}
            )
        self.assertEqual(advisory["enforcement"], "advisory")
        self.assertEqual(required["enforcement"], "required")
        self.assertEqual(insufficient["enforcement"], "advisory")
        self.assertEqual(derive.call_count, 3)
        written = json.loads(
            (self.root / "required" / ".runtime" / "coverage" / "coverage.json").read_text()
        )
        self.assertEqual(written["enforcement"], "required")


if __name__ == "__main__":
    unittest.main()
