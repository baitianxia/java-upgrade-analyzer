import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
from binary_pipeline import (  # noqa: E402
    BinaryPipelineError,
    _source_inputs_contract,
    run_pipeline,
)
from binary_runtime_materializer import materialize_binary_pipeline_config  # noqa: E402
from binary_report import (  # noqa: E402
    BinaryReportError,
    LEGACY_ALERT_FIELDS,
    load_validated_generation,
    publish_step4,
    publish_step5,
    publish_step6,
)
from binary_validation_oracle import (  # noqa: E402
    _declared_members,
    _oracle_runtime_contexts,
    _oracle_provider_location,
    _parse_javap_structural,
    _provider_resource_path,
    _resolve_member,
    validate_generation,
)
from s5_query_call_chain import query_scope_call_chain_result  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryPipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = jdk_home()
        if not shutil.which("javac") or not cls.home or not (cls.home / "jmods").is_dir():
            raise unittest.SkipTest("full target JDK required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_structural_oracle_preserves_array_type_instruction_targets(self):
        parsed = _parse_javap_structural(
            """
public class demo.ArrayCasts {
  java.lang.String[] cast(java.lang.Object);
    descriptor: (Ljava/lang/Object;)[Ljava/lang/String;
    Code:
       0: aload_1
       1: checkcast     #7                  // class \"[Ljava/lang/String;\"
       4: areturn
  java.lang.Class literal();
    descriptor: ()Ljava/lang/Class;
    Code:
       0: ldc           #9                  // class \"[I\"
       2: areturn
}
"""
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "cast", "(Ljava/lang/Object;)[Ljava/lang/String;",
                1, "[Ljava/lang/String;", "checkcast",
            ),
            parsed["type_edges"],
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "method", "cast",
                "(Ljava/lang/Object;)[Ljava/lang/String;", 0,
            ),
            parsed["declared_members"],
        )
        self.assertIn(
            (
                "demo/ArrayCasts", "literal", "()Ljava/lang/Class;",
                0, "[I", "class_literal",
            ),
            parsed["type_edges"],
        )

    def test_runtime_oracle_resolves_object_array_component_and_skips_primitives(self):
        contexts = _oracle_runtime_contexts(
            {
                "java/lang/String": {
                    "status": "definition_ready",
                    "provider_url": "jrt:/java.base/java/lang/String.class",
                    "super_name": "",
                    "interfaces": [],
                },
            },
            ["[I", "[B", "[Ljava/lang/String;", "[[Ljava/lang/String;"],
            ["application-loader"],
            "platform-loader",
        )
        self.assertEqual(
            contexts,
            (("application-loader", "java/lang/String"),),
        )

    def test_runtime_oracle_keeps_provider_selection_separate_from_definition(self):
        self.assertEqual(
            _provider_resource_path(
                "jar:file:/tmp/runtime.jar!/optional/Type.class"
            ),
            Path("/tmp/runtime.jar").resolve(),
        )
        self.assertIsNone(
            _provider_resource_path(
                "jrt:/java.base/java/lang/String.class"
            )
        )

    def test_runtime_oracle_applies_object_fallback_for_interface_methods(self):
        observations = {
            "demo/Api": {
                "status": "definition_ready", "modifiers": 0x0601,
                "members": [], "super_name": "", "interfaces": [],
            },
            "java/lang/Object": {
                "status": "definition_ready", "modifiers": 0x0001,
                "members": [
                    "method|getClass|()Ljava/lang/Class;|273",
                    "method|clone|()Ljava/lang/Object;|260",
                ],
                "super_name": "", "interfaces": [],
            },
        }
        resolved = _resolve_member(
            observations, "demo/Api", "method", "getClass",
            "()Ljava/lang/Class;",
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], "java/lang/Object")
        self.assertIsNone(_resolve_member(
            observations, "demo/Api", "method", "clone",
            "()Ljava/lang/Object;",
        ))

    def test_runtime_oracle_uses_javap_member_when_optional_member_linkage_failed(self):
        observations = {
            "demo/OptionalApi": {
                "status": "definition_failed",
                "failure_phase": "member_linkage",
                "modifiers": 0x0401,
                "super_name": "java/lang/Object",
                "interfaces": [],
                "members": [],
                "javap_declared_members": ["method|available|()V|1"],
            }
        }
        resolved = _resolve_member(
            observations, "demo/OptionalApi", "method", "available", "()V"
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], "demo/OptionalApi")

    def test_runtime_oracle_deduplicates_reflection_and_javap_member_views(self):
        observation = {
            "members": ["method|run|([Ljava/lang/String;)V|129"],
            "javap_declared_members": ["method|run|([Ljava/lang/String;)V|1"],
        }
        self.assertEqual(
            _declared_members(observation),
            [("method", "run", "([Ljava/lang/String;)V", 129)],
        )

    def test_runtime_oracle_uses_code_source_for_non_base_jdk_modules(self):
        self.assertEqual(
            _oracle_provider_location({
                "provider_resource_url": "",
                "provider_url": "jrt:/jdk.jdi",
                "status": "definition_ready",
            }),
            "jrt:/jdk.jdi",
        )
        self.assertEqual(
            _oracle_provider_location({
                "provider_resource_url": "jrt:/java.base/java/lang/String.class",
                "provider_url": "",
            }),
            "jrt:/java.base/java/lang/String.class",
        )

    def test_source_inputs_are_derived_from_actual_source_sets(self):
        self.assertEqual(
            _source_inputs_contract({}),
            {
                "purpose_version": "source-input-purpose-v2",
                "business": {"status": "not_provided", "origin": "not_provided"},
                "dependencies": {"status": "not_provided", "origin": "not_provided"},
            },
        )

    def test_source_input_metadata_cannot_hide_an_available_overlay(self):
        config = {
            "source_inputs": {
                "business": {"status": "not_provided"},
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": ["/not/read"],
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        with self.assertRaises(BinaryPipelineError) as raised:
            _source_inputs_contract(config)
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_BUSINESS_SOURCE_STATUS_MISMATCH",
        )

    def _jar(
        self, side, value, *, service_provider=None, manifest=None,
        uses_system_out=False,
    ):
        source = self.root / side / "src" / "demo" / "Api.java"
        source.parent.mkdir(parents=True)
        statement = 'System.out.print(""); ' if uses_system_out else ""
        source.write_text(
            f"package demo; public class Api {{ public int value(){{ {statement}return {value}; }} }}",
            encoding="utf-8",
        )
        classes = self.root / side / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar = self.root / side / "api.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.write(classes / "demo" / "Api.class", "demo/Api.class")
            if manifest is not None:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
            if service_provider:
                archive.writestr(
                    "META-INF/services/demo.Service", f"{service_provider}\n"
                )
        return jar

    def _compile_sources_jar(self, label, sources, *, classpath=()):
        source_root = self.root / label / "src"
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / label / "classes"
        classes.mkdir(parents=True)
        command = ["javac", "-g"]
        if classpath:
            command.extend(["-cp", os.pathsep.join(map(str, classpath))])
        command.extend(["-d", str(classes), *map(str, paths)])
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar = self.root / label / f"{label}.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        return jar

    def _side(self, jar, version="1"):
        return {
            "jdk_home": str(self.home),
            "artifacts": [{
                "path": str(jar),
                "logical_location": "lib/api.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 0,
                "coord": f"com.acme:api:{version}",
                "lineage": "com.acme:api",
                "runtime_code_source_origin_identity": "deployment-api",
            }],
            "runtime_profile": {
                "container_and_launcher_kind": "java-classpath",
                "loader_topology": {
                    "coverage_status": "complete",
                    "entrypoint_realms": ["application-loader"],
                    "realms": [
                        {
                            "identity": "platform-loader",
                            "kind": "platform",
                            "delegation": "parent_first",
                            "module_mode": "named-platform",
                        },
                        {
                            "identity": "application-loader",
                            "kind": "application",
                            "parent": "platform-loader",
                            "delegation": "parent_first",
                            "module_mode": "unnamed",
                        },
                    ],
                },
                "runtime_security_and_package_sealing_policy_identity": (
                    "standard-unsealed-unsigned-v1"
                ),
                "active_profile_identities": ["default"],
                "external_config_snapshot_identities": [],
                "agent_transformer_plugin_profile_identities": [],
                "business_entrypoint_profile": {
                    "coverage_status": "complete",
                    "methods": [{
                        "initiating_loader_realm_identity": "application-loader",
                        "class_name": "demo/Api",
                        "member_name": "value",
                        "descriptor": "()I",
                    }],
                },
                "runtime_class_closure_coverage_status": "complete",
                "resource_selection_coverage_status": "complete",
            },
        }

    def test_changed_api_with_complete_empty_entrypoints_uses_empty_closed_world(self):
        base = self._jar("empty-roots-base", 1)
        current = self._jar("empty-roots-current", 2)
        base_side = self._side(base, "1")
        current_side = self._side(current, "2")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config, output_root=self.root / "empty-roots-report"
        )
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        coverage = json.loads(
            (generation / "binary_coverage.json").read_text(encoding="utf-8")
        )

        self.assertTrue(formal["results"])
        self.assertEqual(
            {item["reachability_status"] for item in formal["results"]},
            {"not_found_in_static_analysis"},
        )
        self.assertTrue(all(not item["paths"] for item in formal["results"]))
        self.assertEqual(
            coverage["batch_graph_stats"]["graph_materialization_status"],
            "not_required_empty_root_set",
        )
        self.assertEqual(result["validation_status"], "passed")

    def test_two_dependency_pairings_with_same_resource_delta_remain_distinct(self):
        def resource_jar(label, content):
            path = self.root / label / f"{label}.jar"
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META-INF/LICENSE", content)
            return path

        base_jar = resource_jar("shared-resource-base", b"old-license")
        current_jar = resource_jar("shared-resource-current", b"new-license")

        def side(path, version):
            result = self._side(path, version)
            result["artifacts"] = [
                {
                    "path": str(path),
                    "logical_location": f"lib/dependency-{suffix}.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "classpath",
                    "slot": index,
                    "coord": f"com.acme:dependency-{suffix}:{version}",
                    "lineage": f"com.acme:dependency-{suffix}",
                    "runtime_code_source_origin_identity": (
                        f"deployment-dependency-{suffix}"
                    ),
                }
                for index, suffix in enumerate(("a", "b"))
            ]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [],
            }
            return result

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_jar, "1"),
            "current": side(current_jar, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "same-resource-two-pairings-report")

        decisions = json.loads(
            (Path(result["generation_directory"]) / "binary_decisions.json")
            .read_text(encoding="utf-8")
        )
        raw_resource_decisions = [
            row for row in decisions["excluded_decisions"]
            if row["reason_code"]
            == "ARTIFACT_RESOURCE_OBSERVATION_RECONCILED_BY_SELECTION_VIEW"
        ]
        self.assertEqual(len(raw_resource_decisions), 2)
        self.assertEqual(len({
            row["disposition_obligation_identity"]
            for row in raw_resource_decisions
        }), 2)
        self.assertEqual({
            artifact["logical_dependency_lineage"]
            for row in raw_resource_decisions
            for artifact in row["dependency_artifacts"]
        }, {"com.acme:dependency-a", "com.acme:dependency-b"})
        self.assertEqual(result["validation_status"], "passed")

    def test_trace_preserves_independent_entrypoint_paths_for_one_changed_api(self):
        def target(label, value):
            return self._compile_sources_jar(label, {
                "lib/Api.java": (
                    "package lib; public class Api { public int changed() { "
                    f"return {value}; }} }}"
                ),
            })

        base_target = target("multi-path-base", 1)
        current_target = target("multi-path-current", 2)
        business = self._compile_sources_jar("multi-path-business", {
            "biz/Shared.java": (
                "package biz; public class Shared { public int call() { "
                "return new lib.Api().changed(); } }"
            ),
            "biz/First.java": (
                "package biz; public class First { public int run() { "
                "return new Shared().call(); } }"
            ),
            "biz/Second.java": (
                "package biz; public class Second { public int run() { "
                "return new Shared().call(); } }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business),
                "logical_location": "app/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes",
                "slot": 0,
                "coord": "com.acme:application:1",
                "lineage": "com.acme:application",
                "runtime_code_source_origin_identity": "multi-path-business",
            }, {
                "path": str(target_jar),
                "logical_location": "lib/target.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 1,
                "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "multi-path-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": class_name,
                    "member_name": "run",
                    "descriptor": "()I",
                } for class_name in ("biz/First", "biz/Second")],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "multi-path-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal
            if item["display_owner"] == "lib/Api"
            and item["display_member"] == "changed"
        )
        self.assertTrue(changed["path_set_complete"])
        self.assertEqual(len(changed["paths"]), 2)
        self.assertEqual(
            {
                path["path_text"].split(" → ", 1)[0]
                for path in changed["paths"]
            },
            {"biz.First.run()", "biz.Second.run()"},
        )

    def test_path_budget_does_not_hide_exact_or_downgrade_unrelated_result(self):
        def target(label, changed_value, unused_value):
            return self._compile_sources_jar(label, {
                "lib/Api.java": (
                    "package lib; public class Api { "
                    f"public int changed() {{ return {changed_value}; }} "
                    f"public int unused() {{ return {unused_value}; }} }}"
                ),
            })

        base_target = target("path-budget-base", 1, 10)
        current_target = target("path-budget-current", 2, 20)
        method_names = [f"run{index:02d}" for index in range(21)]
        business = self._compile_sources_jar("path-budget-business", {
            "biz/Entrypoints.java": (
                "package biz; public class Entrypoints { "
                + " ".join(
                    f"public int {name}() {{ return new lib.Api().changed(); }}"
                    for name in method_names
                )
                + " }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business),
                "logical_location": "app/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes",
                "slot": 0,
                "coord": "com.acme:application:1",
                "lineage": "com.acme:application",
                "runtime_code_source_origin_identity": "path-budget-business",
            }, {
                "path": str(target_jar),
                "logical_location": "lib/target.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 1,
                "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "path-budget-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entrypoints",
                    "member_name": name,
                    "descriptor": "()I",
                } for name in method_names],
            }
            return result

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "path-budget-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal if item["display_member"] == "changed"
        )
        unused = next(
            item for item in formal if item["display_member"] == "unused"
        )
        self.assertEqual(changed["reachability_status"], "reachable")
        self.assertTrue(changed["exact_path_exists"])
        self.assertFalse(changed["path_set_complete"])
        self.assertEqual(len(changed["paths"]), 20)
        self.assertEqual(
            unused["reachability_status"], "not_found_in_static_analysis"
        )
        self.assertTrue(unused["path_set_complete"])

    def _automatic_scheduled_entry_fixture(self, *, include_activation_resource=True):
        def compile_core(label, value):
            source = self.root / label / "src" / "api" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                f"package api; public class Api {{ public int value() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "core.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "api" / "Api.class", "api/Api.class")
            return jar

        base_core = compile_core("scheduled-core-base", 1)
        current_core = compile_core("scheduled-core-current", 2)
        scheduler_root = self.root / "scheduler-entry"
        scheduler_sources = scheduler_root / "src"
        source_files = {
            "org/springframework/scheduling/annotation/Scheduled.java": """
                package org.springframework.scheduling.annotation;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                public @interface Scheduled { long fixedDelay() default 0; }
            """,
            "org/springframework/boot/autoconfigure/AutoConfiguration.java": """
                package org.springframework.boot.autoconfigure;
                import java.lang.annotation.*;
                @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                public @interface AutoConfiguration {}
            """,
            "org/springframework/boot/SpringApplication.java": """
                package org.springframework.boot;
                public final class SpringApplication {
                    private SpringApplication() {}
                    public static Object run(Class<?> type, String[] args) {
                        return null;
                    }
                }
            """,
            "vendor/ScheduledConfig.java": """
                package vendor;
                import api.Api;
                import org.springframework.boot.autoconfigure.AutoConfiguration;
                import org.springframework.scheduling.annotation.Scheduled;
                @AutoConfiguration
                public class ScheduledConfig {
                    @Scheduled(fixedDelay = 1000)
                    public int tick() { return new Api().value(); }
                }
            """,
        }
        scheduler_paths = []
        for relative, content in source_files.items():
            source = scheduler_sources / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(content, encoding="utf-8")
            scheduler_paths.append(source)
        scheduler_classes = scheduler_root / "classes"
        scheduler_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(base_core), "-d", str(scheduler_classes),
                *map(str, scheduler_paths),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        scheduler_jar = scheduler_root / "scheduler.jar"
        with zipfile.ZipFile(scheduler_jar, "w") as archive:
            for class_file in sorted(scheduler_classes.rglob("*.class")):
                archive.write(
                    class_file,
                    class_file.relative_to(scheduler_classes).as_posix(),
                )
            if include_activation_resource:
                archive.writestr(
                    "META-INF/spring/"
                    "org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                    "vendor.ScheduledConfig\n",
                )
        app_source = self.root / "scheduled-app" / "src" / "biz" / "Application.java"
        app_source.parent.mkdir(parents=True)
        app_source.write_text(
            "package biz; import org.springframework.boot.SpringApplication; "
            "public class Application { public static void main(String[] args) { "
            "SpringApplication.run(Application.class, args); } }",
            encoding="utf-8",
        )
        app_classes = self.root / "scheduled-app" / "classes"
        app_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(scheduler_jar),
                "-d", str(app_classes), str(app_source),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        app_jar = self.root / "scheduled-app" / "app.jar"
        with zipfile.ZipFile(app_jar, "w") as archive:
            archive.write(
                app_classes / "biz" / "Application.class",
                "biz/Application.class",
            )
        return base_core, current_core, scheduler_jar, app_jar

    def _automatic_entry_side(self, core, scheduler, app, version):
        side = self._side(core, version)
        side["artifacts"] = [
            {
                "path": str(app), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "deployment-business",
            },
            {
                "path": str(scheduler), "logical_location": "lib/scheduler.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": "com.acme:scheduler:1.0",
                "lineage": "com.acme:scheduler",
                "runtime_code_source_origin_identity": "deployment-scheduler",
            },
            {
                "path": str(core), "logical_location": "lib/core.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 2, "coord": f"com.acme:core:{version}",
                "lineage": "com.acme:core",
                "runtime_code_source_origin_identity": "deployment-core",
            },
        ]
        side["runtime_profile"]["business_entrypoint_profile"] = {
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "main_class": "biz.Application",
            "methods": [],
        }
        return side

    def test_dependency_scheduled_auto_configuration_is_reachable_without_manual_entrypoint(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture()
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._automatic_entry_side(base_core, scheduler, app, "1.0"),
            "current": self._automatic_entry_side(current_core, scheduler, app, "2.0"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "scheduled-report")
        generation = Path(result["generation_directory"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        self.assertTrue(formal["by_api"], formal)
        matching_targets = [
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        ]
        self.assertEqual(
            len(matching_targets), 1,
            [
                (item.get("display_owner"), item.get("display_member"))
                for item in formal["by_api"]
            ],
        )
        target = matching_targets[0]
        entrypoint_path = generation / "binary_entrypoints.json"
        entrypoints = json.loads(entrypoint_path.read_text())

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(target["paths"][0]["entry_kinds"], ["spring_scheduled"])
        self.assertEqual(
            target["paths"][0]["entry_kind_labels"], ["Spring 定时任务"]
        )
        self.assertEqual(
            target["paths"][0]["entrypoint_dependency_coords"],
            ["com.acme:scheduler:1.0"],
        )
        scheduled = next(
            item for item in entrypoints["records"]
            if item["entry_kind"] == "spring_scheduled"
        )
        self.assertEqual(scheduled["class_name"], "vendor/ScheduledConfig")
        self.assertEqual(scheduled["member_name"], "tick")
        self.assertEqual(scheduled["path_certainty"], "exact")
        self.assertEqual(
            scheduled["activation_reason"],
            "spring_boot_auto_configuration_import",
        )
        entrypoint_path.write_text(
            json.dumps({**entrypoints, "records": []}), encoding="utf-8"
        )
        independent_validation = validate_generation(config, generation)
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_ENTRYPOINT_SET_MISMATCH"
            for item in independent_validation["issues"]
        ), independent_validation["issues"])

    def test_dependency_scheduled_method_without_activation_proof_is_not_exact(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture(
            include_activation_resource=False
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._automatic_entry_side(base_core, scheduler, app, "1.0"),
            "current": self._automatic_entry_side(current_core, scheduler, app, "2.0"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "unactivated-report")
        generation = Path(result["generation_directory"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )
        entrypoints = json.loads((generation / "binary_entrypoints.json").read_text())
        scheduled = next(
            item for item in entrypoints["records"]
            if item["entry_kind"] == "spring_scheduled"
        )

        self.assertEqual(target["reachability_status"], "uncertain")
        self.assertEqual(scheduled["path_certainty"], "possible")
        self.assertEqual(
            scheduled["activation_reason"],
            "dependency_framework_activation_unproven",
        )

    def test_spring_xml_scheduled_entry_is_rebuilt_by_independent_oracle(self):
        base_core, current_core, scheduler, app = self._automatic_scheduled_entry_fixture(
            include_activation_resource=False
        )
        with zipfile.ZipFile(scheduler, "a") as archive:
            archive.writestr(
                "config/scheduler.xml",
                "<beans xmlns:task='urn:test'>"
                "<bean id='job' class='vendor.ScheduledConfig' init-method='tick'/>"
                "<task:scheduled-tasks>"
                "<task:scheduled target='job.tick'/>"
                "</task:scheduled-tasks></beans>",
            )
        base_side = self._automatic_entry_side(base_core, scheduler, app, "1.0")
        current_side = self._automatic_entry_side(current_core, scheduler, app, "2.0")
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"][
                "activated_resource_names"
            ] = ["classpath:config/scheduler.xml"]
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "scheduled-xml-report")
        generation = Path(result["generation_directory"])
        entries = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )["records"]
        xml_entry = next(
            item for item in entries if item["entry_kind"] == "spring_xml_scheduled"
        )
        init_entry = next(
            item for item in entries
            if item["entry_kind"] == "spring_xml_init_method"
        )
        validation = validate_generation(config, generation)

        self.assertEqual(xml_entry["path_certainty"], "exact")
        self.assertEqual(xml_entry["dependency_coord"], "com.acme:scheduler:1.0")
        self.assertEqual(init_entry["path_certainty"], "exact")
        self.assertEqual(init_entry["member_name"], "tick")
        self.assertEqual(validation["status"], "passed", validation["issues"])

    def test_persistence_unit_registration_proves_dependency_jpa_callback(self):
        def entity_jar(label, value):
            jar = self._compile_sources_jar(label, {
                "jakarta/persistence/Entity.java": (
                    "package jakarta.persistence; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface Entity {}"
                ),
                "jakarta/persistence/PostLoad.java": (
                    "package jakarta.persistence; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                    "public @interface PostLoad {}"
                ),
                "lib/EntityRecord.java": (
                    "package lib; @jakarta.persistence.Entity public class EntityRecord { "
                    "@jakarta.persistence.PostLoad public void afterLoad() { "
                    f"System.out.print({value}); }} }}"
                ),
            })
            with zipfile.ZipFile(jar, "a") as archive:
                archive.writestr(
                    "META-INF/persistence.xml",
                    "<?xml version=\"1.0\"?><persistence><persistence-unit name=\"app\">"
                    "<class>lib.EntityRecord</class></persistence-unit></persistence>",
                )
            return jar

        base = entity_jar("jpa-persistence-base", 1)
        current = entity_jar("jpa-persistence-current", 2)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "jpa-persistence-report")
        generation = Path(result["generation_directory"])
        entries = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )["records"]
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        callback_entry = next(
            item for item in entries
            if item["class_name"] == "lib/EntityRecord"
            and item["member_name"] == "afterLoad"
        )
        callback = next(
            item for item in formal
            if item["display_owner"] == "lib/EntityRecord"
            and str(item["display_member"]).startswith("afterLoad")
        )

        self.assertEqual(callback_entry["path_certainty"], "exact")
        self.assertEqual(
            callback_entry["activation_reason"], "jpa_entity_registration_proved"
        )
        self.assertEqual(callback["reachability_status"], "reachable")

    def test_exact_reflection_literals_create_typed_runtime_semantic_path(self):
        def target_jar(label, value):
            source = self.root / label / "src" / "lib" / "Target.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package lib; public class Target { public Target() {} "
                f"public int changed() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "target.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "lib" / "Target.class", "lib/Target.class")
            return jar

        base_target = target_jar("reflection-base", 1)
        current_target = target_jar("reflection-current", 2)
        source = self.root / "reflection-business" / "src" / "biz" / "Entry.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            "package biz; public class Entry { public int run() throws Exception { "
            "Class<?> type = Class.forName(\"lib.Target\"); "
            "java.lang.reflect.Method method = type.getDeclaredMethod(\"changed\"); "
            "Object target = type.getDeclaredConstructor().newInstance(); "
            "return ((Integer) method.invoke(target)).intValue(); } }",
            encoding="utf-8",
        )
        classes = self.root / "reflection-business" / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business = self.root / "reflection-business" / "business.jar"
        with zipfile.ZipFile(business, "w") as archive:
            archive.write(classes / "biz" / "Entry.class", "biz/Entry.class")

        def side(target, version):
            result = self._side(target, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "reflection-business",
            }, {
                "path": str(target), "logical_location": "lib/target.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "reflection-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry",
                    "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "reflection-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "lib/Target"
            and str(item["display_member"]).startswith("changed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "reflection_method_invocation"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))
        overlay["rows"] = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] != "reflection_method_invocation"
        ]
        overlay_path = generation / "binary_runtime_semantic_overlay.json"
        overlay_path.write_text(
            json.dumps(overlay, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path = generation / "result_generation.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sidecar_content_identities"][overlay_path.name] = hashlib.sha256(
            overlay_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        tampered = validate_generation(config, generation)
        self.assertTrue(any(
            issue["reason_code"] == "ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH"
            for issue in tampered["issues"]
        ), tampered["issues"])

    def test_exact_method_handle_lookup_reaches_dependency_change(self):
        def target(label, value):
            return self._compile_sources_jar(label, {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    f"public int changed() {{ return {value}; }} }}"
                ),
            })

        base_target = target("method-handle-base", 1)
        current_target = target("method-handle-current", 2)
        business = self._compile_sources_jar("method-handle-business", {
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() throws Throwable { "
                "java.lang.invoke.MethodHandle handle = java.lang.invoke.MethodHandles.lookup()"
                ".findVirtual(lib.Target.class, \"changed\", "
                "java.lang.invoke.MethodType.methodType(int.class)); "
                "return (int) handle.invokeExact(new lib.Target()); } }"
            ),
        }, classpath=(current_target,))

        def side(target_jar, version):
            result = self._side(target_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "method-handle-business",
            }, {
                "path": str(target_jar), "logical_location": "lib/target.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:target:{version}",
                "lineage": "com.acme:target",
                "runtime_code_source_origin_identity": "method-handle-target",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "method-handle-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed = next(
            item for item in formal
            if item["display_owner"] == "lib/Target"
            and str(item["display_member"]).startswith("changed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(changed["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "method_handle_invocation"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_invoked_registered_dynamic_proxy_handler_reaches_dependency_change(self):
        def api_jar(label, value):
            source = self.root / label / "src" / "api" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                f"package api; public class Api {{ public int value() {{ return {value}; }} }}",
                encoding="utf-8",
            )
            classes = self.root / label / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / label / "api.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "api" / "Api.class", "api/Api.class")
            return jar

        base_api = api_jar("proxy-base", 1)
        current_api = api_jar("proxy-current", 2)
        source_root = self.root / "proxy-business" / "src"
        sources = {
            "biz/Action.java": "package biz; public interface Action { int run(); }",
            "biz/Handler.java": (
                "package biz; public class Handler implements java.lang.reflect.InvocationHandler { "
                "public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { "
                "return Integer.valueOf(new api.Api().value()); } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { "
                "Action action = (Action) java.lang.reflect.Proxy.newProxyInstance("
                "Action.class.getClassLoader(), new Class<?>[]{Action.class}, new Handler()); "
                "return action.run(); } }"
            ),
        }
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / "proxy-business" / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-cp", str(current_api), "-d", str(classes), *map(str, paths)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business = self.root / "proxy-business" / "business.jar"
        with zipfile.ZipFile(business, "w") as archive:
            for class_file in classes.rglob("*.class"):
                archive.write(class_file, class_file.relative_to(classes).as_posix())

        def side(api, version):
            result = self._side(api, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "proxy-business",
            }, {
                "path": str(api), "logical_location": "lib/api.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:api:{version}", "lineage": "com.acme:api",
                "runtime_code_source_origin_identity": "proxy-api",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_api, "1"), "current": side(current_api, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "proxy-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "dynamic_proxy_callback"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_mybatis_mapper_proxy_dispatch_reaches_packaged_runtime_chain(self):
        def runtime(label, value):
            return self._compile_sources_jar(label, {
                "org/apache/ibatis/annotations/Mapper.java": (
                    "package org.apache.ibatis.annotations; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface Mapper {}"
                ),
                "org/apache/ibatis/session/SqlSession.java": (
                    "package org.apache.ibatis.session; public interface SqlSession {}"
                ),
                "org/apache/ibatis/binding/MapperProxy.java": (
                    "package org.apache.ibatis.binding; public class MapperProxy { "
                    "public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args) { "
                    f"return Integer.valueOf({value}); }} }}"
                ),
                "org/apache/ibatis/binding/MapperMethod.java": (
                    "package org.apache.ibatis.binding; public class MapperMethod { "
                    "public Object execute(org.apache.ibatis.session.SqlSession session, Object[] args) { "
                    "return null; } }"
                ),
            })

        base_runtime = runtime("mybatis-base", 1)
        current_runtime = runtime("mybatis-current", 2)
        business = self._compile_sources_jar("mybatis-business", {
            "biz/DemoMapper.java": (
                "package biz; @org.apache.ibatis.annotations.Mapper "
                "public interface DemoMapper { int findOne(); }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(DemoMapper mapper) { "
                "return mapper.findOne(); } }"
            ),
        }, classpath=(current_runtime,))

        def side(runtime_jar, version):
            result = self._side(runtime_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "mybatis-business",
            }, {
                "path": str(runtime_jar), "logical_location": "lib/mybatis.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"org.mybatis:mybatis:{version}",
                "lineage": "org.mybatis:mybatis",
                "runtime_code_source_origin_identity": "mybatis-runtime",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/DemoMapper;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_runtime, "1"), "current": side(current_runtime, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "mybatis-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "org/apache/ibatis/binding/MapperProxy"
            and str(item["display_member"]).startswith("invoke")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "mybatis_mapper_proxy_dispatch"
            and row["target_dependency_coord"] == "org.mybatis:mybatis:2"
            for row in overlay["rows"]
        ))

    def test_transactional_business_method_reaches_packaged_interceptor_chain(self):
        def runtime(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/transaction/annotation/Transactional.java": (
                    "package org.springframework.transaction.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Transactional {}"
                ),
                "org/aopalliance/intercept/MethodInvocation.java": (
                    "package org.aopalliance.intercept; public interface MethodInvocation {}"
                ),
                "org/springframework/transaction/interceptor/TransactionInterceptor.java": (
                    "package org.springframework.transaction.interceptor; public class TransactionInterceptor { "
                    "public Object invoke(org.aopalliance.intercept.MethodInvocation invocation) { "
                    f"return Integer.valueOf({value}); }} }}"
                ),
                "org/springframework/transaction/interceptor/TransactionAspectSupport.java": (
                    "package org.springframework.transaction.interceptor; public class TransactionAspectSupport { "
                    "public interface InvocationCallback {} "
                    "public Object invokeWithinTransaction(java.lang.reflect.Method method, Class<?> type, "
                    "InvocationCallback callback) { return null; } }"
                ),
                "org/springframework/aop/framework/ReflectiveMethodInvocation.java": (
                    "package org.springframework.aop.framework; public class ReflectiveMethodInvocation { "
                    "public Object proceed() { return null; } }"
                ),
            })

        base_runtime = runtime("transaction-base", 1)
        current_runtime = runtime("transaction-current", 2)
        business = self._compile_sources_jar("transaction-business", {
            "biz/Service.java": (
                "package biz; public class Service { "
                "@org.springframework.transaction.annotation.Transactional "
                "public int work() { return 7; } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { return new Service().work(); } }"
            ),
        }, classpath=(current_runtime,))

        def side(runtime_jar, version):
            result = self._side(runtime_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "transaction-business",
            }, {
                "path": str(runtime_jar), "logical_location": "lib/spring-runtime.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"org.springframework:spring-tx:{version}",
                "lineage": "org.springframework:spring-tx",
                "runtime_code_source_origin_identity": "transaction-runtime",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_runtime, "1"), "current": side(current_runtime, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "transaction-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"].endswith("TransactionInterceptor")
            and str(item["display_member"]).startswith("invoke")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(
            target["current_dependency_coords"],
            ["org.springframework:spring-tx:2"],
        )
        self.assertTrue(any(
            row["semantic_edge_kind"] == "spring_transaction_proxy_dispatch"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_component_wiring_and_spring_data_proxy_use_runtime_activation(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/stereotype/Component.java": (
                    "package org.springframework.stereotype; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Component {}"
                ),
                "org/springframework/context/annotation/ComponentScan.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface ComponentScan { String[] value() default {}; }"
                ),
                "org/springframework/context/annotation/Profile.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Profile { String[] value(); }"
                ),
                "org/springframework/context/annotation/Primary.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Primary {}"
                ),
                "org/springframework/data/repository/Repository.java": (
                    "package org.springframework.data.repository; public interface Repository<T,ID> {}"
                ),
                "org/springframework/data/jpa/repository/JpaRepository.java": (
                    "package org.springframework.data.jpa.repository; public interface JpaRepository<T,ID> "
                    "extends org.springframework.data.repository.Repository<T,ID> { java.util.List<T> findAll(); }"
                ),
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository.java": (
                    "package org.springframework.data.jpa.repository.support; public class SimpleJpaRepository<T,ID> { "
                    f"public java.util.List<T> findAll() {{ return {value} == 1 "
                    "? new java.util.ArrayList<T>() : java.util.Collections.emptyList(); } }"
                ),
                "lib/Service.java": "package lib; public interface Service { int ping(); }",
                "lib/LibService.java": (
                    "package lib; @org.springframework.stereotype.Component "
                    "@org.springframework.context.annotation.Primary "
                    "@org.springframework.context.annotation.Profile(\"prod\") "
                    f"public class LibService implements Service {{ public int ping() {{ return {value}; }} }}"
                ),
                "lib/BackupService.java": (
                    "package lib; @org.springframework.stereotype.Component "
                    "@org.springframework.context.annotation.Profile(\"prod\") "
                    f"public class BackupService implements Service {{ public int ping() {{ return {value + 10}; }} }}"
                ),
            })

        base_framework = framework("wiring-base", 1)
        current_framework = framework("wiring-current", 2)
        business = self._compile_sources_jar("wiring-business", {
            "biz/DemoRepository.java": (
                "package biz; public interface DemoRepository extends "
                "org.springframework.data.jpa.repository.JpaRepository<Object,Long> {}"
            ),
            "biz/Config.java": (
                "package biz; @org.springframework.context.annotation.ComponentScan(\"lib\") "
                "public class Config {}"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(lib.Service service, DemoRepository repo) { "
                "return service.ping() + repo.findAll().size(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "wiring-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:framework:{version}",
                "lineage": "com.acme:framework",
                "runtime_code_source_origin_identity": "wiring-framework",
            }]
            profile = result["runtime_profile"]
            profile["container_and_launcher_kind"] = "spring-boot-executable-jar"
            profile["active_profile_identities"] = ["prod"]
            profile["business_entrypoint_profile"] = {
                "coverage_status": "complete", "main_class": "biz.Application",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Llib/Service;Lbiz/DemoRepository;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "wiring-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        ping = next(
            item for item in formal if item["display_owner"] == "lib/LibService"
            and str(item["display_member"]).startswith("ping")
        )
        backup_ping = next(
            item for item in formal if item["display_owner"] == "lib/BackupService"
            and str(item["display_member"]).startswith("ping")
        )
        find_all = next(
            item for item in formal if item["display_owner"].endswith("SimpleJpaRepository")
            and str(item["display_member"]).startswith("findAll")
        )

        self.assertEqual(ping["reachability_status"], "reachable")
        self.assertEqual(
            backup_ping["reachability_status"], "uncertain"
        )
        self.assertEqual(find_all["reachability_status"], "reachable")
        self.assertIn("spring_bean_wiring_dispatch", {
            row["semantic_edge_kind"] for row in overlay["rows"]
        })
        wiring_edges = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
        ]
        self.assertEqual(
            {
                (row["target_class_name"], row["path_certainty"])
                for row in wiring_edges
                if row["target_member_name"] == "ping"
            },
            {("lib/LibService", "exact")},
        )
        self.assertIn("spring_data_repository_proxy_dispatch", {
            row["semantic_edge_kind"] for row in overlay["rows"]
        })

    def test_custom_spring_data_factory_does_not_claim_simple_repository_dispatch(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/springframework/data/repository/Repository.java": (
                    "package org.springframework.data.repository; "
                    "public interface Repository<T,ID> {}"
                ),
                "org/springframework/data/jpa/repository/JpaRepository.java": (
                    "package org.springframework.data.jpa.repository; "
                    "public interface JpaRepository<T,ID> extends "
                    "org.springframework.data.repository.Repository<T,ID> { "
                    "java.util.List<T> findAll(); }"
                ),
                "org/springframework/data/jpa/repository/config/EnableJpaRepositories.java": (
                    "package org.springframework.data.jpa.repository.config; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface EnableJpaRepositories { "
                    "Class<?> repositoryFactoryBeanClass(); }"
                ),
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository.java": (
                    "package org.springframework.data.jpa.repository.support; "
                    "public class SimpleJpaRepository<T,ID> { "
                    f"public java.util.List<T> findAll() {{ return {value} == 1 "
                    "? new java.util.ArrayList<T>() : java.util.Collections.emptyList(); } }"
                ),
            })

        base_framework = framework("custom-repository-base", 1)
        current_framework = framework("custom-repository-current", 2)
        business = self._compile_sources_jar("custom-repository-business", {
            "biz/DemoRepository.java": (
                "package biz; public interface DemoRepository extends "
                "org.springframework.data.jpa.repository.JpaRepository<Object,Long> {}"
            ),
            "biz/CustomFactory.java": (
                "package biz; public class CustomFactory {}"
            ),
            "biz/Config.java": (
                "package biz; "
                "@org.springframework.data.jpa.repository.config.EnableJpaRepositories("
                "repositoryFactoryBeanClass=biz.CustomFactory.class) "
                "public class Config {}"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { "
                "public int run(DemoRepository repository) { "
                "return repository.findAll().size(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            payload = self._side(framework_jar, version)
            payload["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "custom-repository-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:data:{version}",
                "lineage": "com.acme:data",
                "runtime_code_source_origin_identity": "custom-repository-framework",
            }]
            payload["runtime_profile"]["container_and_launcher_kind"] = (
                "spring-boot-executable-jar"
            )
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "activated_frameworks": ["spring_boot"],
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/DemoRepository;)I",
                }],
            }
            return payload

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"),
            "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "custom-repository-report")
        generation = Path(result["generation_directory"])
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            "spring_data_custom_repository_factory", overlay["coverage_gaps"]
        )
        self.assertFalse(any(
            row["semantic_edge_kind"] == "spring_data_repository_proxy_dispatch"
            for row in overlay["rows"]
        ))

    def test_spring_aop_and_security_filter_callbacks_remain_reachable(self):
        def framework(label, value):
            return self._compile_sources_jar(label, {
                "org/aspectj/lang/annotation/Aspect.java": (
                    "package org.aspectj.lang.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Aspect {}"
                ),
                "org/aspectj/lang/annotation/Around.java": (
                    "package org.aspectj.lang.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                    "public @interface Around { String value(); }"
                ),
                "io/micrometer/observation/annotation/Observed.java": (
                    "package io.micrometer.observation.annotation; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) "
                    "@Target({ElementType.TYPE,ElementType.METHOD}) "
                    "public @interface Observed {}"
                ),
                "io/micrometer/observation/aop/ObservedAspect.java": (
                    "package io.micrometer.observation.aop; "
                    "@org.aspectj.lang.annotation.Aspect "
                    "public class ObservedAspect { "
                    "@org.aspectj.lang.annotation.Around(\"@within("
                    "io.micrometer.observation.annotation.Observed) && "
                    "!@annotation(io.micrometer.observation.annotation.Observed) && "
                    "execution(* *.*(..))\") public void observeClass() {} }"
                ),
                "org/springframework/context/annotation/Bean.java": (
                    "package org.springframework.context.annotation; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface Bean {}"
                ),
                "jakarta/servlet/Filter.java": (
                    "package jakarta.servlet; public interface Filter { void doFilter(); }"
                ),
                "org/springframework/security/web/SecurityFilterChain.java": (
                    "package org.springframework.security.web; public interface SecurityFilterChain {}"
                ),
                "org/springframework/security/config/annotation/web/builders/HttpSecurity.java": (
                    "package org.springframework.security.config.annotation.web.builders; "
                    "public class HttpSecurity { public HttpSecurity addFilter(jakarta.servlet.Filter filter) { return this; } "
                    "public org.springframework.security.web.SecurityFilterChain build() { return null; } }"
                ),
                "lib/Api.java": (
                    f"package lib; public class Api {{ public int changed() {{ return {value}; }} }}"
                ),
                "lib/LibFilter.java": (
                    "package lib; public class LibFilter implements jakarta.servlet.Filter { "
                    f"public void doFilter() {{ System.out.print({value}); }} }}"
                ),
            })

        base_framework = framework("aop-security-base", 1)
        current_framework = framework("aop-security-current", 2)
        business = self._compile_sources_jar("aop-security-business", {
            "biz/Service.java": "package biz; public class Service { public int work() { return 1; } }",
            "biz/ObservedService.java": (
                "package biz; "
                "@io.micrometer.observation.annotation.Observed "
                "public class ObservedService { public void observed() {} "
                "@io.micrometer.observation.annotation.Observed "
                "public void suppressed() {} }"
            ),
            "biz/TracingAspect.java": (
                "package biz; @org.aspectj.lang.annotation.Aspect public class TracingAspect { "
                "@org.aspectj.lang.annotation.Around(\"execution(* biz.Service.work(..))\") "
                "public int around() { return new lib.Api().changed(); } }"
            ),
            "biz/SecurityConfig.java": (
                "package biz; public class SecurityConfig { @org.springframework.context.annotation.Bean "
                "public org.springframework.security.web.SecurityFilterChain chain("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http) { "
                "return http.addFilter(new lib.LibFilter()).build(); } }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run() { return new Service().work(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "aop-security-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:framework:{version}",
                "lineage": "com.acme:framework",
                "runtime_code_source_origin_identity": "aop-security-framework",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run", "descriptor": "()I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "aop-security-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        api = next(item for item in formal if item["display_owner"] == "lib/Api")
        callback = next(
            item for item in formal if item["display_owner"] == "lib/LibFilter"
            and str(item["display_member"]).startswith("doFilter")
        )

        self.assertEqual(api["reachability_status"], "reachable")
        self.assertEqual(callback["reachability_status"], "reachable")
        kinds = {row["semantic_edge_kind"] for row in overlay["rows"]}
        self.assertIn("spring_aop_dispatch", kinds)
        self.assertIn("spring_security_filter_dispatch", kinds)
        observed_edges = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] == "spring_aop_dispatch"
            and row["target_class_name"]
            == "io/micrometer/observation/aop/ObservedAspect"
        ]
        self.assertEqual(
            {(row["caller_class_name"], row["caller_member_name"], row["path_certainty"])
             for row in observed_edges},
            {("biz/ObservedService", "observed", "possible")},
        )

    def test_declarative_client_and_dubbo_spi_dispatch_are_preserved(self):
        def framework(label, value):
            jar = self._compile_sources_jar(label, {
                "org/springframework/cloud/openfeign/FeignClient.java": (
                    "package org.springframework.cloud.openfeign; import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface FeignClient { String value(); }"
                ),
                "feign/SynchronousMethodHandler.java": (
                    "package feign; public class SynchronousMethodHandler { "
                    f"public Object invoke(Object[] args) {{ return Integer.valueOf({value}); }} }}"
                ),
                "org/apache/dubbo/common/extension/ExtensionLoader.java": (
                    "package org.apache.dubbo.common.extension; public class ExtensionLoader { "
                    "public Object getExtension(String name) { return null; } }"
                ),
                "demo/DubboService.java": (
                    "package demo; public interface DubboService { int execute(); }"
                ),
                "demo/Provider.java": (
                    f"package demo; public class Provider implements DubboService {{ "
                    f"public int execute() {{ return {value}; }} }}"
                ),
            })
            with zipfile.ZipFile(jar, "a") as archive:
                archive.writestr(
                    "META-INF/dubbo/demo.DubboService",
                    "fast=demo.Provider\n",
                )
            return jar

        base_framework = framework("dispatch-base", 1)
        current_framework = framework("dispatch-current", 2)
        business = self._compile_sources_jar("dispatch-business", {
            "biz/RemoteClient.java": (
                "package biz; @org.springframework.cloud.openfeign.FeignClient(\"remote\") "
                "public interface RemoteClient { int call(); }"
            ),
            "biz/Entry.java": (
                "package biz; public class Entry { public int run(RemoteClient client) { "
                "org.apache.dubbo.common.extension.ExtensionLoader loader = "
                "new org.apache.dubbo.common.extension.ExtensionLoader(); "
                "demo.DubboService service = (demo.DubboService) loader.getExtension(\"fast\"); "
                "return client.call() + service.execute(); } }"
            ),
        }, classpath=(current_framework,))

        def side(framework_jar, version):
            result = self._side(framework_jar, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "dispatch-business",
            }, {
                "path": str(framework_jar), "logical_location": "lib/framework.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:dispatch:{version}",
                "lineage": "com.acme:dispatch",
                "runtime_code_source_origin_identity": "dispatch-framework",
            }]
            result["runtime_profile"]["container_and_launcher_kind"] = "spring-boot-executable-jar"
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Entry", "member_name": "run",
                    "descriptor": "(Lbiz/RemoteClient;)I",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_framework, "1"), "current": side(current_framework, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(config, output_root=self.root / "dispatch-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(encoding="utf-8")
        )
        feign = next(
            item for item in formal if item["display_owner"] == "feign/SynchronousMethodHandler"
        )
        provider = next(
            item for item in formal if item["display_owner"] == "demo/Provider"
            and str(item["display_member"]).startswith("execute")
        )

        self.assertEqual(feign["reachability_status"], "reachable")
        self.assertEqual(provider["reachability_status"], "reachable")
        kinds = {row["semantic_edge_kind"] for row in overlay["rows"]}
        self.assertIn("declarative_http_client_dispatch", kinds)
        self.assertIn("dubbo_spi_dispatch", kinds)

    def test_web_binding_keeps_removed_dependency_field_reachable_as_data_contract(self):
        base_dto = self._compile_sources_jar("dto-base", {
            "lib/Dto.java": (
                "package lib; public class Dto { "
                "public String removed; public String retained; }"
            ),
        })
        current_dto = self._compile_sources_jar("dto-current", {
            "lib/Dto.java": (
                "package lib; public class Dto { public String retained; }"
            ),
        })
        business = self._compile_sources_jar("dto-business", {
            "org/springframework/web/bind/annotation/GetMapping.java": (
                "package org.springframework.web.bind.annotation; "
                "import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) "
                "@Target(ElementType.METHOD) public @interface GetMapping {}"
            ),
            "biz/Controller.java": (
                "package biz; public class Controller { "
                "@org.springframework.web.bind.annotation.GetMapping "
                "public lib.Dto endpoint(lib.Dto request) { return request; } }"
            ),
        }, classpath=(current_dto,))

        def side(dto, version):
            result = self._side(dto, version)
            result["artifacts"] = [{
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "dto-business",
            }, {
                "path": str(dto), "logical_location": "lib/dto.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"com.acme:dto:{version}",
                "lineage": "com.acme:dto",
                "runtime_code_source_origin_identity": "dto-dependency",
            }]
            result["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Controller", "member_name": "endpoint",
                    "descriptor": "(Llib/Dto;)Llib/Dto;",
                }],
            }
            return result

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_dto, "1"), "current": side(current_dto, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "data-contract-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        removed = next(
            item for item in formal
            if item["display_owner"] == "lib/Dto"
            and str(item["display_member"]).startswith("removed")
        )
        overlay = json.loads(
            (generation / "binary_runtime_semantic_overlay.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(removed["reachability_status"], "reachable")
        self.assertTrue(any(
            row["semantic_edge_kind"] == "implicit_data_contract_dispatch"
            and row["target_class_name"] == "lib/Dto"
            and row["target_member_name"] == "removed"
            and row["path_certainty"] == "exact"
            for row in overlay["rows"]
        ))

    def test_step1_runtime_materialization_runs_without_handwritten_binary_config(self):
        base_core, current_core, scheduler, app = (
            self._automatic_scheduled_entry_fixture()
        )
        report = self.root / "auto-materialized-report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)

        def digest(path):
            return hashlib.sha256(Path(path).read_bytes()).hexdigest()

        manifest = {
            "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
            "items": [],
            "business_artifacts": [],
            "runtime_closure": {},
        }
        provenance = {"sides": []}
        for side, core, version in (
            ("base", base_core, "1.0"),
            ("current", current_core, "2.0"),
        ):
            manifest["business_artifacts"].append({
                "side": side,
                "retained_path": str(app),
                "sha256": digest(app),
                "outer_artifact_path": str(app),
                "outer_artifact_sha256": digest(app),
                "container_and_launcher_kind": "spring-boot-executable-jar",
            })
            for index, (jar, coord, dependency_version) in enumerate((
                (scheduler, "com.acme:scheduler", "1.0"),
                (core, "com.acme:core", version),
            )):
                manifest["items"].append({
                    "side": side,
                    "coord": coord,
                    "version": dependency_version,
                    "lib_entry": f"BOOT-INF/lib/{Path(jar).name}",
                    "retained_path": str(jar),
                    "nested_jar_sha256": digest(jar),
                    "outer_artifact_sha256": digest(app),
                    "runtime_classpath_index": index,
                    "purposes": ["binary_runtime"],
                })
            manifest["runtime_closure"][side] = {
                "coverage_status": "complete",
                "coverage_gaps": [],
            }
            provenance["sides"].append({
                "side": side,
                "target_module": "app",
                "jdk_home": str(self.home),
                "artifact_sha256": digest(app),
            })
        (dependencies / "dependency_jars.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (dependencies / "build_provenance.json").write_text(
            json.dumps(provenance), encoding="utf-8"
        )

        config = materialize_binary_pipeline_config(report)
        config["asm_jar"] = str(self.asm_jar)
        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        formal = json.loads(
            (Path(result["generation_directory"]) / "binary_formal_results.json")
            .read_text(encoding="utf-8")
        )
        target = next(
            item for item in formal["by_api"]
            if item["display_owner"] == "api/Api"
            and str(item["display_member"]).startswith("value")
        )

        self.assertEqual(target["reachability_status"], "reachable")
        self.assertEqual(
            target["paths"][0]["entrypoint_dependency_coords"],
            ["com.acme:scheduler:1.0"],
        )

    def test_end_to_end_generation_is_content_bound_and_immutable(self):
        base = self._jar("base", 1, service_provider="demo.OldProvider")
        current = self._jar("current", 2, service_provider="demo.NewProvider")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        report = self.root / "report"
        output = report / ".runtime" / "binary_authority"
        first = run_pipeline(config, output_root=output)
        second = run_pipeline(config, output_root=output)

        self.assertEqual(
            first["result_generation_identity"], second["result_generation_identity"]
        )
        self.assertGreater(first["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["artifact_snapshot_misses"], 0)
        self.assertEqual(first["authoritative_change_fact_count"], 2)
        self.assertGreater(first["total_elapsed_seconds"], 0)
        self.assertTrue(first["phase_timings"])
        self.assertTrue(all(
            item["elapsed_seconds"] >= 0 for item in first["phase_timings"]
        ))
        timings = json.loads(Path(first["phase_timings_path"]).read_text())
        self.assertTrue(timings["non_authoritative_observability"])
        self.assertGreater(timings["peak_rss_bytes"], 0)
        self.assertEqual(timings["peak_rss_scope"], "current_process")
        self.assertEqual(second["peak_rss_bytes"], timings["peak_rss_bytes"])
        self.assertEqual(
            timings["result_generation_identity"],
            first["result_generation_identity"],
        )
        progress = json.loads(
            (
                output / "binary_observability" / "latest_in_progress.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(
            progress["last_completed_phase"], "validated_generation_activation"
        )
        generation = Path(first["generation_directory"])
        summary = json.loads((generation / "binary_summary.json").read_text())
        self.assertEqual(summary["formal_projection_count"], 1)
        self.assertEqual(summary["reachable_total"], 1)
        self.assertTrue((generation / "base_binary_facts.sqlite").is_file())
        active = json.loads((output / "active_binary_generation.json").read_text())
        self.assertEqual(
            active["result_generation_identity"], first["result_generation_identity"]
        )
        api_dir = report / "evidence" / "api_changes"
        call_dir = report / "evidence" / "call_chain"
        findings = report / ".runtime" / "findings" / "s6_findings.json"
        final_report = report / "deliverables" / "report.md"
        step4_result = publish_step4(report, api_dir)
        publish_step5(report, call_dir)
        publish_step6(report, findings, final_report)
        self.assertFalse((api_dir / "binary_decisions.json").exists())
        self.assertEqual(step4_result["change_fact_count"], 1)
        step4_summary = json.loads(
            (api_dir / "summary.json").read_text()
        )
        self.assertEqual(
            step4_summary["source_inputs"]["business"]["status"], "not_provided"
        )
        self.assertEqual(step4_summary["authoritative_change_fact_count"], 2)
        self.assertEqual(step4_summary["published_api_change_count"], 1)
        self.assertEqual(step4_summary["confirmed_unprojectable_fact_count"], 1)
        self.assertIn(
            "业务源码：未提供；依赖源码：未提供",
            (report / "evidence" / "source_analysis" / "review.md").read_text(
                encoding="utf-8"
            ),
        )
        with (report / "evidence" / "source_analysis" / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(list(csv.DictReader(handle)), [])
        self.assertTrue(
            (api_dir / "all_changed_apis.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        api_csv = (api_dir / "all_changed_apis.csv").read_text()
        self.assertNotIn("META-INF/services/demo.Service", api_csv)
        with (api_dir / "all_changed_apis.csv").open(encoding="utf-8-sig", newline="") as handle:
            api_rows = list(csv.DictReader(handle))
        self.assertEqual(api_rows[0]["coord"], "com.acme:api")
        self.assertEqual(api_rows[0]["old_version"], "1")
        self.assertEqual(api_rows[0]["new_version"], "2")
        self.assertEqual(api_rows[0]["api_signature"], "()")
        dependency_review = (api_dir / "changed_dependencies.md").read_text()
        self.assertIn("com.acme:api", dependency_review)
        self.assertIn("[review.md](review.md)", dependency_review)
        per_dependency_review = next((api_dir / "s4_per_dependency").glob("*/summary.md"))
        self.assertIn(
            "[查看完整裁决](../../review.md)",
            per_dependency_review.read_text(),
        )
        complete_review = (api_dir / "review.md").read_text()
        self.assertIn("业务源码：未提供；依赖源码：未提供", complete_review)
        self.assertIn("## com.acme:api\n", complete_review)
        self.assertNotIn("## com.acme:api:1、com.acme:api:2", complete_review)
        self.assertIn("META-INF/services/demo.Service", complete_review)
        self.assertFalse(any(api_dir.glob("*.sqlite")))
        published_summary = json.loads((call_dir / "summary.json").read_text())
        self.assertEqual(
            published_summary["schema"],
            "java-upgrade-analyzer.binary-step5-summary.v1",
        )
        step5_review = (call_dir / "summary.md").read_text(encoding="utf-8")
        self.assertIn("# 系统触达证据", step5_review)
        self.assertIn("com.acme:api", step5_review)
        self.assertIn("不是已确认无影响", step5_review)
        self.assertEqual(published_summary["reachable"], 1)
        self.assertNotIn("confirmed_impact", published_summary["quality_gate"])
        self.assertNotIn("confirmed_no_impact", published_summary["quality_gate"])
        # The established Step5 report contract retains the explicit
        # not-impacted bucket even though binary-first never fabricates a
        # confirmed-no-impact result.  The bucket must therefore remain empty.
        self.assertEqual(published_summary["not_impacted"], 0)
        self.assertEqual(published_summary["not_impacted_apis"], [])
        self.assertTrue(
            (call_dir / "alerts.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        with (call_dir / "alerts.csv").open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            alert_rows = list(reader)
            self.assertEqual(tuple(reader.fieldnames or ()), LEGACY_ALERT_FIELDS)
        self.assertEqual(alert_rows[0]["target_coord"], "com.acme:api")
        self.assertEqual(alert_rows[0]["api_signature"], "()")
        self.assertTrue(alert_rows[0]["path_text"].endswith("demo.Api.value()"))
        query = query_scope_call_chain_result(report, "com.acme:api", "coord")
        self.assertEqual(query["matched_coords"], ["com.acme:api"])
        self.assertTrue(query["chains"], query)
        self.assertTrue(
            (generation / "binary_formal_results.csv").read_bytes().startswith(
                b"\xef\xbb\xbf"
            )
        )
        self.assertIn("业务源码：未提供；依赖源码：未提供", final_report.read_text())
        rendered_report = final_report.read_text()
        self.assertIn("# Java 依赖升级影响报告", rendered_report)
        self.assertIn("## 一、依赖层面结论", rendered_report)
        self.assertIn("## 二、API 及调用关系", rendered_report)
        self.assertIn("## 三、用户可见文件说明", rendered_report)
        self.assertIn("确认有影响", rendered_report)
        self.assertIn("不表示运行时故障已经发生", rendered_report)
        self.assertNotIn("五态语义", rendered_report)
        for internal_status in (
            "reachable",
            "uncertain",
            "not_found_in_static_analysis",
            "not_analyzed",
        ):
            self.assertNotIn(internal_status, rendered_report)
        self.assertNotIn("未确认影响（存在候选关系）", rendered_report)
        self.assertNotIn("Analysis context：", rendered_report)
        self.assertFalse((api_dir / "source_overlay.md").exists())
        self.assertTrue(
            (report / "evidence" / "source_analysis" / "review.md").is_file()
        )
        self.assertTrue((final_report.parent / "all-affected-dependencies.md").is_file())
        self.assertTrue((final_report.parent / "all-affected-dependencies.csv").is_file())
        self.assertTrue((final_report.parent / "all-impact-details.md").is_file())
        self.assertTrue((final_report.parent / "all-impact-details.csv").is_file())
        self.assertTrue((final_report.parent / "analysis-scope.md").is_file())
        with (final_report.parent / "all-affected-dependencies.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(
                csv.DictReader(handle).fieldnames,
                ["依赖", "版本变化", "API 分析（已完成/总数）", "当前系统调用关系", "分析结果", "结果说明"],
            )
        with (final_report.parent / "all-impact-details.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            self.assertEqual(
                csv.DictReader(handle).fieldnames,
                ["依赖", "API", "新版本中的变化", "当前系统调用关系", "分析结果", "结果说明"],
            )
        scope_report = (final_report.parent / "analysis-scope.md").read_text()
        self.assertIn("## 源码辅助分析", scope_report)
        self.assertIn("业务源码：未提供；依赖源码：未提供", scope_report)
        impact_detail = (final_report.parent / "all-impact-details.md").read_text()
        self.assertIn("当前系统调用关系", impact_detail)
        self.assertIn("demo.Api.value()", impact_detail)
        self.assertEqual(
            load_validated_generation(report)["manifest"]["result_generation_identity"],
            first["result_generation_identity"],
        )
        validation = validate_generation(config, generation)
        self.assertEqual(validation["status"], "passed", validation["issues"])
        self.assertNotEqual(
            validation["validation_run_identity"], first["analysis_context_identity"]
        )
        formal_path = generation / "binary_formal_results.json"
        manifest_path = generation / "result_generation.json"
        original_formal = formal_path.read_bytes()
        original_manifest = manifest_path.read_bytes()
        manipulated = json.loads(original_formal)
        manipulated["by_api"][0]["reachability_status"] = (
            "not_found_in_static_analysis"
        )
        manipulated["by_api"][0]["impact_conclusion"] = "inconclusive"
        formal_path.write_text(
            json.dumps(
                manipulated, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ) + "\n",
            encoding="utf-8",
        )
        manifest = json.loads(original_manifest)
        manifest["sidecar_content_identities"][formal_path.name] = hashlib.sha256(
            formal_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        conclusion_tampered = validate_generation(config, generation)
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_API_AGGREGATION_MISMATCH"
            for item in conclusion_tampered["issues"]
        ), conclusion_tampered["issues"])
        formal_path.write_bytes(original_formal)
        manifest_path.write_bytes(original_manifest)
        summary_path = generation / "binary_summary.json"
        summary_path.write_text("{}\n", encoding="utf-8")
        tampered = validate_generation(config, generation)
        self.assertEqual(tampered["status"], "failed")
        self.assertTrue(any(
            item["reason_code"] == "ORACLE_GENERATION_SIDECAR_TAMPERED"
            for item in tampered["issues"]
        ))
        with self.assertRaises(BinaryReportError):
            load_validated_generation(report)

    def test_inherited_resolution_and_service_activation_are_human_visible(self):
        def compile_dependency(side, parent, provider, value):
            source_root = self.root / side / "dependency-src"
            sources = {
                "demo/hierarchy/ParentA.java": (
                    "package demo.hierarchy; public class ParentA { "
                    "public int value(){ return 1; } }"
                ),
                "demo/hierarchy/ParentB.java": (
                    "package demo.hierarchy; public class ParentB { "
                    f"public int value(){{ return {value}; }} }}"
                ),
                "demo/hierarchy/Child.java": (
                    "package demo.hierarchy; public class Child extends "
                    f"{parent} {{ public int call() {{ return value(); }} }}"
                ),
                "demo/spi/Service.java": (
                    "package demo.spi; public interface Service { String run(); }"
                ),
                f"demo/spi/{provider}.java": (
                    "package demo.spi; public class "
                    f"{provider} implements Service {{ public String run(){{ "
                    f"return \"{provider}\"; }} }}"
                ),
            }
            source_paths = []
            for relative, content in sources.items():
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                source_paths.append(path)
            classes = self.root / side / "dependency-classes"
            classes.mkdir(parents=True)
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), *map(str, source_paths)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / side / "dependency.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                for path in sorted(classes.rglob("*.class")):
                    archive.write(path, path.relative_to(classes).as_posix())
                archive.writestr(
                    "META-INF/services/demo.spi.Service",
                    f"demo.spi.{provider}\n",
                )
            return jar

        base_dependency = compile_dependency("semantic-base", "ParentA", "OldProvider", 2)
        current_dependency = compile_dependency("semantic-current", "ParentB", "NewProvider", 2)
        business_source = self.root / "semantic-business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; import java.util.ServiceLoader; "
            "public class Main { public String entry(){ return "
            "new demo.hierarchy.Child().call() + \":\" + "
            "ServiceLoader.load(demo.spi.Service.class).findFirst()"
            ".orElseThrow().run(); } }",
            encoding="utf-8",
        )
        business_classes = self.root / "semantic-business-classes"
        business_classes.mkdir()
        completed = subprocess.run(
            [
                "javac", "-g", "-cp", str(base_dependency),
                "-d", str(business_classes), str(business_source),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        business_jar = self.root / "semantic-business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")

        def side(dependency, version):
            return {
                "jdk_home": str(self.home),
                "artifacts": [{
                    "path": str(business_jar),
                    "logical_location": "app/business.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "business_classes",
                    "slot": 0,
                    "coord": "com.acme:application:1",
                    "lineage": "com.acme:application",
                    "runtime_code_source_origin_identity": "semantic:application",
                }, {
                    "path": str(dependency),
                    "logical_location": "lib/semantic.jar",
                    "loader_realm": "application-loader",
                    "path_kind": "classpath",
                    "slot": 1,
                    "coord": f"com.acme:semantic:{version}",
                    "lineage": "com.acme:semantic",
                    "runtime_code_source_origin_identity": (
                        f"semantic:dependency:{version}"
                    ),
                }],
                "runtime_profile": {
                    "container_and_launcher_kind": "java-classpath",
                    "loader_topology": {
                        "coverage_status": "complete",
                        "entrypoint_realms": ["application-loader"],
                        "realms": [{
                            "identity": "platform-loader", "kind": "platform",
                            "delegation": "parent_first", "module_mode": "named-platform",
                        }, {
                            "identity": "application-loader", "kind": "application",
                            "parent": "platform-loader", "delegation": "parent_first",
                            "module_mode": "unnamed",
                        }],
                    },
                    "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
                    "active_profile_identities": ["default"],
                    "external_config_snapshot_identities": [],
                    "agent_transformer_plugin_profile_identities": [],
                    "business_entrypoint_profile": {
                        "coverage_status": "complete",
                        "methods": [{
                            "initiating_loader_realm_identity": "application-loader",
                            "class_name": "biz/Main", "member_name": "entry",
                            "descriptor": "()Ljava/lang/String;",
                        }],
                    },
                    "runtime_class_closure_coverage_status": "complete",
                    "resource_selection_coverage_status": "complete",
                },
            }

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_dependency, "1"),
            "current": side(current_dependency, "2"),
            "runtime_comparison": {
                "comparison_intent": "release_snapshot",
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
                "changed_or_unknown_profile_fields": [
                    "runtime_code_source_origin_mapping_identity"
                ],
            },
        }
        report = self.root / "semantic-report"
        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        generation = Path(result["generation_directory"])
        decisions = json.loads((generation / "binary_decisions.json").read_text())
        resolution = [
            item for item in decisions["authoritative_change_facts"]
            if item.get("reason_code") == "RUNTIME_MEMBER_RESOLUTION_CHANGED"
        ]
        self.assertEqual(len(resolution), 1)
        self.assertEqual(
            resolution[0]["evidence"]["base_resolution"]["resolved_owner"],
            "demo/hierarchy/ParentA",
        )
        self.assertEqual(
            resolution[0]["evidence"]["current_resolution"]["resolved_owner"],
            "demo/hierarchy/ParentB",
        )
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        resolution_result = next(
            item for item in formal["results"]
            if item.get("change_fact_identity") == resolution[0]["change_fact_identity"]
        )
        self.assertEqual(resolution_result["reachability_status"], "reachable")
        resource_result = formal["resource_activation_results"]
        self.assertEqual(len(resource_result), 1)
        self.assertEqual(resource_result[0]["activation_status"], "reachable")

        publish_step4(report, report / "evidence" / "api_changes")
        publish_step5(report, report / "evidence" / "call_chain")
        publish_step6(
            report,
            report / ".runtime" / "findings" / "s6_findings.json",
            report / "deliverables" / "report.md",
        )
        with (report / "evidence" / "api_changes" / "all_changed_apis.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            rows = list(csv.DictReader(handle))
        resolution_row = next(
            item for item in rows
            if item["change_type"] == "MEMBER_RESOLUTION_CHANGED"
        )
        self.assertEqual(resolution_row["old_value"], "demo/hierarchy/ParentA")
        self.assertEqual(resolution_row["new_value"], "demo/hierarchy/ParentB")
        report_text = (report / "deliverables" / "report.md").read_text()
        self.assertIn("demo.hierarchy.ParentA → demo.hierarchy.ParentB", report_text)
        self.assertIn("META-INF/services/demo.spi.Service", report_text)
        self.assertIn("已确认当前系统激活", report_text)
        dependencies_text = (
            report / "deliverables" / "all-affected-dependencies.md"
        ).read_text()
        semantic_row = next(
            line for line in dependencies_text.splitlines()
            if "`com.acme:semantic`" in line
        )
        self.assertIn("确认有影响", semantic_row)
        self.assertIn("运行时资源", semantic_row)

    def test_manifest_semantics_match_independent_validation(self):
        manifest = (
            "Manifest-Version: 1.0\r\n"
            "Created-By: comparison fixture\r\n"
            "Long-Value: first-\r\n"
            " continuation\r\n"
            "\r\n"
        )
        base = self._jar("base", 1, manifest=manifest, uses_system_out=True)
        current = self._jar("current", 2, manifest=manifest, uses_system_out=True)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base),
            "current": self._side(current),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config,
            output_root=self.root / "report" / ".runtime" / "binary_authority",
        )

        self.assertEqual(result["validation_status"], "passed")

    def test_one_sided_platform_reference_is_not_a_provider_change(self):
        def signature_jar(side, parameter_type):
            source = self.root / side / "src" / "demo" / "Api.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class Api { "
                "public int value(){ return 1; } "
                f"public int signature({parameter_type} value){{ return value.length(); }} "
                "}",
                encoding="utf-8",
            )
            classes = self.root / side / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            jar = self.root / side / "api.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.write(classes / "demo" / "Api.class", "demo/Api.class")
            return jar

        base = signature_jar("platform-ref-base", "String")
        current = signature_jar("platform-ref-current", "CharSequence")
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }

        result = run_pipeline(
            config,
            output_root=self.root / "platform-reference-output",
        )
        decisions = json.loads(
            (Path(result["generation_directory"]) / "binary_decisions.json").read_text()
        )
        all_decisions = [
            *decisions["authoritative_change_facts"],
            *decisions["diagnostic_candidate_facts"],
        ]

        self.assertFalse(any(
            item.get("fact_kind") == "provider_topology"
            and (item.get("fact_scope") or {}).get("class_name")
            == "java/lang/CharSequence"
            for item in all_decisions
        ))

    def test_dependency_source_set_is_published_with_dependency_dimension(self):
        base = self._jar("source-base", 1)
        current = self._jar("source-current", 2, uses_system_out=True)
        current_source = self.root / "source-current" / "src"
        kotlin_source = current_source / "demo" / "KotlinConsumer.kt"
        kotlin_source.write_text(
            "package demo\nclass KotlinConsumer { fun value() = Api().value() }\n",
            encoding="utf-8",
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._side(base, "1"),
            "current": self._side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "dependency",
                    "owner_coord": "com.acme:api:2",
                    "module": "api",
                }],
            },
        }
        report = self.root / "dependency-source-report"

        result = run_pipeline(
            config,
            output_root=report / ".runtime" / "binary_authority",
        )
        self.assertEqual(
            result["source_inputs"]["dependencies"]["status"], "available"
        )
        attestation = json.loads(
            (
                Path(result["generation_directory"])
                / "binary_source_attestation.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(attestation["coverage_status"], "partial")
        self.assertEqual(attestation["source_sets"][0]["owner_type"], "dependency")
        self.assertEqual(attestation["source_sets"][0]["owner_coord"], "com.acme:api:2")
        self.assertEqual(attestation["file_count"], 2)
        self.assertEqual(
            attestation["language_file_counts"], {"java": 1, "kotlin": 1}
        )
        self.assertEqual(
            attestation["coverage_gaps"][0]["reason_code"],
            "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
        )
        self.assertGreaterEqual(attestation["mapped_binary_member_count"], 1)
        self.assertEqual(len(attestation["files"][0]["sha256"]), 64)
        api_dir = report / "evidence" / "api_changes"
        publish_step4(report, api_dir)
        source_dir = report / "evidence" / "source_analysis"
        with (source_dir / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            rows = list(csv.DictReader(handle))

        mapped = next(row for row in rows if row["二进制方法"] == "demo.Api.value()")
        self.assertEqual(mapped["源码归属"], "com.acme:api:2")
        self.assertEqual(mapped["二进制制品"], "com.acme:api:2")
        self.assertEqual(mapped["源码位置"], "demo/Api.java:1")
        self.assertTrue(mapped["源码声明"])
        source_review = (source_dir / "review.md").read_text(encoding="utf-8")
        self.assertIn("kotlin 1 个", source_review)
        self.assertIn("coverage_gaps.csv", source_review)
        with (source_dir / "coverage_gaps.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            gap_rows = list(csv.DictReader(handle))
        self.assertEqual(gap_rows[0]["源码文件"], "demo/KotlinConsumer.kt")
        self.assertTrue((source_dir / "source_snapshot.json").is_file())
        with (source_dir / "candidate_relationships.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            candidate_rows = list(csv.DictReader(handle))
        self.assertTrue(candidate_rows)
        self.assertTrue(all(
            row["源码归属"] == "com.acme:api:2"
            and row["权威边界"] == "源码候选关系，不是可执行调用边"
            for row in candidate_rows
        ))

    def _constant_side(self, side, constant):
        root = self.root / side
        vendor_source = root / "vendor-src" / "vendor" / "Constants.java"
        vendor_source.parent.mkdir(parents=True)
        vendor_source.write_text(
            f"package vendor; public class Constants {{ public static final int VALUE = {constant}; }}",
            encoding="utf-8",
        )
        vendor_classes = root / "vendor-classes"
        vendor_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(vendor_classes), str(vendor_source)],
            check=True,
            capture_output=True,
        )
        vendor_jar = root / "vendor.jar"
        with zipfile.ZipFile(vendor_jar, "w") as archive:
            archive.write(
                vendor_classes / "vendor" / "Constants.class",
                "vendor/Constants.class",
            )
        business_source = root / "business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; public class Main { public int entry(){ return vendor.Constants.VALUE; } }",
            encoding="utf-8",
        )
        business_classes = root / "business-classes"
        business_classes.mkdir()
        subprocess.run(
            [
                "javac", "-g", "-cp", str(vendor_jar), "-d", str(business_classes),
                str(business_source),
            ],
            check=True,
            capture_output=True,
        )
        business_jar = root / "business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")
        return business_source.parent.parent, business_jar, vendor_jar

    def _constant_config_side(self, source_root, business, vendor):
        side = self._side(vendor)
        side["artifacts"] = [
            {
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "business", "lineage": "business",
                "runtime_code_source_origin_identity": "deployment-business",
            },
            {
                "path": str(vendor), "logical_location": "lib/vendor.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": "vendor", "lineage": "vendor",
                "runtime_code_source_origin_identity": "deployment-vendor",
            },
        ]
        side["runtime_profile"]["business_entrypoint_profile"] = {
            "coverage_status": "complete",
            "methods": [{
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "biz/Main", "member_name": "entry", "descriptor": "()I",
            }],
        }
        return side

    def test_source_overlay_proves_javac_constant_inline_without_literal_guessing(self):
        _base_source, base_business, base_vendor = self._constant_side("inline-base", 11)
        current_source, current_business, current_vendor = self._constant_side("inline-current", 29)
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._constant_config_side(_base_source, base_business, base_vendor),
            "current": self._constant_config_side(current_source, current_business, current_vendor),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        inline_report = self.root / "inline-report"
        result = run_pipeline(
            config,
            output_root=inline_report / ".runtime" / "binary_authority",
        )
        generation = Path(result["generation_directory"])
        inline = json.loads((generation / "binary_inline_overlay.json").read_text())
        self.assertEqual(inline["proven_count"], 1, inline)
        proven = next(row for row in inline["rows"] if row["binding_certainty"] == "proven")
        self.assertTrue(proven["bytecode_constant_transition_proven"])
        formal = json.loads((generation / "binary_formal_results.json").read_text())
        field_results = [
            item for item in formal["results"]
            if item["target_nodes"] == [proven["changed_field_member_identity"]]
        ]
        self.assertEqual(len(field_results), 1)
        self.assertEqual(field_results[0]["reachability_status"], "reachable")
        source_report_dir = inline_report / "evidence" / "api_changes"
        publish_step4(inline_report, source_report_dir)
        source_analysis_dir = inline_report / "evidence" / "source_analysis"
        source_report = (source_analysis_dir / "review.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("`business`", source_report)
        self.assertIn("biz.Main.entry()", source_report)
        with (source_analysis_dir / "method_mappings.csv").open(
            encoding="utf-8-sig", newline=""
        ) as handle:
            source_rows = list(csv.DictReader(handle))
        self.assertTrue(any(row["源码归属"] == "business" for row in source_rows))

    def test_retained_base_constant_consumer_never_becomes_exact_inline_edge(self):
        base_source, base_business, base_vendor = self._constant_side("retained-base", 7)
        current_source, _rebuilt_business, current_vendor = self._constant_side(
            "retained-current", 31
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "use_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self._constant_config_side(base_source, base_business, base_vendor),
            # Deliberately retain the old consumer bytes while updating the
            # dependency and source snapshot.
            "current": self._constant_config_side(
                current_source, base_business, current_vendor
            ),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_sets": [{
                    "source_dirs": [str(current_source)],
                    "source_root": str(current_source),
                    "owner_type": "business",
                    "owner_coord": "business",
                }],
            },
        }
        result = run_pipeline(
            config,
            output_root=self.root / "retained-output",
        )
        inline = json.loads(
            (Path(result["generation_directory"]) / "binary_inline_overlay.json").read_text()
        )
        self.assertEqual(inline["proven_count"], 0)
        self.assertEqual(inline["retained_or_unchanged_count"], 1)
        row = next(
            item for item in inline["rows"]
            if item["consumption_state"] == "retained_base_or_unchanged"
        )
        self.assertEqual(row["binding_certainty"], "none")

    def _dispatch_jar(self, side, value):
        source_root = self.root / side / "src"
        sources = {
            "demo/Api.java": "package demo; public interface Api { int value(); }",
            "demo/Impl.java": (
                f"package demo; public class Impl implements Api {{ public int value(){{ return {value}; }} }}"
            ),
            "demo/Main.java": (
                "package demo; public class Main { "
                "public int entry(){ Api api = new Impl(); return api.value(); } "
                "public java.util.function.IntSupplier supplier(Api api){ return api::value; } "
                "}"
            ),
        }
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / side / "classes"
        classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(classes), *map(str, paths)],
            check=True,
            capture_output=True,
        )
        jar = self.root / side / "app.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        return jar

    def test_independent_oracle_validates_interface_dispatch_targets(self):
        base = self._dispatch_jar("dispatch-base", 1)
        current = self._dispatch_jar("dispatch-current", 2)
        base_side = self._side(base)
        current_side = self._side(current)
        for side in (base_side, current_side):
            side["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "demo/Main", "member_name": "entry", "descriptor": "()I",
                }],
            }
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source",
                "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": base_side,
            "current": current_side,
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(
            config,
            output_root=self.root / "dispatch-output",
        )
        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)


if __name__ == "__main__":
    unittest.main()
