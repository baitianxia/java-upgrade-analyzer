import csv
import json
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
from binary_pipeline import BinaryPipelineError, run_pipeline  # noqa: E402
from binary_report import (  # noqa: E402
    BinaryReportError,
    LEGACY_ALERT_FIELDS,
    load_validated_generation,
    publish_step4,
    publish_step5,
    publish_step6,
)
from binary_validation_oracle import validate_generation  # noqa: E402
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

    def test_source_usage_requires_an_explicit_user_decision(self):
        with self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {"schema": "java-upgrade-analyzer.binary-pipeline-input.v1"},
                output_root=self.root / "missing-source-decision",
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_SOURCE_USAGE_DECISION_REQUIRED",
        )

    def test_skip_source_rejects_an_implicit_overlay(self):
        with self.assertRaises(BinaryPipelineError) as raised:
            run_pipeline(
                {
                    "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                    "source_usage": {
                        "decision": "skip_source",
                        "decision_source": "explicit_config",
                    },
                    "source_overlay": {
                        "source_sets": [{
                            "source_dirs": ["/not/read"],
                            "owner_type": "business",
                            "owner_coord": "business",
                        }],
                    },
                },
                output_root=self.root / "unconsented-source",
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_SOURCE_OVERLAY_NOT_CONSENTED",
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
            step4_summary["source_usage"]["decision"], "skip_source"
        )
        self.assertEqual(step4_summary["authoritative_change_fact_count"], 2)
        self.assertEqual(step4_summary["published_api_change_count"], 1)
        self.assertEqual(step4_summary["confirmed_unprojectable_fact_count"], 1)
        self.assertIn(
            "用户明确选择不提供源码",
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
        self.assertIn("用户选择不提供源码", complete_review)
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
        self.assertIn("用户选择不提供源码", final_report.read_text())
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
        self.assertIn("用户选择不提供源码", scope_report)
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
                    f"{parent} {{ }}"
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
            "new demo.hierarchy.Child().value() + \":\" + "
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
                    "runtime_code_source_origin_identity": "semantic:dependency",
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
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
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
        self.assertEqual(result["source_usage"]["decision"], "use_source")
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
