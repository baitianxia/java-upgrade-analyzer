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
from binary_pipeline import run_pipeline  # noqa: E402
from binary_compat_output import (  # noqa: E402
    BinaryCompatibilityOutputError,
    load_validated_generation,
    materialize_step4,
    materialize_step5,
    materialize_step6,
    write_engine_descriptor,
)
from binary_validation_oracle import validate_generation  # noqa: E402


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

    def _side(self, jar):
        return {
            "jdk_home": str(self.home),
            "artifacts": [{
                "path": str(jar),
                "logical_location": "lib/api.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 0,
                "coord": "com.acme:api:1",
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
            "asm_jar": str(self.asm_jar),
            "base": self._side(base),
            "current": self._side(current),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        report = self.root / "report"
        output = report / ".runtime" / "binary_authority"
        first = run_pipeline(config, output_root=output, engine_mode="binary_strict")
        second = run_pipeline(config, output_root=output, engine_mode="binary_strict")

        self.assertEqual(
            first["result_generation_identity"], second["result_generation_identity"]
        )
        self.assertGreater(first["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["classfile_parser_invocations"], 0)
        self.assertEqual(second["cache_metrics"]["artifact_snapshot_misses"], 0)
        self.assertEqual(first["authoritative_change_fact_count"], 2)
        generation = Path(first["generation_directory"])
        summary = json.loads((generation / "binary_summary.json").read_text())
        self.assertEqual(summary["formal_projection_count"], 1)
        self.assertEqual(summary["reachable_total"], 1)
        self.assertTrue((generation / "base_binary_facts.sqlite").is_file())
        active = json.loads((output / "active_binary_generation.json").read_text())
        self.assertEqual(
            active["result_generation_identity"], first["result_generation_identity"]
        )
        write_engine_descriptor(report, {
            "requested_engine_mode": "binary_strict",
            "authoritative_engine": "binary",
            "result_generation_identity": first["result_generation_identity"],
            "analysis_context_identity": first["analysis_context_identity"],
            "validation_run_identity": first["validation_run_identity"],
        })
        api_dir = report / "evidence" / "api_changes"
        call_dir = report / "evidence" / "call_chain"
        findings = report / ".runtime" / "findings" / "s6_findings.json"
        final_report = report / "deliverables" / "report.md"
        step4_result = materialize_step4(report, api_dir)
        materialize_step5(report, call_dir)
        materialize_step6(report, findings, final_report)
        self.assertTrue((api_dir / "binary_decisions.json").is_file())
        self.assertEqual(step4_result["row_count"], 1)
        step4_summary = json.loads(
            (api_dir / "binary_step4_summary.json").read_text()
        )
        self.assertEqual(step4_summary["authoritative_change_fact_count"], 2)
        self.assertEqual(step4_summary["targetable_api_change_count"], 1)
        self.assertEqual(step4_summary["confirmed_unprojectable_fact_count"], 1)
        self.assertTrue(
            (api_dir / "all_changed_apis.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        api_csv = (api_dir / "all_changed_apis.csv").read_text()
        self.assertNotIn("META-INF/services/demo.Service", api_csv)
        compatibility_summary = json.loads((call_dir / "summary.json").read_text())
        self.assertEqual(compatibility_summary["reachable"], 1)
        self.assertEqual(compatibility_summary["quality_gate"]["confirmed_impact"], 0)
        self.assertEqual(compatibility_summary["quality_gate"]["confirmed_no_impact"], 0)
        self.assertTrue(
            (call_dir / "alerts.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        )
        self.assertTrue(
            (generation / "binary_formal_results.csv").read_bytes().startswith(
                b"\xef\xbb\xbf"
            )
        )
        self.assertIn("not_found_in_static_analysis", final_report.read_text())
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
        with self.assertRaises(BinaryCompatibilityOutputError):
            load_validated_generation(report)

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
            engine_mode="binary_strict",
        )

        self.assertEqual(result["validation_status"], "passed")

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
            "asm_jar": str(self.asm_jar),
            "base": self._constant_config_side(_base_source, base_business, base_vendor),
            "current": self._constant_config_side(current_source, current_business, current_vendor),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
            "source_overlay": {
                "source_dirs": [str(current_source)],
                "source_root": str(current_source),
                "owner_type": "business",
                "owner_coord": "business",
            },
        }
        result = run_pipeline(
            config, output_root=self.root / "inline-output", engine_mode="binary_strict"
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

    def test_retained_base_constant_consumer_never_becomes_exact_inline_edge(self):
        base_source, base_business, base_vendor = self._constant_side("retained-base", 7)
        current_source, _rebuilt_business, current_vendor = self._constant_side(
            "retained-current", 31
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
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
                "source_dirs": [str(current_source)],
                "source_root": str(current_source),
                "owner_type": "business",
                "owner_coord": "business",
            },
        }
        result = run_pipeline(
            config,
            output_root=self.root / "retained-output",
            engine_mode="binary_strict",
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
            engine_mode="binary_strict",
        )
        self.assertEqual(result["validation_status"], "passed")
        validation = json.loads(Path(result["validation_result_path"]).read_text())
        self.assertEqual(validation["issue_count"], 0)


if __name__ == "__main__":
    unittest.main()
