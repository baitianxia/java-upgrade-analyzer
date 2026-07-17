import csv
import hashlib
import io
import json
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import real_project_regression as realreg  # noqa: E402


def minimal_classfile_with_utf8(*values):
    entries = []
    for value in values:
        encoded = value.encode("utf-8")
        entries.append(b"\x01" + struct.pack(">H", len(encoded)) + encoded)
    return (
        b"\xca\xfe\xba\xbe"
        + struct.pack(">HHH", 0, 61, len(entries) + 1)
        + b"".join(entries)
    )


def minimal_classfile_with_methodref(owner, member, descriptor):
    values = (owner, member, descriptor)
    utf8_entries = []
    for value in values:
        encoded = value.encode("utf-8")
        utf8_entries.append(b"\x01" + struct.pack(">H", len(encoded)) + encoded)
    entries = [
        utf8_entries[0],
        b"\x07" + struct.pack(">H", 1),
        utf8_entries[1],
        utf8_entries[2],
        b"\x0c" + struct.pack(">HH", 3, 4),
        b"\x0a" + struct.pack(">HH", 2, 5),
    ]
    return (
        b"\xca\xfe\xba\xbe"
        + struct.pack(">HHH", 0, 61, len(entries) + 1)
        + b"".join(entries)
    )


class RealProjectRegressionTest(unittest.TestCase):
    def test_ruoyi_discovery_case_pins_full_population_and_performance_manifest(self):
        case = realreg.CASES["ruoyi-full-artifact-discovery"]
        manifest = json.loads(case.performance_manifest.read_text(encoding="utf-8"))

        self.assertTrue(case.derive_step1_from_artifacts)
        self.assertEqual(case.required_topologies, ("field_access", "same_jar_bridge"))
        self.assertEqual(manifest["population_contract"]["step4_changed_apis"], 2185)
        self.assertEqual(manifest["oracle_contract"]["verified_apis"], 2185)
        self.assertEqual(
            manifest["performance_baseline"]["artifact_sha256"],
            manifest["current_artifact_sha256"],
        )

    def test_topology_coordinate_entries_include_split_runtime_provider_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            evidence = report / "evidence" / "api_changes"
            evidence.mkdir(parents=True)
            (evidence / "artifact_replacements.json").write_text(json.dumps({
                "items": [{
                    "base_coord": "g:core",
                    "current_coord": "g:core",
                    "current_provider_coords": ["g:core", "g:common"],
                    "evidence_type": "final_artifact_binary_provider_set",
                }],
            }), encoding="utf-8")

            result = realreg.extend_coordinate_entries_for_runtime_provider_sets(
                report,
                {
                    "g:core": ["BOOT-INF/lib/core.jar"],
                    "g:common": ["BOOT-INF/lib/common.jar"],
                },
            )

        self.assertEqual(result["g:core"], [
            "BOOT-INF/lib/core.jar", "BOOT-INF/lib/common.jar",
        ])

    def test_real_project_case_declares_required_fault_injections(self):
        case = realreg.RealProjectCase(
            name="fault-gated",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=("drop_analyzer_edge",),
        )

        self.assertEqual(case.required_fault_injections, ("drop_analyzer_edge",))

    def test_embedded_changed_api_materialization_preserves_step4_evidence_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "all_changed_apis.csv"
            case = realreg.RealProjectCase(
                name="constant", default_project=Path(tmp),
                default_changed_apis=output, baseline_specs=(),
                prefer_embedded_changed_api_rows=True,
                changed_api_rows=({
                    "coord": "g:a", "old_version": "1", "new_version": "2",
                    "change_type": "REMOVED", "api_name": "p.Flags.VALUE",
                    "api_simple": "VALUE", "symbol_kind": "field",
                    "api_signature": "", "confirmed": "true", "severity": "P1",
                    "source": "japicmp", "compatibility_flags": "CONSTANT_REMOVED",
                    "old_value": "10",
                },),
            )

            realreg.ensure_changed_apis(case, output)
            with output.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))

        self.assertEqual(row["compatibility_flags"], "CONSTANT_REMOVED")
        self.assertEqual(row["old_value"], "10")

    def test_parse_args_accepts_final_artifact_override_for_single_case(self):
        args = realreg.parse_args([
            "--case", "commons-text",
            "--final-artifact", "/tmp/commons-text.jar",
        ])

        self.assertEqual(args.final_artifact, "/tmp/commons-text.jar")

    def test_project_asset_health_records_revision_without_fake_git_error(self):
        completed = [
            subprocess.CompletedProcess([], 0, stdout="true\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            realreg.subprocess, "run", side_effect=completed
        ):
            health = realreg.collect_project_asset_health(Path(tmp))

        self.assertTrue(health["valid_git_checkout"])
        self.assertEqual(health["git_revision"], "a" * 40)
        self.assertFalse(health["git_dirty"])
        self.assertEqual(health["git_error"], "")

    def test_mybatis_sample_fixtures_pin_two_distinct_published_artifacts(self):
        fixture_dir = ROOT / "tests" / "fixtures" / "real_projects"
        annotation = json.loads(
            (fixture_dir / "mybatis-sample-annotation.json").read_text(encoding="utf-8")
        )
        xml = json.loads(
            (fixture_dir / "mybatis-sample-xml.json").read_text(encoding="utf-8")
        )

        expected_revision = "bb8bac144e4677cf1bab5a6d27ced2521972adfc"
        self.assertEqual(annotation["git_revision"], expected_revision)
        self.assertEqual(xml["git_revision"], expected_revision)
        self.assertEqual(annotation["release_version"], "4.0.1")
        self.assertEqual(xml["release_version"], "4.0.1")
        self.assertNotEqual(annotation["artifact_sha256"], xml["artifact_sha256"])
        self.assertEqual(annotation["ground_truth_status"], "reviewed")
        self.assertEqual(xml["ground_truth_status"], "reviewed")
        self.assertEqual(annotation["runtime_verification"]["exit_code"], 0)
        self.assertEqual(xml["runtime_verification"]["exit_code"], 0)
        self.assertEqual(annotation["unverified_apis"], [])
        self.assertEqual(xml["unverified_apis"], [])

    def test_every_pinned_manifest_has_an_executable_materialization_contract(self):
        fixture_dir = ROOT / "tests" / "fixtures" / "real_projects"
        manifests = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(fixture_dir.glob("*.json"))
        ]

        failures = {
            manifest["case"]: realreg.validate_reproducible_asset_contract(manifest)
            for manifest in manifests
        }

        self.assertEqual(failures, {manifest["case"]: [] for manifest in manifests})

    def test_absolute_artifact_path_without_published_origin_is_not_reproducible(self):
        manifest = {
            "repository": "example/project",
            "git_revision": "a" * 40,
            "artifact_path": "/private/tmp/app.jar",
            "artifact_sha256": "b" * 64,
            "materialization": {
                "kind": "source_build",
                "repository_url": "https://github.com/example/project.git",
                "working_directory": ".",
                "command": ["mvn", "-q", "package"],
                "artifact_path": "/private/tmp/app.jar",
            },
        }

        errors = realreg.validate_reproducible_asset_contract(manifest)

        self.assertIn("source_build_artifact_path_not_relative", errors)

    def test_pinned_asset_gate_rejects_missing_materialization_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("app/App.class", minimal_classfile_with_utf8("app/App"))
            manifest = {
                "git_revision": "a" * 40,
                "artifact_path": "app.jar",
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            completed = SimpleNamespace(returncode=0, stdout="a" * 40, stderr="")

            with patch.object(realreg.subprocess, "run", return_value=completed):
                result = realreg.validate_pinned_asset(manifest, root)

        self.assertFalse(result["passed"])
        self.assertIn("materialization_contract_missing", result["errors"])

    def test_mybatis_cases_audit_dependency_apis_not_business_mapper_contracts(self):
        expected = {
            "org.apache.ibatis.binding.MapperProxy.invoke",
            "org.apache.ibatis.binding.MapperMethod.execute",
            "org.apache.ibatis.session.SqlSession.selectOne",
        }
        for case_name in ("mybatis-sample-annotation", "mybatis-sample-xml"):
            with self.subTest(case=case_name):
                case = realreg.CASES[case_name]
                with case.default_changed_apis.open(newline="", encoding="utf-8") as handle:
                    rows = list(csv.DictReader(handle))
                self.assertEqual({row["api_name"] for row in rows}, expected)
                self.assertNotIn(
                    "sample.mybatis", " ".join(row["api_name"] for row in rows)
                )
                self.assertEqual(case.bytecode_coord, "org.mybatis:mybatis")
                self.assertIn("mybatis_mapper_proxy", case.required_topologies)
                self.assertEqual(case.case_mode, "guard")

    def test_mybatis_xml_guard_requires_false_negative_fault_injection(self):
        self.assertEqual(
            realreg.CASES["mybatis-sample-xml"].required_fault_injections,
            realreg.STANDARD_FAULT_INJECTIONS,
        )

    def test_spring_security_config_case_is_a_pinned_constructor_guard(self):
        case = realreg.CASES["spring-security-config"]

        self.assertEqual(case.source_dirs, (Path("config/src/main/java"),))
        self.assertEqual(
            case.final_artifact.name, "spring-security-config-6.5.10.jar"
        )
        self.assertEqual(
            case.final_artifact.parent,
            case.default_project / "config" / "build" / "libs",
        )
        self.assertNotIn(".m2", case.final_artifact.parts)
        fixture_dir = realreg.ROOT_DIR / "tests" / "fixtures" / "real_projects"
        self.assertEqual(case.case_mode, "guard")
        self.assertEqual(case.ground_truth_status, "reviewed")
        self.assertEqual(
            case.default_changed_apis,
            fixture_dir / "spring-security-config-changed-apis.csv",
        )
        self.assertEqual(
            case.fixture_manifest,
            fixture_dir / "spring-security-config.json",
        )
        self.assertEqual(
            case.required_fault_injections,
            realreg.STANDARD_FAULT_INJECTIONS,
        )
        self.assertTrue(case.require_relative_performance_baseline)
        self.assertTrue(case.enable_jdk_oracle)
        self.assertLessEqual(case.max_elapsed_seconds, 130.0)
        self.assertEqual(
            set(case.bytecode_owner_prefixes),
            {
                "org/springframework/security/authentication/ProviderManager",
                "org/springframework/security/core/context/SecurityContextHolder",
                "org/springframework/security/authorization/method/AuthorizationAdvisorProxyFactory",
            },
        )

        manifest = realreg.load_pinned_guard_manifest(case)
        self.assertEqual(len(manifest["apis"]), 15)
        self.assertEqual(len(manifest["canonical_edges"]), 15)
        self.assertEqual(manifest["ground_truth_status"], "reviewed")
        self.assertEqual(
            manifest["performance_baseline"]["scope"]["selected_api_count"],
            15,
        )
        self.assertEqual(manifest.get("unverified_apis", []), [])

    def test_dubbo_rpc_proxy_consumer_case_is_a_new_strict_discovery_target(self):
        case = realreg.CASES["dubbo-rpc-proxy-consumer"]

        self.assertEqual(case.source_dirs, (Path("src/main/java"),))
        self.assertEqual(
            case.bytecode_coord,
            "org.apache.dubbo.samples:dubbo-samples-rpc-basic-api",
        )
        self.assertEqual(
            case.bytecode_owner_prefixes,
            ("org/apache/dubbo/samples/DemoService",),
        )
        self.assertEqual(
            case.final_artifact.name,
            "dubbo-samples-rpc-basic-consumer-0.0.1-SNAPSHOT.jar",
        )
        self.assertEqual(case.case_mode, "discovery")
        self.assertTrue(case.enable_jdk_oracle)
        self.assertTrue(case.require_valid_git)
        self.assertIn("business_direct", case.required_topologies)
        self.assertIn("interface_dispatch", case.required_topologies)
        self.assertIn("framework_callback", case.required_topologies)

    def test_commons_cases_reject_empty_or_stale_real_project_checkouts(self):
        expected_minimums = {
            "commons-text": (100, 100),
            "commons-lang": (500, 400),
        }

        for case_name, (project_min, main_min) in expected_minimums.items():
            with self.subTest(case=case_name):
                case = realreg.CASES[case_name]
                self.assertTrue(case.require_valid_git)
                self.assertGreaterEqual(case.min_project_java_files, project_min)
                self.assertGreaterEqual(case.min_main_java_files, main_min)

    def test_commons_text_is_a_pinned_source_bytecode_guard(self):
        case = realreg.CASES["commons-text"]

        self.assertEqual(case.case_mode, "guard")
        self.assertEqual(case.source_dirs, (Path("src/main/java"),))
        self.assertEqual(case.required_topologies, ("source_bytecode_agree",))
        self.assertEqual(case.required_fault_injections, realreg.STANDARD_FAULT_INJECTIONS)
        self.assertTrue(case.require_relative_performance_baseline)
        self.assertTrue(case.source_attestation.is_file())
        self.assertTrue(case.default_changed_apis.is_file())

        manifest = realreg.load_pinned_guard_manifest(case)
        self.assertEqual(len(manifest["apis"]), 6)
        self.assertEqual(len(manifest["canonical_edges"]), 5)
        self.assertEqual(
            sum(api["expected_conclusion"] == "uncertain" for api in manifest["apis"]),
            1,
        )
        self.assertEqual(
            manifest["performance_baseline"]["scope"]["fault_injection_detected_count"],
            1,
        )

    def test_grpc_netty_shaded_is_a_pinned_source_bytecode_conflict_guard(self):
        case = realreg.CASES["grpc-netty-shaded"]

        self.assertEqual(case.case_mode, "guard")
        self.assertEqual(case.source_dirs, (Path("netty/src/main/java"),))
        self.assertEqual(case.required_topologies, ("source_bytecode_true_conflict",))
        self.assertEqual(case.required_fault_injections, realreg.STANDARD_FAULT_INJECTIONS)
        self.assertTrue(case.require_relative_performance_baseline)
        self.assertTrue(case.source_attestation.is_file())
        self.assertTrue(case.default_changed_apis.is_file())

        manifest = realreg.load_pinned_guard_manifest(case)
        self.assertEqual(len(manifest["apis"]), 84)
        self.assertEqual(
            sum(api["expected_conclusion"] == "reachable" for api in manifest["apis"]),
            42,
        )
        self.assertEqual(
            sum(
                api["expected_conclusion"] == "not_found_in_static_analysis"
                for api in manifest["apis"]
            ),
            42,
        )
        self.assertGreaterEqual(len(manifest["canonical_edges"]), 100)
        self.assertEqual(
            manifest["performance_baseline"]["scope"]["fault_injection_detected_count"],
            1,
        )

    def test_mybatis_semantic_references_require_complete_oracle_and_runtime(self):
        selected = [
            {
                "coord": "org.mybatis:mybatis",
                "api_name": api_name,
                "api_signature": signature,
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            for api_name, signature in (
                (
                    "org.apache.ibatis.binding.MapperProxy.invoke",
                    "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])",
                ),
                (
                    "org.apache.ibatis.binding.MapperMethod.execute",
                    "(org.apache.ibatis.session.SqlSession,java.lang.Object[])",
                ),
                (
                    "org.apache.ibatis.session.SqlSession.selectOne",
                    "(java.lang.String,java.lang.Object)",
                ),
            )
        ]
        mapper_oracle = {
            "complete": True,
            "proxy_dispatch_links": [{
                "registration_entry": "BOOT-INF/classes/sample/Mapper.class",
                "physical_dispatch_edges": [{}, {}],
            }],
            "physical_edges": [{
                "artifact_entry": (
                    "BOOT-INF/lib/mybatis-9.9.9.jar!/"
                    "org/apache/ibatis/binding/MapperProxy.class"
                ),
            }],
            "framework_api_evidence": {
                "org.apache.ibatis.binding.MapperProxy.invoke": [{}],
                "org.apache.ibatis.binding.MapperMethod.execute": [{}],
                "org.apache.ibatis.session.SqlSession.selectOne": [{}],
            },
        }
        runtime = {"active": True, "output_sha256": "b" * 64, "failures": []}

        references = realreg.build_mybatis_semantic_references(
            selected, mapper_oracle, runtime, "a" * 64
        )

        self.assertEqual(len(references), 3)
        self.assertTrue(all(
            item["authority"] == "final-artifact-mybatis-proxy-runtime"
            for item in references
        ))
        self.assertEqual(
            {item["api_identity"] for item in references},
            {realreg.serialized_api_identity(row) for row in selected},
        )
        self.assertTrue(all(
            item["artifact_entry"].startswith(
                "BOOT-INF/lib/mybatis-9.9.9.jar!/"
            )
            for item in references
        ))
        self.assertEqual(
            realreg.build_mybatis_semantic_references(
                selected, {**mapper_oracle, "complete": False}, runtime, "a" * 64
            ),
            [],
        )
        self.assertEqual(
            realreg.build_mybatis_semantic_references(
                selected, mapper_oracle, {**runtime, "active": False}, "a" * 64
            ),
            [],
        )
        without_select_one = {
            **mapper_oracle,
            "framework_api_evidence": {
                **mapper_oracle["framework_api_evidence"],
                "org.apache.ibatis.session.SqlSession.selectOne": [],
            },
        }
        self.assertEqual(
            {
                item["target_class"]
                for item in realreg.build_mybatis_semantic_references(
                    selected, without_select_one, runtime, "a" * 64
                )
            },
            {
                "org.apache.ibatis.binding.MapperProxy.invoke",
                "org.apache.ibatis.binding.MapperMethod.execute",
            },
        )

    def test_v3_edge_gate_propagates_missing_semantic_reference(self):
        semantic = {
            "api_identity": "api",
            "target_class": "com.acme.Target",
            "artifact_sha256": "a" * 64,
            "artifact_entry": "BOOT-INF/classes/com/acme/Target.class",
            "authority": "test-authority",
        }
        manifest = {
            "required_topologies": [],
            "apis": [],
            "canonical_edges": [],
            "canonical_semantic_references": [semantic],
        }
        result = {
            "api_coverage_complete": True,
            "summary": {},
            "topology_coverage": {"complete": True, "observed": []},
            "edge_truth": {
                "complete": True,
                "blocking": False,
                "ledger": [],
                "semantic_references": [],
            },
            "quality_signals": [],
        }

        gates = realreg.build_v3_gates(
            manifest,
            result,
            {"name": "asset", "passed": True, "errors": []},
            {"passed": True, "errors": []},
        )

        self.assertFalse(gates["edge_truth"]["passed"])
        self.assertIn(
            "expected_semantic_reference_missing",
            gates["edge_truth"]["errors"],
        )

    def test_v3_edge_gate_rejects_unexpected_semantic_reference(self):
        semantic = {
            "api_identity": "api",
            "target_class": "com.acme.Target",
            "artifact_sha256": "a" * 64,
            "artifact_entry": "BOOT-INF/classes/com/acme/Target.class",
            "authority": "test-authority",
        }
        result = {
            "api_coverage_complete": True,
            "summary": {},
            "topology_coverage": {"complete": True, "observed": []},
            "edge_truth": {
                "complete": True,
                "blocking": False,
                "ledger": [],
                "semantic_references": [semantic],
            },
            "quality_signals": [],
        }

        gates = realreg.build_v3_gates(
            {"required_topologies": [], "apis": [], "canonical_edges": [],
             "canonical_semantic_references": []},
            result,
            {"name": "asset", "passed": True, "errors": []},
            {"passed": True, "errors": []},
        )

        self.assertFalse(gates["edge_truth"]["passed"])
        self.assertIn("unexpected_semantic_reference", gates["edge_truth"]["errors"])

    def test_real_fat_jar_cases_require_cross_jar_bridge_topologies(self):
        self.assertIn(
            "cross_jar_bridge",
            realreg.CASES["spring-petclinic"].required_topologies,
        )
        self.assertIn(
            "business_to_cross_jar_bridge",
            realreg.CASES["mall"].required_topologies,
        )

    def test_fixture_reference_resolves_when_runner_is_loaded_from_scripts_directory(self):
        reference = (
            "tests.test_real_project_regression.RealProjectRegressionTests."
            "test_gs_multi_module_same_coordinate_guard"
        )
        command = [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys;"
                f"sys.path.insert(0, {str(ROOT / 'scripts')!r});"
                "import real_project_regression as module;"
                f"print(module._resolves_to_unittest({reference!r}))"
            ),
        ]

        completed = subprocess.run(command, capture_output=True, text=True, check=False)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "True")

    def test_alert_identity_does_not_duplicate_rendered_method_signature(self):
        self.assertEqual(
            realreg._api_identity_from_alert_row({
                "changed_symbol": "fixture.Target.changed()",
                "api_signature": "()",
                "symbol_kind": "method",
            }),
            ("fixture.Target.changed", "()", "method"),
        )

    def test_api_identity_normalizes_signature_whitespace_across_changed_and_alert_rows(self):
        changed = realreg._api_identity_from_changed_row({
            "api_name": "fixture.Target.call",
            "api_signature": "(int,int)",
            "symbol_kind": "method",
        })
        alert = realreg._api_identity_from_alert_row({
            "changed_symbol": "fixture.Target.call(int, int)",
            "api_signature": "(int, int)",
            "symbol_kind": "method",
        })

        self.assertEqual(changed, alert)

    def test_alert_identity_strips_rendered_signature_after_normalizing_whitespace(self):
        changed = realreg._api_identity_from_changed_row({
            "api_name": "fixture.Target.call",
            "api_signature": "(int, int)",
            "symbol_kind": "method",
        })
        alert = realreg._api_identity_from_alert_row({
            "changed_symbol": "fixture.Target.call(int,int)",
            "api_signature": "(int, int)",
            "symbol_kind": "method",
        })

        self.assertEqual(changed, alert)

    def test_output_audit_rejects_source_call_edges_in_final_artifact_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["api_name", "api_signature", "symbol_kind"])
                writer.writeheader()
                writer.writerow({"api_name": "lib.Api.call", "api_signature": "()", "symbol_kind": "method"})
            fields = [
                "conclusion", "change_summary", "review_reason", "chain_summary",
                "chain_target", "changed_symbol", "api_signature", "symbol_kind",
                "path_status", "path_text",
            ]
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "conclusion": "已确认影响", "change_summary": "removed",
                    "review_reason": "path", "chain_summary": "path",
                    "chain_target": "lib.Api.call()", "changed_symbol": "lib.Api.call()",
                    "api_signature": "()", "symbol_kind": "method",
                    "path_status": "reachable", "path_text": "app.App.run -> lib.Api.call()",
                })
            summary = {
                "total_apis": 1,
                "reachable_apis": [{
                    "evidence_paths": [[{
                        "evidence_type": "ast_method_invocation", "file": "App.java"
                    }]]
                }],
            }

            audit = realreg.audit_analysis_outputs(changed, alerts, summary)

        self.assertIn("source_edges_in_final_artifact_paths:1", audit["failures"])

    def test_output_audit_allows_source_clues_for_artifact_conflict_uncertainty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["api_name", "api_signature", "symbol_kind"])
                writer.writeheader()
                writer.writerow({"api_name": "lib.Api.call", "api_signature": "()", "symbol_kind": "method"})
            fields = [
                "conclusion", "change_summary", "review_reason", "chain_summary",
                "chain_target", "changed_symbol", "api_signature", "symbol_kind",
                "path_status", "path_text",
            ]
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "conclusion": "需人工复核", "change_summary": "removed",
                    "review_reason": "source artifact conflict", "chain_summary": "source clue",
                    "chain_target": "lib.Api.call()", "changed_symbol": "lib.Api.call()",
                    "api_signature": "()", "symbol_kind": "method",
                    "path_status": "uncertain", "path_text": "app.App.run -> lib.Api.call()",
                })
            summary = {
                "total_apis": 1,
                "uncertain_apis": [{
                    "reason_code": "SOURCE_BYTECODE_EDGE_CONFLICT",
                    "evidence_paths": [[{
                        "evidence_type": "ast_method_invocation", "file": "App.java"
                    }]],
                }],
            }

            audit = realreg.audit_analysis_outputs(changed, alerts, summary)

        self.assertNotIn("source_edges_in_final_artifact_paths:1", audit["failures"])

    def test_output_audit_rejects_alert_identity_not_in_changed_api_population(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed.write_text(
                "api_name,api_signature,symbol_kind\n"
                "lib.Api.call,(),method\n",
                encoding="utf-8",
            )
            fields = [
                "conclusion", "change_summary", "review_reason", "chain_summary",
                "chain_target", "changed_symbol", "api_signature", "symbol_kind",
                "path_status",
            ]
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for symbol in ("lib.Api.call", "lib.Api.notChanged"):
                    writer.writerow({
                        "conclusion": "需人工复核",
                        "change_summary": "removed",
                        "review_reason": "bytecode reference",
                        "chain_summary": "dependency path",
                        "chain_target": f"{symbol}()",
                        "changed_symbol": f"{symbol}()",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "path_status": "uncertain",
                    })

            audit = realreg.audit_analysis_outputs(
                changed, alerts, {"total_apis": 1}
            )

        self.assertIn("alerts_extra_api_rows:1", audit["failures"])

    def test_output_audit_uses_coordinate_and_change_type_in_closed_identity_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed_rows = [
                {
                    "coord": coord,
                    "api_name": "lib.Api.call",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
                for coord in ("one:api", "two:api")
            ]
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=changed_rows[0])
                writer.writeheader()
                writer.writerows(changed_rows)
            alert_identity = realreg.serialized_api_identity(changed_rows[0])
            alert_row = {
                "api_identity": alert_identity,
                "conclusion": "需人工复核",
                "change_summary": "removed",
                "review_reason": "bytecode reference",
                "chain_summary": "dependency path",
                "chain_target": "lib.Api.call()",
                "changed_symbol": "lib.Api.call()",
                "api_signature": "()",
                "symbol_kind": "method",
                "path_status": "uncertain",
            }
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=alert_row)
                writer.writeheader()
                writer.writerow(alert_row)

            audit = realreg.audit_analysis_outputs(
                changed, alerts, {"total_apis": 2}
            )

        self.assertIn("alerts_missing_api_rows:1", audit["failures"])

    def test_output_audit_rejects_duplicate_step4_canonical_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed_row = {
                "coord": "one:api",
                "api_name": "lib.Api.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=changed_row)
                writer.writeheader()
                writer.writerows([changed_row, changed_row])
            alert_row = {
                "api_identity": realreg.serialized_api_identity(changed_row),
                "conclusion": "需人工复核",
                "change_summary": "removed",
                "review_reason": "bytecode reference",
                "chain_summary": "dependency path",
                "chain_target": "lib.Api.call()",
                "changed_symbol": "lib.Api.call()",
                "api_signature": "()",
                "symbol_kind": "method",
                "path_status": "uncertain",
            }
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=alert_row)
                writer.writeheader()
                writer.writerow(alert_row)

            audit = realreg.audit_analysis_outputs(
                changed, alerts, {"total_apis": 2}
            )

        self.assertIn("changed_duplicate_api_identities:1", audit["failures"])

    def test_output_audit_rejects_equal_count_summary_with_wrong_identity_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed_rows = [
                {
                    "coord": "g:a",
                    "api_name": name,
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
                for name in ("p.Api.one", "p.Api.two")
            ]
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=changed_rows[0])
                writer.writeheader()
                writer.writerows(changed_rows)
            alert_fields = [
                "api_identity", "conclusion", "change_summary", "review_reason",
                "chain_summary", "chain_target", "changed_symbol", "api_signature",
                "symbol_kind", "change_type", "path_status",
            ]
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=alert_fields)
                writer.writeheader()
                for row in changed_rows:
                    writer.writerow({
                        "api_identity": realreg.serialized_api_identity(row),
                        "conclusion": "需人工复核",
                        "change_summary": "removed",
                        "review_reason": "bytecode reference",
                        "chain_summary": "dependency path",
                        "chain_target": f"{row['api_name']}()",
                        "changed_symbol": f"{row['api_name']}()",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "path_status": "uncertain",
                    })
            wrong = {
                **changed_rows[0],
                "api_name": "p.Api.extra",
                "api": "p.Api.extra",
            }
            summary = {
                "total_apis": 2,
                "uncertain_apis": [changed_rows[0], wrong],
            }

            audit = realreg.audit_analysis_outputs(changed, alerts, summary)

        self.assertIn("summary_missing_api_rows:1", audit["failures"])
        self.assertIn("summary_extra_api_rows:1", audit["failures"])

    def test_output_audit_accepts_one_identical_canonical_identity_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed_rows = [
                {
                    "coord": "g:a",
                    "api_name": name,
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                }
                for name in ("p.Api.one", "p.Api.two")
            ]
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=changed_rows[0])
                writer.writeheader()
                writer.writerows(changed_rows)
            alert_fields = [
                "api_identity", "conclusion", "change_summary", "review_reason",
                "chain_summary", "chain_target", "changed_symbol", "api_signature",
                "symbol_kind", "change_type", "path_status",
            ]
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=alert_fields)
                writer.writeheader()
                for row in changed_rows:
                    writer.writerow({
                        "api_identity": realreg.serialized_api_identity(row),
                        "conclusion": "需人工复核",
                        "change_summary": "removed",
                        "review_reason": "bytecode reference",
                        "chain_summary": "dependency path",
                        "chain_target": f"{row['api_name']}()",
                        "changed_symbol": f"{row['api_name']}()",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                        "path_status": "uncertain",
                    })
            summary = {"total_apis": 2, "uncertain_apis": changed_rows}

            audit = realreg.audit_analysis_outputs(changed, alerts, summary)

        self.assertEqual(audit["failures"], [])

    def test_all_real_cases_have_active_measurable_performance_budgets(self):
        self.assertTrue(realreg.CASES)
        for name, case in realreg.CASES.items():
            with self.subTest(case=name):
                self.assertGreater(case.max_elapsed_seconds, 0.0)
                self.assertGreater(case.max_potential_pairs_per_api, 0.0)
                self.assertGreaterEqual(case.max_duplicate_class_scans, 0)
                self.assertGreater(case.max_seconds_per_100k_edges, 0.0)
                self.assertGreater(case.min_edges_for_normalized_rate, 0)
                self.assertGreater(case.min_classes_per_second, 0.0)
                self.assertGreater(case.max_oracle_seconds, 0.0)

    def test_real_case_performance_defaults_and_mall_policy_match_the_measured_baseline(self):
        self.assertEqual(
            realreg.REAL_CASE_PERFORMANCE_BUDGET,
            {
                "max_elapsed_seconds": 300.0,
                "max_potential_pairs_per_api": 100000.0,
                "max_duplicate_class_scans": 0,
                "max_seconds_per_100k_edges": 1000000.0,
                "min_edges_for_normalized_rate": 100,
                "min_classes_per_second": 1.0,
                "max_oracle_seconds": 120.0,
            },
        )
        mall = realreg.CASES["mall"]
        self.assertEqual(mall.max_duplicate_class_scans, 0)
        self.assertEqual(mall.max_seconds_per_100k_edges, 1000000.0)
        self.assertEqual(mall.min_classes_per_second, 1.0)

    def test_spring_petclinic_case_uses_final_artifact_spring_data_api_discovery(self):
        case = realreg.CASES["spring-petclinic"]

        self.assertEqual(case.bytecode_coord, "org.springframework.data:spring-data-commons")
        self.assertEqual(case.bytecode_owner_prefixes, ("org/springframework/data/domain/",))
        self.assertEqual(
            case.final_artifact,
            Path(
                "/private/tmp/jua-real-project-spring-petclinic/target/"
                "spring-petclinic-4.0.0-SNAPSHOT.jar"
            ),
        )
        self.assertEqual(
            set(case.required_topologies),
            {
                "business_direct", "cross_jar_bridge",
                "interface_dispatch", "static_dispatch",
            },
        )

    def test_dubbo_spring6_security_guard_declares_independent_reflection_api(self):
        case = realreg.CASES["dubbo-spring6-security"]

        self.assertEqual(case.case_mode, "guard")
        self.assertEqual(case.required_topologies, ("reflection",))
        self.assertEqual(
            case.default_changed_apis,
            ROOT / "tests" / "fixtures" / "real_projects" /
            "dubbo-spring6-security-changed-apis.csv",
        )
        self.assertEqual(
            case.final_artifact,
            Path(
                "/private/tmp/jua-real-project-dubbo-source-20260710/dubbo-plugin/"
                "dubbo-spring6-security/target/dubbo-spring6-security-3.3.7-SNAPSHOT.jar"
            ),
        )

    def test_all_executable_real_cases_declare_nonempty_topology_requirements(self):
        self.assertTrue(realreg.CASES)
        for name, case in realreg.CASES.items():
            with self.subTest(case=name):
                self.assertTrue(case.required_topologies)

    def test_actual_discovery_cases_require_valid_pinned_prior_matrix_and_rotation_math(self):
        discovery = [case for case in realreg.CASES.values() if case.case_mode in {"discovery", "convergence"}]
        self.assertTrue(discovery)
        for case in discovery:
            with self.subTest(case=case.name):
                matrix = realreg.load_pinned_prior_topology_matrix(case.prior_topology_matrix)
                self.assertTrue(matrix["valid"], matrix["errors"])
                coverage = realreg.compute_topology_coverage(
                    case.required_topologies,
                    set(case.required_topologies),
                    prior_covered=set(matrix["covered_ids"]),
                    case_mode=case.case_mode,
                )
                self.assertEqual(
                    coverage["newly_observed"],
                    sorted(set(case.required_topologies) - set(matrix["covered_ids"])),
                )
        mall = realreg.CASES["mall"]
        matrix = realreg.load_pinned_prior_topology_matrix(mall.prior_topology_matrix)
        coverage = realreg.compute_topology_coverage(
            mall.required_topologies, set(mall.required_topologies),
            prior_covered=set(matrix["covered_ids"]), case_mode=mall.case_mode,
        )
        self.assertTrue(coverage["discovery_target_eligible"])
        self.assertFalse(coverage["rotation_required"])

    def test_actual_discovery_case_rejects_missing_and_corrupt_prior_matrix(self):
        actual = realreg.CASES["mall"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corrupt = root / "matrix.json"
            corrupt.write_text('{"covered_ids":["business_direct"],"evidence_sha256":"bad"}', encoding="utf-8")
            missing_case = realreg.replace(actual, prior_topology_matrix=root / "missing.json")
            corrupt_case = realreg.replace(actual, prior_topology_matrix=corrupt)
            missing_result = realreg.load_pinned_prior_topology_matrix(missing_case.prior_topology_matrix)
            corrupt_result = realreg.load_pinned_prior_topology_matrix(corrupt_case.prior_topology_matrix)

        self.assertFalse(missing_result["valid"])
        self.assertFalse(corrupt_result["valid"])

    def test_prior_topology_matrix_persists_union_of_converged_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            realreg.update_prior_topology_matrix(
                root, "guard-a", "guard", {"business_direct", "static_dispatch"}
            )
            realreg.update_prior_topology_matrix(
                root, "guard-b", "convergence", {"spi"}
            )
            matrix = realreg.load_prior_topology_matrix(root)

        self.assertEqual(
            set(matrix["converged_guard_union"]),
            {"business_direct", "static_dispatch", "spi"},
        )

    def test_discovery_prior_merges_pinned_and_report_root_converged_guard_matrix(self):
        case = realreg.CASES["dubbo"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            realreg.update_prior_topology_matrix(root, "guard", "guard", {"spi"})
            prior = realreg.resolve_discovery_prior_coverage(case, root)

        self.assertTrue(prior["valid"])
        self.assertEqual(set(prior["covered_ids"]), {"business_direct", "static_dispatch", "spi"})

    def test_convergence_rejects_tampered_report_root_prior_matrix(self):
        case = realreg.replace(realreg.CASES["dubbo"], case_mode="convergence")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "topology_prior_matrix.json").write_text(json.dumps({
                "converged_guard_union": ["spi"],
                "cases": {"forged": {"case_mode": "guard", "observed": ["spi"]}},
            }), encoding="utf-8")
            prior = realreg.resolve_discovery_prior_coverage(case, root)

        self.assertFalse(prior["valid"])
        self.assertEqual(prior["covered_ids"], [])

    def test_discovery_uses_pinned_prior_when_report_root_matrix_does_not_exist_yet(self):
        case = realreg.CASES["dubbo"]
        with tempfile.TemporaryDirectory() as tmp:
            prior = realreg.resolve_discovery_prior_coverage(case, Path(tmp))

        pinned = realreg.load_pinned_prior_topology_matrix(case.prior_topology_matrix)
        self.assertTrue(prior["valid"])
        self.assertEqual(prior["covered_ids"], pinned["covered_ids"])

    def test_discovery_case_rejects_empty_required_topology_policy(self):
        case = realreg.RealProjectCase(
            "mini", Path("."), Path(""), (), case_mode="discovery", required_topologies=()
        )
        coverage = realreg.compute_topology_coverage(
            (), {"business_direct"}, case_mode="discovery"
        )

        signals = realreg.build_topology_coverage_signals(case, coverage, Path("/tmp/report"))

        self.assertEqual([item["signal_type"] for item in signals], ["topology_configuration_invalid"])
        self.assertTrue(signals[0]["blocking"])

    def test_rotation_is_reported_when_discovery_observes_no_new_topology(self):
        case = realreg.RealProjectCase(
            "mini", Path("."), Path(""), (), case_mode="discovery",
            required_topologies=("business_direct",),
            prior_covered_topologies=("business_direct",),
        )
        coverage = realreg.compute_topology_coverage(
            case.required_topologies, {"business_direct"},
            prior_covered=set(case.prior_covered_topologies), case_mode=case.case_mode,
        )

        signals = realreg.build_topology_coverage_signals(case, coverage, Path("/tmp/report"))

        self.assertIn("topology_rotation_required", {item["signal_type"] for item in signals})
        self.assertFalse(next(item for item in signals if item["signal_type"] == "topology_rotation_required")["blocking"])

    def test_topology_policy_emits_one_blocking_gap_with_all_missing_ids(self):
        case = realreg.RealProjectCase(
            "mini", Path("."), Path(""), (), required_topologies=("spi", "business_direct")
        )
        coverage = realreg.compute_topology_coverage(case.required_topologies, {"business_direct"})

        signals = realreg.build_topology_coverage_signals(case, coverage, Path("/tmp/report"))

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["signal_type"], "topology_coverage_gap")
        self.assertEqual(signals[0]["severity"], "P1")
        self.assertTrue(signals[0]["blocking"])
        self.assertEqual(signals[0]["sample_symbols"], ["spi"])
        self.assertIn("spi", signals[0]["message"])

    def test_topology_coverage_outputs_include_required_observed_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            coverage = realreg.compute_topology_coverage(
                ("spi", "business_direct"), {"business_direct", "static_dispatch"}
            )

            paths = realreg.write_topology_coverage(report_dir, coverage)

            payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            with Path(paths["csv"]).open(encoding="utf-8-sig") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(payload["missing"], ["spi"])
        self.assertEqual(
            {(row["topology_id"], row["required"], row["observed"], row["missing"]) for row in rows},
            {
                ("business_direct", "true", "true", "false"),
                ("spi", "true", "false", "true"),
                ("static_dispatch", "false", "true", "false"),
            },
        )

    def test_mall_case_rebuilds_truth_set_from_all_hutool_bytecode_calls(self):
        case = realreg.CASES["mall"]

        self.assertEqual(case.case_mode, "discovery")
        self.assertEqual(case.bytecode_owner_prefixes, ("cn/hutool/",))
        self.assertEqual(case.bytecode_coord, "cn.hutool:hutool-all")
        self.assertTrue(case.enable_jdk_oracle)
        self.assertTrue(case.require_valid_git)
        self.assertEqual(
            case.final_artifact,
            Path("/private/tmp/jua-real-project-mall/mall-admin/target/mall-admin-1.0-SNAPSHOT.jar"),
        )
        self.assertEqual(case.baseline_specs, ())

    def test_dubbo_samples_is_a_separate_full_discovery_consumer_case(self):
        case = realreg.CASES["dubbo-samples"]

        self.assertEqual(case.case_mode, "discovery")
        self.assertTrue(case.run_step4)
        self.assertTrue(case.enable_jdk_oracle)
        self.assertIn("dubbo-samples", str(case.default_project))
        self.assertEqual(case.baseline_specs, ())

    def test_discovery_coverage_requires_full_step4_population(self):
        coverage = realreg.compute_api_coverage("discovery", 5440, 9, 9)

        self.assertEqual(coverage["coverage_scope"], "full")
        self.assertAlmostEqual(coverage["coverage_ratio"], 9 / 5440)
        self.assertFalse(coverage["complete"])

    def test_discovery_step4_always_uses_the_full_api_population(self):
        case = realreg.RealProjectCase(
            name="full-discovery",
            default_project=Path("/tmp/project"),
            default_changed_apis=Path(""),
            baseline_specs=(),
            run_step4=True,
            case_mode="discovery",
            expected_step4_api_names=("only.a.probe",),
        )

        self.assertTrue(realreg.requires_full_step4_population(case, requested=False))

    def test_artifact_derived_step4_rejects_hand_written_dependency_rows(self):
        case = realreg.RealProjectCase(
            name="artifact-derived",
            default_project=Path("/tmp/current"),
            default_changed_apis=Path(""),
            baseline_specs=(),
            run_step4=True,
            derive_step1_from_artifacts=True,
            base_final_artifact=Path("/tmp/old.jar"),
            final_artifact=Path("/tmp/new.jar"),
            step4_dep_rows=({"coord": "hand:selected"},),
        )

        with self.assertRaisesRegex(ValueError, "step4_dep_rows"):
            realreg.validate_step4_population_contract(case)

    def test_artifact_derived_step4_runs_step1_and_step2_before_step4(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")
            project = root / "project"
            source_dir = project / "module/src/main/java"
            source_dir.mkdir(parents=True)
            case = realreg.RealProjectCase(
                name="artifact-derived",
                default_project=project,
                default_changed_apis=Path(""),
                baseline_specs=(),
                source_dirs=(Path("module/src/main/java"),),
                run_step4=True,
                derive_step1_from_artifacts=True,
                base_final_artifact=old_jar,
                final_artifact=new_jar,
                base_source_project=project,
                current_source_project=project,
                base_revision="base-sha",
                current_revision="current-sha",
            )
            commands = []

            def fake_run(cmd, **_kwargs):
                commands.append(cmd)
                if str(cmd[1]).endswith("s1_dep_diff.py"):
                    Path(cmd[cmd.index("--output") + 1]).write_text(
                        "coord,old_version,new_version,change_type,scope\n"
                        "g:a,1,2,MINOR,compile\n",
                        encoding="utf-8",
                    )
                elif str(cmd[1]).endswith("s2_context_from_deps.py"):
                    Path(cmd[cmd.index("--output") + 1]).write_text(
                        json.dumps({"changed_dependencies": [{"coord": "g:a"}]}),
                        encoding="utf-8",
                    )
                else:
                    output = Path(cmd[cmd.index("--output-dir") + 1])
                    output.mkdir(parents=True, exist_ok=True)
                    (output / "all_changed_apis.csv").write_text(
                        "coord,api_name,symbol_kind,api_signature\n"
                        "g:a,p.A.m,method,()\n",
                        encoding="utf-8",
                    )
                return SimpleNamespace(returncode=0)

            with patch.object(realreg.subprocess, "run", side_effect=fake_run):
                result = realreg.run_step4(case, root / "report")

        self.assertEqual(len(commands), 3)
        self.assertTrue(str(commands[0][1]).endswith("s1_dep_diff.py"))
        self.assertIn("--base-artifact-path", commands[0])
        self.assertTrue(str(commands[1][1]).endswith("s2_context_from_deps.py"))
        self.assertIn(str(source_dir), commands[1])
        self.assertTrue(str(commands[2][1]).endswith("s4_jar_compare.py"))
        self.assertEqual(result["population_source"], "step1_final_artifacts")
        self.assertIn("evidence/dependencies/s1_dep_changes.csv", result["dep_changes"])
        self.assertIn("evidence/context/s2_context.json", result["context"])

    def test_declared_artifact_provenance_preserves_matching_step1_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "app.jar"
            artifact.write_bytes(b"artifact")
            report = root / "report"
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            provenance = dependencies / "build_provenance.json"
            provenance.write_text(json.dumps({"sides": [{
                "side": "current",
                "artifact_path": str(artifact),
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }]}), encoding="utf-8")
            resolved = dependencies / "deps_current_resolved.csv"
            resolved.write_text("coord\ng:a\n", encoding="utf-8")
            case = realreg.RealProjectCase(
                name="preserve", default_project=root, default_changed_apis=Path(""),
                baseline_specs=(), final_artifact=artifact,
            )

            realreg.write_declared_final_artifact_provenance(report, case)
            preserved = resolved.read_text(encoding="utf-8")

        self.assertEqual(preserved, "coord\ng:a\n")

    def test_guard_coverage_declares_probe_scope(self):
        coverage = realreg.compute_api_coverage("guard", 5440, 9, 9)

        self.assertEqual(coverage["coverage_scope"], "declared_probes")
        self.assertTrue(coverage["complete"])

    def test_conclusion_gaps_are_grouped_by_reason_and_symbol_kind(self):
        groups = realreg.group_conclusion_gaps({
            "not_analyzed_apis": [
                {"api": "a.A.one", "reason_code": "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "symbol_kind": "method"},
                {"api": "a.A.two", "reason_code": "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "symbol_kind": "method"},
                {"api": "a.B.B", "reason_code": "OVERLOAD_AMBIGUOUS_TARGET", "symbol_kind": "constructor"},
            ]
        })

        self.assertEqual([(item["reason_code"], item["symbol_kind"], item["count"]) for item in groups], [
            ("OVERLOAD_AMBIGUOUS_TARGET", "constructor", 1),
            ("RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "method", 2),
        ])
        self.assertEqual(groups[1]["sample_symbols"], ["a.A.one", "a.A.two"])

    def test_status_reflects_blocking_signals_and_unreviewed_discovery(self):
        blocking = [{"blocking": True, "signal_type": "conclusion_gap"}]

        self.assertEqual(realreg.derive_case_status(True, blocking, "reviewed"), "failed")
        self.assertEqual(realreg.derive_case_status(False, [], "reviewed"), "skipped")
        self.assertEqual(realreg.derive_case_status(True, [], "unreviewed"), "observed")
        self.assertEqual(realreg.derive_case_status(True, [], "reviewed"), "passed")

    def test_run_status_requires_every_case_to_be_conclusively_passed(self):
        self.assertEqual(
            realreg.derive_run_status([{"status": "passed"}]),
            "passed",
        )
        self.assertEqual(
            realreg.derive_run_status([
                {"status": "passed"},
                {"status": "observed"},
            ]),
            "incomplete",
        )
        self.assertEqual(
            realreg.derive_run_status([{"status": "skipped"}]),
            "incomplete",
        )
        self.assertEqual(
            realreg.derive_run_status([{"status": "failed"}]),
            "failed",
        )

    def test_performance_envelope_normalizes_candidate_pairs(self):
        envelope = realreg.collect_performance_envelope(
            {"meta": {"graph_stats": {"step5_perf": {"main": {
                "indirect_usage_potential_legacy_method_target_pairs": 143240640,
                "indirect_usage_owner_presence_scans": 8058,
            }}}}},
            elapsed=107.7,
            selected=5440,
        )

        self.assertEqual(envelope["potential_method_target_pairs"], 143240640)
        self.assertEqual(envelope["owner_presence_scans"], 8058)
        self.assertAlmostEqual(envelope["potential_pairs_per_api"], 143240640 / 5440)
        self.assertAlmostEqual(envelope["elapsed_seconds_per_1000_apis"], 107.7 / 5.44)

    def test_performance_envelope_includes_parse_reconcile_and_cache_metrics(self):
        envelope = realreg.collect_performance_envelope(
            {"meta": {"graph_stats": {"step5_perf": {"bytecode_scan": {
                "artifact_bytes": 4096,
                "class_entries_scoped": 16,
                "class_entries_parsed": 5,
                "elapsed_sec": 2.0,
                "class_parse_elapsed_sec": 2.5,
                "artifact_cache_hits": 3,
                "javap_fallbacks": 4,
                "duplicate_class_scans": 1,
            }}}}},
            elapsed=8.0,
            selected=2,
            oracle_metrics={
                "class_count": 120,
                "completed_class_count": 120,
                "parsed_class_count": 116,
                "cached_class_count": 4,
                "parse_failure_count": 2,
                "parse_seconds": 3.5,
                "elapsed_seconds": 3.75,
                "worker_count": 8,
                "cache_hits": 1,
                "cache_misses": 0,
                "timed_out": False,
                "interrupted": False,
            },
        )
        envelope.update({
            "oracle_edge_count": 10,
            "analyzer_edge_count": 8,
            "reconcile_seconds": 0.5,
        })
        realreg.finalize_performance_envelope(envelope)

        self.assertEqual(envelope["artifact_bytes"], 4096)
        self.assertEqual(envelope["class_count"], 16)
        self.assertEqual(envelope["parsed_class_count"], 5)
        self.assertEqual(envelope["artifact_cache_hits"], 3)
        self.assertEqual(envelope["javap_fallbacks"], 4)
        self.assertEqual(envelope["duplicate_class_scans"], 1)
        self.assertEqual(envelope["oracle_edge_count"], 10)
        self.assertEqual(envelope["analyzer_edge_count"], 8)
        self.assertEqual(envelope["parse_seconds"], 2.5)
        self.assertEqual(envelope["parse_classes_per_second"], 2.0)
        self.assertTrue(envelope["parse_rate_available"])
        self.assertEqual(envelope["reconcile_edges_per_second"], 20.0)
        self.assertEqual(envelope["elapsed_seconds_per_100k_edges"], 80000.0)
        self.assertTrue(envelope["edge_rate_available"])
        self.assertEqual(envelope["oracle_class_count"], 120)
        self.assertEqual(envelope["oracle_completed_class_count"], 120)
        self.assertEqual(envelope["oracle_parsed_class_count"], 116)
        self.assertEqual(envelope["oracle_cached_class_count"], 4)
        self.assertEqual(envelope["oracle_parse_failure_count"], 2)
        self.assertEqual(envelope["oracle_parse_seconds"], 3.5)
        self.assertEqual(envelope["oracle_elapsed_seconds"], 3.75)
        self.assertEqual(envelope["oracle_worker_count"], 8)
        self.assertEqual(envelope["oracle_cache_hits"], 1)
        self.assertFalse(envelope["oracle_timed_out"])
        self.assertFalse(envelope["oracle_interrupted"])

    def test_performance_envelope_exposes_complete_normalized_resource_metrics(self):
        envelope = realreg.collect_performance_envelope(
            {"meta": {"graph_stats": {"step5_perf": {
                "main": {"peak_rss_mb": 256.5},
                "bytecode_scan": {
                    "class_entries_scoped": 2000,
                    "elapsed_sec": 4.0,
                    "javap_tasks": 7,
                    "duplicate_jar_scans": 2,
                },
                "bytecode_expand": {"javap_classes": 3},
                "trace": {"api_trace_timings": [
                    {"api_name": "a.A.one", "elapsed_sec": 0.1},
                    {"api_name": "a.A.two", "elapsed_sec": 0.2},
                ]},
            }}}},
            elapsed=2.0,
            selected=2,
        )

        self.assertEqual(envelope["elapsed_seconds_per_api"], 1.0)
        self.assertEqual(envelope["scan_seconds_per_1000_classes"], 2.0)
        self.assertEqual(envelope["duplicate_jar_scans"], 2)
        self.assertEqual(envelope["javap_invocations"], 10)
        self.assertEqual(envelope["peak_rss_mb"], 256.5)
        self.assertEqual(len(envelope["per_api_timings"]), 2)

    def test_relative_performance_baseline_is_sha_bound_and_blocks_regression(self):
        case = realreg.RealProjectCase(
            name="relative-perf",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            require_relative_performance_baseline=True,
        )
        manifest = {
            "git_revision": "a" * 40,
            "artifact_sha256": "b" * 64,
            "performance_baseline": {
                "git_revision": "a" * 40,
                "artifact_sha256": "b" * 64,
                "scope": {
                    "selected_api_count": 1,
                    "accounted_api_count": 1,
                    "artifact_count": 1,
                    "class_count": 1,
                    "analyzer_edge_count": 1,
                    "oracle_edge_count": 1,
                    "fault_injection_detected_count": 1,
                },
                "metrics": {
                    "elapsed_seconds_per_api": {"value": 1.0, "max_ratio": 1.5},
                    "duplicate_jar_scans": {"value": 0, "max_absolute": 0},
                },
            },
        }

        regression = realreg.evaluate_relative_performance_baseline(
            case,
            manifest,
            {
                "elapsed_seconds_per_api": 1.6,
                "duplicate_jar_scans": 0,
                "per_api_timing_complete": True,
                **manifest["performance_baseline"]["scope"],
            },
        )
        stale = realreg.evaluate_relative_performance_baseline(
            case,
            {**manifest, "artifact_sha256": "c" * 64},
            {
                "elapsed_seconds_per_api": 1.0,
                "duplicate_jar_scans": 0,
                "per_api_timing_complete": True,
                **manifest["performance_baseline"]["scope"],
            },
        )

        self.assertFalse(regression["passed"])
        self.assertIn("elapsed_seconds_per_api", regression["regressions"])
        self.assertFalse(stale["passed"])
        self.assertIn("performance_baseline_artifact_sha_mismatch", stale["errors"])

    def test_performance_scope_gate_accepts_faster_run_with_identical_scope(self):
        baseline = {
            "selected_api_count": 3,
            "accounted_api_count": 3,
            "artifact_count": 33,
            "class_count": 8118,
            "analyzer_edge_count": 6,
            "oracle_edge_count": 6,
            "fault_injection_detected_count": 1,
        }
        current = {**baseline, "elapsed_seconds": 4.0}

        result = realreg.evaluate_performance_scope_preservation(baseline, current)

        self.assertTrue(result["passed"])
        self.assertEqual(result["regressions"], {})

    def test_performance_scope_gate_rejects_faster_run_that_reduces_scan_scope(self):
        baseline = {
            "selected_api_count": 2185,
            "accounted_api_count": 2185,
            "artifact_count": 119,
            "class_count": 44462,
            "analyzer_edge_count": 313,
            "oracle_edge_count": 313,
            "fault_injection_detected_count": 1,
        }
        current = {
            **baseline,
            "class_count": 44461,
            "analyzer_edge_count": 312,
            "elapsed_seconds": 1.0,
        }

        result = realreg.evaluate_performance_scope_preservation(baseline, current)

        self.assertFalse(result["passed"])
        self.assertEqual(result["regressions"]["class_count"]["missing"], 1)
        self.assertEqual(result["regressions"]["analyzer_edge_count"]["missing"], 1)

    def test_final_artifact_reconciliation_passes_budget_and_exposes_oracle_metrics(self):
        scan = {
            "artifact_sha256": "a" * 64,
            "complete": True,
            "edges": [],
            "failures": [],
            "class_count": 9,
            "completed_class_count": 9,
            "parsed_class_count": 9,
            "cached_class_count": 0,
            "parse_failure_count": 0,
            "parse_seconds": 1.25,
            "elapsed_seconds": 1.5,
            "worker_count": 4,
            "cache_hits": 0,
            "cache_misses": 1,
            "timed_out": False,
            "interrupted": False,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            realreg, "_verified_current_final_artifact", return_value=(Path("artifact.jar"), "a" * 64, [])
        ), patch.object(realreg, "_csv_rows", return_value=([], [])), patch.object(
            realreg, "_artifact_class_entries", return_value={"fixture/A.class"}
        ), patch.object(realreg, "scan_final_artifact", return_value=scan) as scan_oracle:
            result = realreg.reconcile_final_artifact_edges(
                Path(tmp), [{
                    "api_name": "fixture.Target.changed",
                    "api_simple": "changed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                }], oracle_time_budget_seconds=12.5
            )

        scan_oracle.assert_called_once_with(
            Path("artifact.jar"),
            time_budget_seconds=12.5,
            selected_targets=[{
                "owner": "fixture.Target",
                "member": "changed",
                "descriptor": "",
            }],
        )
        self.assertEqual(result["oracle_metrics"]["class_count"], 9)
        self.assertEqual(result["oracle_metrics"]["parse_seconds"], 1.25)

    def test_final_artifact_oracle_excludes_explicitly_external_target_provider_jar(self):
        scan = {
            "artifact_sha256": "a" * 64,
            "complete": True,
            "edges": [],
            "failures": [],
            "artifact_entries": ["BOOT-INF/classes/app/App.class"],
        }
        selected = [{
            "coord": "vendor:provider",
            "api_name": "vendor.Target.changed",
            "api_signature": "()",
            "symbol_kind": "method",
        }]
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            catalog_path = (
                report / ".runtime" / "cache" / "s5_artifact_bytecode_catalog.json"
            )
            catalog_path.parent.mkdir(parents=True)
            catalog_path.write_text(json.dumps({"entries": [{
                "coord": "vendor:provider",
                "artifact_entry": "BOOT-INF/lib/provider-1.0.jar",
                "application_owned": False,
            }]}), encoding="utf-8")
            with patch.object(
                realreg, "_verified_current_final_artifact",
                return_value=(Path("artifact.jar"), "a" * 64, []),
            ), patch.object(realreg, "_csv_rows", return_value=([], [])), patch.object(
                realreg, "_artifact_class_entries",
                return_value={"BOOT-INF/classes/app/App.class"},
            ), patch.object(
                realreg, "scan_final_artifact", return_value=scan
            ) as scan_oracle:
                realreg.reconcile_final_artifact_edges(report, selected)

        scan_oracle.assert_called_once_with(
            Path("artifact.jar"),
            time_budget_seconds=None,
            selected_targets=[{
                "owner": "vendor.Target",
                "member": "changed",
                "descriptor": "",
            }],
            excluded_nested_jars={"BOOT-INF/lib/provider-1.0.jar"},
        )

    def test_oracle_budget_failure_emits_blocking_incomplete_and_performance_signals(self):
        case = realreg.RealProjectCase(
            name="oracle-budgeted",
            default_project=Path("."),
            default_changed_apis=Path(""),
            baseline_specs=(),
            max_oracle_seconds=0.05,
        )
        edge_truth = {
            "complete": False,
            "errors": ["oracle_time_budget_exceeded:0.050s"],
            "oracle_edges": "oracle.csv",
            "edge_reconciliation": "reconciliation.csv",
            "reconciliation": {"blocking": False},
        }
        performance = {
            "oracle_timed_out": True,
            "oracle_interrupted": False,
            "oracle_elapsed_seconds": 0.051,
            "oracle_class_count": 100,
            "oracle_completed_class_count": 8,
        }

        signals = realreg.build_edge_truth_signals(case, edge_truth, {"valid": True})
        signals.extend(realreg.build_policy_signals(
            case,
            coverage={"complete": True},
            performance=performance,
            report_dir=Path("/tmp/report"),
        ))

        by_type = {signal["signal_type"]: signal for signal in signals}
        self.assertIn("oracle_incomplete", by_type)
        self.assertIn("performance_regression", by_type)
        self.assertTrue(by_type["oracle_incomplete"]["blocking"])
        self.assertTrue(by_type["performance_regression"]["blocking"])
        self.assertIn("time budget", by_type["performance_regression"]["message"])

    def test_zero_edge_rate_is_unavailable_and_blocks_a_configured_budget(self):
        envelope = realreg.collect_performance_envelope({}, elapsed=8.0, selected=2)
        envelope.update({
            "oracle_edge_count": 0,
            "analyzer_edge_count": 0,
            "reconcile_seconds": 0.5,
        })
        realreg.finalize_performance_envelope(envelope)

        self.assertFalse(envelope["edge_rate_available"])
        self.assertIsNone(envelope["elapsed_seconds_per_100k_edges"])

        case = realreg.RealProjectCase(
            name="zero-edge-budgeted",
            default_project=Path("."),
            default_changed_apis=Path(""),
            baseline_specs=(),
            max_seconds_per_100k_edges=100.0,
        )
        signals = realreg.build_policy_signals(
            case,
            coverage={"complete": True},
            performance=envelope,
            report_dir=Path("/tmp/report"),
        )

        regressions = [item for item in signals if item["signal_type"] == "performance_regression"]
        self.assertEqual(len(regressions), 1)
        self.assertTrue(regressions[0]["blocking"])
        self.assertIn("unavailable", regressions[0]["message"])

    def test_semantic_reference_is_a_valid_normalized_audit_denominator(self):
        envelope = realreg.collect_performance_envelope({}, elapsed=0.8, selected=1)
        envelope.update({
            "oracle_edge_count": 0,
            "analyzer_edge_count": 0,
            "semantic_reference_count": 1,
            "reconcile_seconds": 0.01,
        })

        realreg.finalize_performance_envelope(envelope)

        self.assertTrue(envelope["edge_rate_available"])
        self.assertEqual(envelope["audit_evidence_count"], 1)
        self.assertEqual(envelope["elapsed_seconds_per_100k_edges"], 80000.0)

    def test_zero_parsed_class_rate_is_unavailable_and_blocks_a_configured_budget(self):
        envelope = realreg.collect_performance_envelope(
            {"meta": {"graph_stats": {"step5_perf": {"bytecode_scan": {
                "class_entries_scoped": 16,
                "class_entries_parsed": 0,
                "class_parse_elapsed_sec": 0.0,
            }}}}},
            elapsed=8.0,
            selected=2,
        )
        realreg.finalize_performance_envelope(envelope)

        self.assertFalse(envelope["parse_rate_available"])
        self.assertIsNone(envelope["parse_classes_per_second"])

        case = realreg.RealProjectCase(
            name="zero-class-budgeted",
            default_project=Path("."),
            default_changed_apis=Path(""),
            baseline_specs=(),
            min_classes_per_second=1.0,
        )
        signals = realreg.build_policy_signals(
            case,
            coverage={"complete": True},
            performance=envelope,
            report_dir=Path("/tmp/report"),
        )

        regressions = [item for item in signals if item["signal_type"] == "performance_regression"]
        self.assertEqual(len(regressions), 1)
        self.assertTrue(regressions[0]["blocking"])
        self.assertIn("unavailable", regressions[0]["message"])

    def test_policy_signals_block_normalized_performance_budget_regressions(self):
        case = realreg.RealProjectCase(
            name="budgeted",
            default_project=Path("."),
            default_changed_apis=Path(""),
            baseline_specs=(),
            max_duplicate_class_scans=0,
            max_seconds_per_100k_edges=100.0,
            min_classes_per_second=20.0,
        )
        signals = realreg.build_policy_signals(
            case,
            coverage={"complete": True},
            performance={
                "duplicate_class_scans": 1,
                "elapsed_seconds_per_100k_edges": 101.0,
                "parse_classes_per_second": 19.0,
            },
            report_dir=Path("/tmp/report"),
        )

        regressions = [item for item in signals if item["signal_type"] == "performance_regression"]
        self.assertEqual(len(regressions), 3)
        self.assertTrue(all(item["blocking"] for item in regressions))
        self.assertTrue(any("elapsed_seconds_per_100k_edges=101.00" in item["message"] for item in regressions))

    def test_sparse_edge_case_uses_absolute_and_class_rate_budgets(self):
        case = realreg.RealProjectCase(
            name="sparse",
            default_project=Path("."),
            default_changed_apis=Path(""),
            baseline_specs=(),
            max_seconds_per_100k_edges=100.0,
            min_edges_for_normalized_rate=100,
        )

        signals = realreg.build_policy_signals(
            case,
            coverage={"complete": True},
            performance={
                "oracle_edge_count": 4,
                "analyzer_edge_count": 4,
                "edge_rate_available": True,
                "elapsed_seconds_per_100k_edges": 2_840_000.0,
            },
            report_dir=Path("/tmp/report"),
        )

        self.assertFalse(any(item["signal_type"] == "performance_regression" for item in signals))

    def test_edge_truth_reconciliation_fails_when_an_intermediate_oracle_edge_is_missing(self):
        artifact_sha256 = "a" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        direct = self._edge_row(
            artifact_sha256, "bridge.Adapter", "call", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/bridge.jar!/bridge/Adapter.class",
        )
        intermediate = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "bridge.Adapter", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
        )
        direct["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [direct], {"artifact_sha256": artifact_sha256,
                "complete": True, "edges": [direct, intermediate], "failures": [],
                "artifact_entries": [direct["artifact_entry"], intermediate["artifact_entry"]]},
            )
            with open(result["oracle_edges"], encoding="utf-8") as handle:
                oracle_rows = list(csv.DictReader(handle))
            with open(result["edge_reconciliation"], encoding="utf-8") as handle:
                ledger_rows = list(csv.DictReader(handle))

        self.assertTrue(result["blocking"])
        self.assertEqual(result["reconciliation"]["verdict_counts"]["missing"], 1)
        self.assertEqual(len(oracle_rows), 2)
        self.assertEqual(len(ledger_rows), 3)

    def test_fault_injection_drops_analyzer_edge_and_proves_gate_detects_false_negative(self):
        artifact_sha256 = "a" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        edge = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
            instruction_offset=12,
        )
        edge["api_identity"] = realreg.serialized_api_identity(target)
        case = realreg.RealProjectCase(
            name="fault-gated",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=("drop_analyzer_edge",),
        )
        oracle_scan = {
            "artifact_sha256": artifact_sha256,
            "complete": True,
            "edges": [edge],
            "failures": [],
            "artifact_entries": [edge["artifact_entry"]],
        }

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            clean = realreg.reconcile_selected_api_edges(
                report_dir / "clean", [target], [edge], oracle_scan
            )
            injected = realreg.evaluate_required_fault_injections(
                case,
                report_dir,
                [target],
                {**clean, "oracle_scan": oracle_scan},
                analyzer_rows=[edge],
            )
            persisted = json.loads(
                Path(injected["manifest"]).read_text(encoding="utf-8")
            )

        self.assertFalse(clean["blocking"])
        self.assertTrue(injected["passed"], injected)
        self.assertEqual(injected["runs"][0]["mode"], "drop_analyzer_edge")
        self.assertGreaterEqual(
            injected["runs"][0]["verdict_counts"]["missing"], 1
        )
        self.assertEqual(persisted["runs"][0]["removed_occurrence"],
                         realreg.physical_edge_occurrence(edge))

    def test_fault_injection_fails_closed_when_no_analyzer_edge_can_be_removed(self):
        case = realreg.RealProjectCase(
            name="fault-gated",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=("drop_analyzer_edge",),
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.evaluate_required_fault_injections(
                case,
                Path(tmp),
                [],
                {"complete": True, "blocking": False, "oracle_scan": {}},
                analyzer_rows=[],
            )

        self.assertFalse(result["passed"])
        self.assertEqual(result["runs"][0]["error"], "injectable_analyzer_edge_missing")

    def test_fault_injection_registry_detects_extra_wrong_and_oracle_mutations(self):
        artifact_sha256 = "b" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        edge = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class", instruction_offset=12,
        )
        edge["api_identity"] = realreg.serialized_api_identity(target)
        modes = (
            "add_analyzer_edge",
            "wrong_analyzer_descriptor",
            "corrupt_oracle_digest",
            "truncate_oracle_scan",
        )
        case = realreg.RealProjectCase(
            name="fault-registry",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=modes,
        )
        oracle_scan = {
            "artifact_sha256": artifact_sha256,
            "complete": True,
            "edges": [edge],
            "failures": [],
            "artifact_entries": [edge["artifact_entry"]],
        }

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            clean = realreg.reconcile_selected_api_edges(
                report_dir / "clean", [target], [edge], oracle_scan
            )
            with patch.object(
                realreg,
                "detect_oracle_mutation",
                side_effect=AssertionError("self-referential detector must not be used"),
            ):
                injected = realreg.evaluate_required_fault_injections(
                    case,
                    report_dir,
                    [target],
                    {**clean, "oracle_scan": oracle_scan},
                    analyzer_rows=[edge],
                )

        self.assertTrue(injected["passed"], injected)
        by_mode = {run["mode"]: run for run in injected["runs"]}
        self.assertGreater(by_mode["add_analyzer_edge"]["verdict_counts"]["extra"], 0)
        self.assertGreater(
            by_mode["wrong_analyzer_descriptor"]["verdict_counts"]["missing"], 0
        )
        self.assertEqual(
            by_mode["corrupt_oracle_digest"]["detected_signal"], "oracle_invalid"
        )
        self.assertEqual(
            by_mode["truncate_oracle_scan"]["detected_signal"], "oracle_incomplete"
        )

    def test_fault_injection_rejects_unsupported_mode(self):
        case = realreg.RealProjectCase(
            name="fault-gated",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=("invent_edge",),
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.evaluate_required_fault_injections(
                case,
                Path(tmp),
                [],
                {"complete": True, "blocking": False, "oracle_scan": {}},
                analyzer_rows=[],
            )

        self.assertFalse(result["passed"])
        self.assertEqual(
            result["runs"][0]["error"],
            "unsupported_fault_injection:invent_edge",
        )

    def test_failed_required_fault_injection_emits_blocking_quality_signal(self):
        case = realreg.RealProjectCase(
            name="fault-gated",
            default_project=Path("."),
            default_changed_apis=Path("changed.csv"),
            baseline_specs=(),
            required_fault_injections=("drop_analyzer_edge",),
        )

        signals = realreg.build_fault_injection_signals(case, {
            "passed": False,
            "manifest": "/tmp/fault-injection.json",
            "runs": [{
                "mode": "drop_analyzer_edge",
                "passed": False,
                "error": "injected_false_negative_did_not_fail_closed",
            }],
        })

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["signal_type"], "fault_injection_failure")
        self.assertTrue(signals[0]["blocking"])

    def test_edge_truth_preserves_duplicate_physical_oracle_occurrences(self):
        artifact_sha256 = "d" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        first = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
            instruction_offset=12,
        )
        duplicate = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/duplicate.jar!/app/Entry.class",
            instruction_offset=28,
        )
        first["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [first], {
                    "artifact_sha256": artifact_sha256,
                    "complete": True,
                    "edges": [first, duplicate],
                    "failures": [],
                    "artifact_entries": [first["artifact_entry"], duplicate["artifact_entry"]],
                },
            )
            with open(result["oracle_edges"], encoding="utf-8") as handle:
                oracle_rows = list(csv.DictReader(handle))
            with open(result["edge_reconciliation"], encoding="utf-8") as handle:
                ledger_rows = list(csv.DictReader(handle))

        self.assertTrue(result["blocking"])
        self.assertEqual(len(oracle_rows), 2)
        self.assertEqual(result["reconciliation"]["verdict_counts"]["missing"], 1)
        self.assertEqual(
            {row["api_identity"] for row in ledger_rows},
            {realreg.serialized_api_identity(target)},
        )
        self.assertEqual(len({row["physical_occurrence"] for row in ledger_rows}), 2)

    def test_edge_truth_associates_unlabeled_bridge_edge_by_path_identity(self):
        artifact_sha256 = "e" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        direct = self._edge_row(
            artifact_sha256, "bridge.Adapter", "call", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/bridge.jar!/bridge/Adapter.class",
            instruction_offset=7,
        )
        bridge = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "bridge.Adapter", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
            instruction_offset=19,
        )
        direct["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [direct, bridge], {
                    "artifact_sha256": artifact_sha256,
                    "complete": True,
                    "edges": [direct, bridge],
                    "failures": [],
                    "artifact_entries": [direct["artifact_entry"], bridge["artifact_entry"]],
                },
            )

        self.assertFalse(result["blocking"])
        self.assertEqual(result["reconciliation"]["verdict_counts"]["correct"], 4)

    def test_dependency_internal_reference_is_complete_but_not_business_reachable(self):
        artifact_sha256 = "e" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        internal = self._edge_row(
            artifact_sha256, "vendor.Internal", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/vendor.jar!/vendor/Internal.class",
        )
        internal["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [internal], {
                    "artifact_sha256": artifact_sha256,
                    "complete": True,
                    "edges": [internal],
                    "failures": [],
                    "artifact_entries": [internal["artifact_entry"]],
                },
            )

        identity = realreg.serialized_api_identity(target)
        self.assertTrue(result["complete"])
        self.assertFalse(result["blocking"])
        self.assertEqual(result["api_reachability"][identity], "uncertain")
        self.assertNotIn(
            f"selected_api_unreached_business_boundary:{identity}",
            result["errors"],
        )

    def test_class_api_is_not_misrepresented_as_an_executable_member_target(self):
        targets = realreg._oracle_selected_targets([{
            "api_name": "com.vendor.OptionalSecurityType",
            "api_signature": "",
            "symbol_kind": "class",
        }])

        self.assertEqual(targets, [])

    def test_final_artifact_dynamic_class_oracle_requires_loader_and_exact_name(self):
        target = {
            "coord": "com.vendor:security-api",
            "api_name": "com.vendor.OptionalSecurityType",
            "api_signature": "",
            "symbol_kind": "class",
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/app/SecurityModule.class",
                    minimal_classfile_with_utf8(
                        "com.vendor.OptionalSecurityType",
                        "org/apache/dubbo/common/utils/ClassUtils",
                        "forName",
                    ),
                )
                archive.writestr(
                    "BOOT-INF/classes/app/Unrelated.class",
                    minimal_classfile_with_utf8("com.vendor.OptionalSecurityType"),
                )
                archive.writestr(
                    "BOOT-INF/classes/app/Invalid.class",
                    b"com.vendor.OptionalSecurityType\x00ClassUtils\x00forName",
                )

            references = realreg.scan_final_artifact_dynamic_class_references(
                artifact, [target]
            )

        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["api_identity"], realreg.serialized_api_identity(target))
        self.assertEqual(references[0]["artifact_entry"], "BOOT-INF/classes/app/SecurityModule.class")
        self.assertEqual(references[0]["authority"], "final-artifact-classfile-constants")

    def test_dynamic_class_semantic_reference_resolves_oracle_as_uncertain(self):
        artifact_sha256 = "a" * 64
        target = {
            "coord": "com.vendor:security-api",
            "api_name": "com.vendor.OptionalSecurityType",
            "api_signature": "",
            "symbol_kind": "class",
        }
        identity = realreg.serialized_api_identity(target)
        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [], {
                    "artifact_sha256": artifact_sha256,
                    "complete": True,
                    "edges": [],
                    "failures": [],
                    "artifact_entries": ["BOOT-INF/classes/app/SecurityModule.class"],
                    "semantic_references": [{
                        "api_identity": identity,
                        "artifact_entry": "BOOT-INF/classes/app/SecurityModule.class",
                    }],
                },
            )

        self.assertTrue(result["complete"])
        self.assertFalse(result["blocking"])
        self.assertEqual(result["api_reachability"][identity], "uncertain")

    def test_pinned_guard_accepts_uncertain_class_with_canonical_semantic_reference(self):
        target = {
            "coord": "com.vendor:security-api",
            "api_name": "com.vendor.OptionalSecurityType",
            "api_signature": "",
            "symbol_kind": "class",
            "change_type": "REMOVED",
        }
        identity = realreg.serialized_api_identity(target)
        semantic = {
            "api_identity": identity,
            "target_class": target["api_name"],
            "artifact_sha256": "a" * 64,
            "artifact_entry": "app/SecurityModule.class",
            "authority": "final-artifact-classfile-constants",
        }
        manifest = {
            "required_topologies": ["reflection"],
            "apis": [{
                "owner": target["api_name"],
                "member": "",
                "symbol_kind": "class",
                "expected_conclusion": "uncertain",
                "expected_chain": ["app.SecurityModule.setup", target["api_name"]],
            }],
            "canonical_edges": [],
            "canonical_semantic_references": [semantic],
        }
        result = {
            "summary": {
                "uncertain_apis": [{
                    "api_name": target["api_name"],
                    "coord": target["coord"],
                    "symbol_kind": target["symbol_kind"],
                    "analysis_status": "uncertain",
                    "call_paths": [
                        f"app.SecurityModule.setup -> {target['api_name']}"
                    ],
                }],
            },
            "topology_coverage": {"complete": True, "observed": ["reflection"]},
            "edge_truth": {
                "complete": True, "blocking": False, "ledger": [],
                "semantic_references": [semantic],
            },
        }

        evaluation = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertTrue(evaluation["passed"], evaluation["errors"])

    def test_final_artifact_oracle_records_preserve_per_api_reachability(self):
        reachable = {
            "coord": "vendor:api", "api_name": "vendor.Api.call",
            "api_signature": "()", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        internal = {
            "coord": "vendor:api", "api_name": "vendor.Api.internal",
            "api_signature": "()", "symbol_kind": "method",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "oracle_edges.csv"
            evidence.write_text("header\nvalue\n", encoding="utf-8")
            records = realreg.build_final_artifact_api_oracle_records(
                [reachable, internal],
                {
                    "complete": True,
                    "oracle_edges": str(evidence),
                    "api_reachability": {
                        realreg.serialized_api_identity(reachable): "reachable",
                        realreg.serialized_api_identity(internal): "uncertain",
                    },
                },
            )

        self.assertEqual(
            {row["api_name"]: row["oracle_conclusion"] for row in records},
            {"vendor.Api.call": "reachable", "vendor.Api.internal": "uncertain"},
        )
        self.assertTrue(all(row["authority"] == "final-artifact-classfile" for row in records))
        self.assertEqual(records[0]["change_type"], "REMOVED")
        self.assertTrue(all(len(row["evidence_sha256"]) == 64 for row in records))

    def test_final_artifact_oracle_records_include_authoritative_absence(self):
        absent = {
            "coord": "vendor:api", "api_name": "vendor.Api.removed",
            "api_signature": "()", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "oracle_edges.csv"
            evidence.write_text("header\n", encoding="utf-8")
            records = realreg.build_final_artifact_api_oracle_records(
                [absent],
                {
                    "complete": True,
                    "oracle_edges": str(evidence),
                    "api_reachability": {
                        realreg.serialized_api_identity(absent):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["oracle_conclusion"], "not_found_in_static_analysis"
        )

    def test_final_artifact_oracle_treats_compile_time_constant_absence_as_uncertain(self):
        constant = {
            "coord": "vendor:api", "api_name": "vendor.Flags.EMPTY",
            "api_signature": "", "symbol_kind": "field",
            "change_type": "REMOVED", "compatibility_flags": "CONSTANT_REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "oracle_edges.csv"
            evidence.write_text("header\n", encoding="utf-8")
            records = realreg.build_final_artifact_api_oracle_records(
                [constant],
                {
                    "complete": True,
                    "oracle_edges": str(evidence),
                    "api_reachability": {
                        realreg.serialized_api_identity(constant):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(records[0]["oracle_conclusion"], "uncertain")
        self.assertIn("compile-time constant", records[0]["procedure"])

    def test_final_artifact_oracle_reports_compile_and_runtime_constant_impacts(self):
        constant = {
            "coord": "vendor:api", "api_name": "vendor.Flags.EMPTY",
            "api_signature": "", "symbol_kind": "field",
            "change_type": "REMOVED", "compatibility_flags": "CONSTANT_REMOVED",
            "old_field_has_constant_value": True,
            "source_reference_present": True,
            "source_artifact_aligned": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "oracle_edges.csv"
            evidence.write_text("header\n", encoding="utf-8")
            records = realreg.build_final_artifact_api_oracle_records(
                [constant],
                {
                    "complete": True,
                    "oracle_edges": str(evidence),
                    "api_reachability": {
                        realreg.serialized_api_identity(constant):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(records[0]["compile_impact"], "recompile_break")
        self.assertEqual(records[0]["runtime_link_impact"], "inlined_no_link")
        self.assertTrue(records[0]["constant_impact_evidence"]["source_reference_present"])

    def test_constant_impact_parses_false_string_evidence_as_false(self):
        constant = {
            "coord": "vendor:api", "api_name": "vendor.Flags.EMPTY",
            "api_signature": "", "symbol_kind": "field",
            "change_type": "REMOVED", "compatibility_flags": "CONSTANT_REMOVED",
            "old_field_has_constant_value": "false",
            "source_reference_present": "false",
            "source_artifact_aligned": "false",
        }

        record = realreg._constant_impact_record(constant, "uncertain")

        self.assertEqual(record["compile_impact"], "unverified")
        self.assertFalse(
            record["constant_impact_evidence"]["old_field_has_constant_value"]
        )
        self.assertFalse(
            record["constant_impact_evidence"]["source_reference_present"]
        )

    def test_constant_impact_is_unverified_without_independent_source_evidence(self):
        constant = {
            "coord": "vendor:api", "api_name": "vendor.Flags.EMPTY",
            "api_signature": "", "symbol_kind": "field",
            "change_type": "REMOVED", "compatibility_flags": "CONSTANT_REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "oracle_edges.csv"
            evidence.write_text("header\n", encoding="utf-8")
            records = realreg.build_final_artifact_api_oracle_records(
                [constant],
                {
                    "complete": True,
                    "oracle_edges": str(evidence),
                    "api_reachability": {
                        realreg.serialized_api_identity(constant): "uncertain",
                    },
                },
            )

        self.assertEqual(records[0]["compile_impact"], "unverified")
        self.assertEqual(records[0]["runtime_link_impact"], "unverified")

    def test_constant_pool_oracle_records_are_a_distinct_member_authority(self):
        absent = {
            "coord": "vendor:api", "api_name": "vendor.Api.removed",
            "api_signature": "()", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "member-references.json"
            evidence.write_text("[]\n", encoding="utf-8")
            records = realreg.build_constant_pool_api_oracle_records(
                [absent],
                {
                    "complete": True,
                    "member_reference_evidence": str(evidence),
                    "member_reference_reachability": {
                        realreg.serialized_api_identity(absent):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["authority"], "raw-classfile-constant-pool")
        self.assertEqual(records[0]["change_type"], "REMOVED")
        self.assertEqual(records[0]["oracle_conclusion"], "not_found_in_static_analysis")

    def test_constant_pool_oracle_treats_compile_time_constant_absence_as_uncertain(self):
        constant = {
            "coord": "vendor:api", "api_name": "vendor.Flags.EMPTY",
            "api_signature": "", "symbol_kind": "field",
            "change_type": "REMOVED", "compatibility_flags": "CONSTANT_REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "member-references.json"
            evidence.write_text("[]\n", encoding="utf-8")
            records = realreg.build_constant_pool_api_oracle_records(
                [constant],
                {
                    "complete": True,
                    "member_reference_evidence": str(evidence),
                    "member_reference_reachability": {
                        realreg.serialized_api_identity(constant):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(records[0]["oracle_conclusion"], "uncertain")
        self.assertIn("compile-time constant", records[0]["procedure"])

    def test_jdeps_oracle_records_are_a_distinct_class_authority(self):
        target = {
            "coord": "vendor:api", "api_name": "vendor.RemovedType",
            "api_signature": "", "symbol_kind": "class",
            "change_type": "REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "jdeps-references.json"
            evidence.write_text("[]\n", encoding="utf-8")
            records = realreg.build_jdeps_api_oracle_records(
                [target],
                {
                    "complete": True,
                    "jdeps_class_reference_evidence": str(evidence),
                    "jdeps_class_reachability": {
                        realreg.serialized_api_identity(target):
                            "not_found_in_static_analysis",
                    },
                },
            )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["authority"], "jdk-jdeps")
        self.assertEqual(records[0]["change_type"], "REMOVED")

    def test_final_artifact_class_reference_oracle_uses_packaged_constant_pool(self):
        selected = [{
            "coord": "vendor:api", "api_name": "vendor.RemovedType",
            "api_signature": "", "symbol_kind": "class", "change_type": "REMOVED",
        }]
        identity = realreg.serialized_api_identity(selected[0])
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/demo/App.class",
                    minimal_classfile_with_utf8("vendor/RemovedType"),
                )

            result = realreg.scan_final_artifact_class_references(
                artifact, selected
            )

        self.assertTrue(result["complete"])
        self.assertEqual(result["api_reachability"][identity], "reachable")
        self.assertEqual(result["references"][0]["artifact_entry"], "BOOT-INF/classes/demo/App.class")

    def test_final_artifact_member_reference_oracle_parses_exact_constant_pool_reference(self):
        selected = [{
            "coord": "vendor:api", "api_name": "vendor.Api.call",
            "api_signature": "(java.lang.String)", "symbol_kind": "method",
            "change_type": "REMOVED",
        }]
        identity = realreg.serialized_api_identity(selected[0])
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/demo/App.class",
                    minimal_classfile_with_methodref(
                        "vendor/Api", "call", "(Ljava/lang/String;)V"
                    ),
                )

            result = realreg.scan_final_artifact_member_references(
                artifact, selected
            )

        self.assertTrue(result["complete"])
        self.assertEqual(result["api_reachability"][identity], "reachable")
        self.assertEqual(result["references"][0]["callee_member"], "call")

    def test_analyzer_path_cannot_import_an_edge_labeled_for_another_api(self):
        artifact_sha256 = "e" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        direct = self._edge_row(
            artifact_sha256, "bridge.Adapter", "call", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/bridge.jar!/bridge/Adapter.class",
        )
        contaminated = self._edge_row(
            artifact_sha256, "other.Entry", "run", "()V",
            "bridge.Adapter", "call", "()V", "invokestatic",
            "BOOT-INF/classes/other/Entry.class",
        )
        direct["api_identity"] = realreg.serialized_api_identity(target)
        contaminated["api_identity"] = "different-api-identity"

        retained = realreg._retain_analyzer_api_path(
            [target], [direct, contaminated]
        )

        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0]["caller_owner"], "bridge.Adapter")

    def test_edge_truth_rejects_caller_owner_that_disagrees_with_artifact_entry(self):
        artifact_sha256 = "f" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        malformed = self._edge_row(
            artifact_sha256, "Lapp", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
        )
        malformed["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [malformed], {
                    "artifact_sha256": artifact_sha256,
                    "complete": True,
                    "edges": [malformed],
                    "failures": [],
                    "artifact_entries": [malformed["artifact_entry"]],
                },
            )

        self.assertFalse(result["complete"])
        self.assertTrue(result["blocking"])
        self.assertTrue(any(
            error.startswith("oracle_caller_owner_artifact_entry_mismatch:")
            for error in result["errors"]
        ))

    def test_source_bytecode_conflict_rejects_stale_or_fabricated_final_evidence(self):
        artifact_sha256 = "f" * 64
        oracle_edge = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
            instruction_offset=23,
        )
        edge_truth = {
            "complete": True,
            "trusted_artifact_sha": artifact_sha256,
            "oracle_physical_occurrences": [realreg.physical_edge_occurrence(oracle_edge)],
        }
        source_edge = {
            field: oracle_edge[field]
            for field in realreg.EDGE_COMPARISON_FIELDS
        }
        for label, final_edge, expected_error in (
            ("stale", {**oracle_edge, "artifact_sha256": "a" * 64}, "final_artifact_sha_mismatch"),
            ("fabricated", {**oracle_edge, "callee_member": "invented"}, "final_artifact_oracle_identity_missing"),
        ):
            with self.subTest(evidence=label):
                result = realreg.validate_source_bytecode_conflicts({
                    "uncertain_apis": [{
                        "reason_code": "SOURCE_BYTECODE_EDGE_CONFLICT",
                        "source_revision_provenance": {"valid": True, "git_revision": "abc123"},
                        "normalized_source_edge": source_edge,
                        "normalized_final_artifact_edge": final_edge,
                    }]
                }, edge_truth)

                self.assertFalse(result["valid"])
                self.assertTrue(any(expected_error in error for error in result["errors"]))

    def test_edge_truth_extra_path_that_creates_false_reachability_is_blocking(self):
        artifact_sha256 = "b" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        direct = self._edge_row(
            artifact_sha256, "bridge.Adapter", "call", "()V",
            "vendor.Api", "call", "()V", "invokestatic",
            "BOOT-INF/lib/bridge.jar!/bridge/Adapter.class",
        )
        direct["api_identity"] = realreg.serialized_api_identity(target)
        invented = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "bridge.Adapter", "call", "()V", "invokestatic",
            "BOOT-INF/classes/app/Entry.class",
        )
        invented["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [direct, invented], {"artifact_sha256": artifact_sha256,
                "complete": True, "edges": [direct], "failures": [],
                "artifact_entries": [direct["artifact_entry"], invented["artifact_entry"]]},
            )

        self.assertTrue(result["blocking"])
        self.assertEqual(result["reconciliation"]["verdict_counts"]["extra"], 1)

    def test_edge_truth_matches_constructor_api_using_its_owner_name(self):
        artifact_sha256 = "c" * 64
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api",
            "api_signature": "()",
            "symbol_kind": "constructor",
            "change_type": "REMOVED",
        }
        constructor = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "<init>", "()V", "invokespecial",
            "BOOT-INF/classes/app/Entry.class",
        )
        constructor["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [constructor], {"artifact_sha256": artifact_sha256,
                "complete": True, "edges": [constructor], "failures": [],
                "artifact_entries": [constructor["artifact_entry"]]},
            )

        self.assertTrue(result["complete"])
        self.assertFalse(result["blocking"])
        self.assertEqual(result["reconciliation"]["verdict_counts"]["correct"], 2)

    def test_edge_truth_matches_constructor_api_with_repeated_simple_class_name(self):
        target = {
            "coord": "vendor:api",
            "api_name": "vendor.Api.Api",
            "api_signature": "()",
            "symbol_kind": "constructor",
            "change_type": "REMOVED",
        }
        edge = self._edge_row(
            "c" * 64, "app.Entry", "run", "()V",
            "vendor.Api", "<init>", "()V", "invokespecial",
            "BOOT-INF/classes/app/Entry.class",
        )

        self.assertTrue(realreg._api_target_matches(target, edge))

    def test_oracle_target_selection_normalizes_repeated_constructor_name(self):
        targets = realreg._oracle_selected_targets([{
            "api_name": "vendor.Api.Api",
            "symbol_kind": "constructor",
        }])

        self.assertEqual(targets, [{
            "owner": "vendor.Api", "member": "<init>", "descriptor": "",
        }])

    def test_edge_truth_accepts_plain_jar_root_class_as_business_boundary(self):
        artifact_sha256 = "d" * 64
        target = {
            "coord": "vendor:api", "api_name": "vendor.Api.call",
            "api_signature": "()", "symbol_kind": "method", "change_type": "REMOVED",
        }
        edge = self._edge_row(
            artifact_sha256, "app.Entry", "run", "()V",
            "vendor.Api", "call", "()V", "invokestatic", "app/Entry.class",
            instruction_offset=4,
        )
        edge["api_identity"] = realreg.serialized_api_identity(target)

        with tempfile.TemporaryDirectory() as tmp:
            result = realreg.reconcile_selected_api_edges(
                Path(tmp), [target], [edge], {
                    "artifact_sha256": artifact_sha256, "complete": True,
                    "edges": [edge], "failures": [], "artifact_entries": ["app/Entry.class"],
                },
            )

        self.assertTrue(result["complete"])
        self.assertFalse(result["blocking"])

    def test_invalid_source_bytecode_conflict_requires_source_identity_and_revision_provenance(self):
        result = realreg.validate_source_bytecode_conflicts({
            "uncertain_apis": [{
                "reason_code": "SOURCE_BYTECODE_EDGE_CONFLICT",
                "source_edge": {"caller_owner": "app.Entry"},
                "final_artifact_edge": {"caller_owner": "app.Entry"},
            }]
        })

        self.assertFalse(result["valid"])
        self.assertEqual(result["invalid_count"], 1)
        self.assertIn("source_revision_provenance_missing", result["errors"][0])

    @staticmethod
    def _edge_row(
        artifact_sha256, caller_owner, caller_member, caller_descriptor,
        callee_owner, callee_member, callee_descriptor, opcode_family, artifact_entry,
        instruction_offset="",
    ):
        return {
            "artifact_sha256": artifact_sha256,
            "artifact_entry": artifact_entry,
            "caller_owner": caller_owner,
            "caller_member": caller_member,
            "caller_descriptor": caller_descriptor,
            "callee_owner": callee_owner,
            "callee_member": callee_member,
            "callee_descriptor": callee_descriptor,
            "opcode_family": opcode_family,
            "instruction_offset": instruction_offset,
            "authority": "jdk-javap",
            "authority_version": "21",
            "procedure": "test oracle",
        }

    def test_quality_signals_separate_not_analyzed_reason_groups(self):
        case = realreg.RealProjectCase("dubbo", Path("."), Path(""), ())
        summary = {
            "not_analyzed": 3,
            "not_analyzed_apis": [
                {"api": "a.A.one", "reason_code": "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "symbol_kind": "method"},
                {"api": "a.A.two", "reason_code": "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "symbol_kind": "method"},
                {"api": "a.B.B", "reason_code": "OVERLOAD_AMBIGUOUS_TARGET", "symbol_kind": "constructor"},
            ],
        }

        signals = realreg.build_quality_signals(
            case,
            summary=summary,
            checks=[],
            failures=[],
            result_audit={},
            report_dir=Path("/tmp/report"),
        )

        gaps = [item for item in signals if item["signal_type"] == "conclusion_gap"]
        self.assertEqual(len(gaps), 2)
        self.assertEqual({item["reason_code"] for item in gaps}, {
            "RUNTIME_DEPENDENCY_JARS_UNAVAILABLE", "OVERLOAD_AMBIGUOUS_TARGET"
        })

    def test_policy_signals_gate_discovery_coverage_ground_truth_and_performance(self):
        case = realreg.RealProjectCase(
            "dubbo", Path("."), Path(""), (), case_mode="discovery",
            ground_truth_status="unreviewed", max_potential_pairs_per_api=100.0,
        )
        signals = realreg.build_policy_signals(
            case,
            coverage=realreg.compute_api_coverage("discovery", 5440, 9, 9),
            performance={"potential_pairs_per_api": 200.0},
            report_dir=Path("/tmp/report"),
        )

        self.assertEqual({item["signal_type"] for item in signals}, {
            "coverage_gap", "ground_truth_insufficient", "performance_regression"
        })
        self.assertTrue(all(item["blocking"] for item in signals))

    def test_policy_ground_truth_signal_uses_exhaustive_oracle_counts(self):
        case = realreg.RealProjectCase(
            "dubbo", Path("."), Path(""), (), case_mode="discovery",
            ground_truth_status="unreviewed",
        )
        signals = realreg.build_policy_signals(
            case,
            coverage=realreg.compute_api_coverage("discovery", 2, 2, 2),
            performance={},
            report_dir=Path("/tmp/report"),
            oracle_audit={"selected": 2, "verified": 0, "unverified": 2, "incorrect": 0, "oracle_conflicts": 0},
        )

        signal = next(item for item in signals if item["signal_type"] == "ground_truth_insufficient")
        self.assertEqual(signal["count"], 2)
        self.assertIn("verified=0/2", signal["message"])

    def test_policy_emits_correctness_failure_for_third_party_disagreement(self):
        case = realreg.RealProjectCase(
            "dubbo", Path("."), Path(""), (), case_mode="discovery",
            ground_truth_status="unreviewed",
        )
        signals = realreg.build_policy_signals(
            case,
            coverage=realreg.compute_api_coverage("discovery", 2, 2, 2),
            performance={},
            report_dir=Path("/tmp/report"),
            oracle_audit={
                "selected": 2, "verified": 1, "unverified": 0,
                "incorrect": 1, "oracle_conflicts": 0, "blocking": True,
            },
        )

        correctness = next(item for item in signals if item["signal_type"] == "correctness_failure")
        self.assertEqual(correctness["count"], 1)
        self.assertIn("third-party oracle disagrees", correctness["message"])

    def _write_readable_alerts(self, path, symbol, evidence_file, signature="(String)", path_status="reachable"):
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "conclusion",
            "change_summary",
            "review_reason",
            "chain_summary",
            "chain_entry",
            "chain_target",
            "chain_hop_count",
            "chain_detail",
            "changed_symbol",
            "api_signature",
            "symbol_kind",
            "path_status",
            "path_text",
            "evidence_files",
        ]
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerow({
                "conclusion": (
                    "已确认影响：已找到业务入口到变更 API 的完整调用链"
                    if path_status == "reachable" else "需要人工复核"
                ),
                "change_summary": f"删除方法，{symbol.rsplit('.', 1)[-1]}，参数：{signature.strip('()') or '无参数'}，严重级别：P1",
                "review_reason": "已找到从系统代码到变更 API 的调用链",
                "chain_summary": f"入口：demo.App.run；终点：{symbol}{signature}；1 跳",
                "chain_entry": "demo.App.run",
                "chain_target": f"{symbol}{signature}",
                "chain_hop_count": "1",
                "chain_detail": f"1. demo.App.run -> 2. {symbol}{signature}",
                "changed_symbol": symbol,
                "api_signature": signature,
                "symbol_kind": "method",
                "path_status": path_status,
                "path_text": f"demo.App.run -> {symbol}{signature}",
                "evidence_files": str(evidence_file),
            })

    def test_collect_alert_files_matches_rendered_signature_and_report_relative_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_file = root / "project/src/main/java/demo/App.java"
            project_file.parent.mkdir(parents=True)
            project_file.write_text("class App {}\n", encoding="utf-8")
            alerts = root / "report/evidence/call_chain/alerts.csv"
            relative_evidence = Path("../../../project/src/main/java/demo/App.java")
            self._write_readable_alerts(
                alerts,
                "vendor.Api.call(java.lang.String)",
                relative_evidence,
                signature="(java.lang.String)",
            )

            files = realreg.collect_alert_files(alerts, "vendor.Api.call")

            self.assertEqual(files, {str(project_file.resolve())})

    def test_collect_alert_files_maps_final_artifact_consumer_class_to_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_file = root / "src/main/java/org/example/App.java"
            project_file.parent.mkdir(parents=True)
            project_file.write_text(
                "package org.example; class App {}\n", encoding="utf-8"
            )
            alerts = root / "report/evidence/call_chain/alerts.csv"
            alerts.parent.mkdir(parents=True)
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "changed_symbol", "api_signature", "symbol_kind",
                    "evidence_files", "consumer_class",
                ])
                writer.writeheader()
                writer.writerow({
                    "changed_symbol": "vendor.Api.call()",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "evidence_files": "../../business-classes.jar",
                    "consumer_class": "org.example.App$Nested",
                })

            files = realreg.collect_alert_files(
                alerts, "vendor.Api.call", project_root=root
            )

        self.assertEqual(files, {str(project_file.resolve())})

    def test_bytecode_materialization_selects_nested_dependency_from_target_coordinate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            nested_jar = io.BytesIO()
            with zipfile.ZipFile(nested_jar, "w") as nested:
                nested.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class")
                archive.writestr(
                    "BOOT-INF/lib/dubbo-demo-spring-boot-interface-3.3.7-SNAPSHOT.jar",
                    nested_jar.getvalue(),
                )
                archive.writestr("BOOT-INF/lib/unrelated-1.0.jar", nested_jar.getvalue())
            case = realreg.RealProjectCase(
                name="dubbo-fatjar",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("org/apache/dubbo/springboot/demo/DemoService",),
                bytecode_coord="org.apache.dubbo:dubbo-demo-spring-boot-interface",
                final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            _, rows = realreg._csv_rows(
                report / "evidence/dependencies/deps_current_resolved.csv"
            )
            self.assertEqual(
                rows[0]["lib_entry"],
                "BOOT-INF/lib/dubbo-demo-spring-boot-interface-3.3.7-SNAPSHOT.jar",
            )
            self.assertEqual(rows[0]["resolution_status"], "resolved")
            self.assertEqual(
                {row["lib_entry"] for row in rows},
                {
                    "BOOT-INF/lib/dubbo-demo-spring-boot-interface-3.3.7-SNAPSHOT.jar",
                    "BOOT-INF/lib/unrelated-1.0.jar",
                },
            )

    def test_bytecode_materialization_does_not_record_absent_target_as_resolved_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "thin-library.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("demo/App.class", b"class")
            case = realreg.RealProjectCase(
                name="thin-reflection",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_coord="vendor:removed-api",
                final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            _, rows = realreg._csv_rows(
                report / "evidence/dependencies/deps_current_resolved.csv"
            )

        self.assertEqual(rows, [])

    def test_declared_final_artifact_is_bound_to_verified_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("demo/App.class", b"class")
            case = realreg.RealProjectCase(
                name="fixed-api-final-artifact",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_coord="demo:application",
                final_artifact=artifact,
            )
            report = root / "report"

            realreg.write_declared_final_artifact_provenance(report, case)

            provenance = json.loads(
                (report / "evidence/dependencies/build_provenance.json").read_text(
                    encoding="utf-8"
                )
            )
            current = provenance["sides"][0]
            expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            verified_artifact, verified_sha, errors = (
                realreg._verified_current_final_artifact(report)
            )

        self.assertEqual(current["authority"], "local-final-artifact")
        self.assertEqual(current["artifact_sha256"], expected_sha)
        self.assertEqual(verified_artifact, artifact)
        self.assertEqual(verified_sha, expected_sha)
        self.assertEqual(errors, [])

    def test_bytecode_materialization_preserves_explicit_changed_api_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class")
            explicit = root / "selected.csv"
            explicit.write_text("api_name\ncn.hutool.StrUtil.isEmpty\n", encoding="utf-8")
            case = realreg.RealProjectCase(
                name="explicit", default_project=root, default_changed_apis=Path(""),
                baseline_specs=(), bytecode_owner_prefixes=("cn/hutool/",),
                bytecode_coord="cn.hutool:hutool-all", final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]) as discover:
                selected = realreg.materialize_bytecode_changed_apis(
                    case, root, report, selected_changed_apis=explicit
                )

        self.assertEqual(selected, explicit)
        discover.assert_not_called()

    def test_bytecode_materialization_discovers_business_classes_from_plain_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "library.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "org/example/security/SecurityBridge.class",
                    b"class-bytes org/springframework/security/core/Authentication",
                )
                archive.writestr(
                    "META-INF/versions/17/org/example/security/SecurityBridge.class",
                    b"versioned-class-bytes",
                )
                archive.writestr("module-info.class", b"module")
            case = realreg.RealProjectCase(
                name="plain-jar",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("org/springframework/security/",),
                bytecode_coord="org.springframework.security:spring-security-core",
                final_artifact=artifact,
            )
            captured = []

            def capture(class_files, **_kwargs):
                captured.extend(class_files)
                return []

            report = root / "report"
            with patch.object(realreg, "discover_calls", side_effect=capture):
                realreg.materialize_bytecode_changed_apis(case, root, report)

        self.assertEqual(
            [path.relative_to(path.parents[3]).as_posix() for path in captured],
            ["org/example/security/SecurityBridge.class"],
        )

    def test_output_audit_rejects_explicit_source_provenance_for_reachable_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            with changed.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["api_name", "api_signature", "symbol_kind"]
                )
                writer.writeheader()
                writer.writerow({
                    "api_name": "lib.Api.call", "api_signature": "()", "symbol_kind": "method",
                })
            self._write_readable_alerts(alerts, "lib.Api.call()", Path("App.java"))
            summary = {
                "total_apis": 1,
                "reachable_apis": [{
                    "evidence_paths": [[{
                        "evidence_type": "constructor_delegation",
                        "evidence_source": "source_worktree",
                    }]],
                }],
            }

            audit = realreg.audit_analysis_outputs(changed, alerts, summary)

        self.assertIn("source_edges_in_final_artifact_paths:1", audit["failures"])

    def test_bytecode_discovery_includes_nested_jar_bridge_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "bridge.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr(
                    "bridge/InternalBridge.class",
                    b"class-bytes org/apache/dubbo/springboot/demo/DemoService",
                )
                archive.writestr("bridge/Unrelated.class", b"class-bytes")
            artifact = root / "application.jar"
            provider = root / "interface.jar"
            with zipfile.ZipFile(provider, "w") as archive:
                archive.writestr(
                    "org/apache/dubbo/springboot/demo/DemoService.class",
                    b"class-bytes org/apache/dubbo/springboot/demo/DemoService",
                )
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class")
                archive.writestr("BOOT-INF/lib/bridge-1.0.jar", nested.read_bytes())
                archive.writestr("BOOT-INF/lib/interface-1.0.jar", provider.read_bytes())
            case = realreg.RealProjectCase(
                name="nested-bridge",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("org/apache/dubbo/springboot/demo/DemoService",),
                bytecode_coord="org.apache.dubbo:interface",
                final_artifact=artifact,
            )
            captured = []

            def capture(class_files, **_kwargs):
                captured.extend(class_files)
                return []

            report = root / "report"
            artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            stale = (
                report / ".runtime" / "final-artifact-classes" / artifact_sha[:16]
                / "nested" / "stale" / "org" / "apache" / "dubbo" / "springboot"
                / "demo" / "DemoService.class"
            )
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale provider cache")
            with patch.object(realreg, "discover_calls", side_effect=capture):
                realreg.materialize_bytecode_changed_apis(case, root, report)
            _, runtime_rows = realreg._csv_rows(
                report / "evidence/dependencies/deps_current_resolved.csv"
            )

        self.assertTrue(any("InternalBridge.class" in str(path) for path in captured))
        self.assertFalse(any("Unrelated.class" in str(path) for path in captured))
        self.assertFalse(any("DemoService.class" in str(path) for path in captured))
        self.assertTrue(any(
            row["coord"] == "runtime:bridge-1.0"
            and row["lib_entry"] == "BOOT-INF/lib/bridge-1.0.jar"
            for row in runtime_rows
        ))

    def test_materialized_class_inventory_excludes_stale_provider_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"business")
            case = realreg.RealProjectCase(
                name="inventory",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("vendor/Api",),
                bytecode_coord="vendor:api",
                final_artifact=artifact,
            )
            report = root / "report"
            artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
            stale = (
                report / ".runtime" / "final-artifact-classes" / artifact_sha[:16]
                / "nested" / "stale" / "vendor" / "Api.class"
            )
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            class_files = realreg.load_materialized_class_inventory(report, artifact)

        self.assertEqual([path.name for path in class_files], ["App.class"])
        self.assertNotIn(stale, class_files)

    def test_bytecode_materialization_writes_artifact_java_version_for_multi_release_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nJava-Version: 17\nBuild-Jdk-Spec: 24\n",
                )
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class")
            case = realreg.RealProjectCase(
                name="jdk-context", default_project=root, default_changed_apis=Path(""),
                baseline_specs=(), bytecode_owner_prefixes=("vendor/Api",),
                bytecode_coord="vendor:api", final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            context = json.loads(
                (report / "evidence/context/context.json").read_text(encoding="utf-8")
            )

        self.assertEqual(context["jdk_current"], "17")

    def test_bytecode_materialization_infers_java_version_from_business_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            class_header = b"\xca\xfe\xba\xbe\x00\x00\x00="
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nBuild-Jdk-Spec: 24\n",
                )
                archive.writestr("BOOT-INF/classes/demo/App.class", class_header)
            case = realreg.RealProjectCase(
                name="classfile-jdk-context", default_project=root,
                default_changed_apis=Path(""), baseline_specs=(),
                bytecode_owner_prefixes=("vendor/Api",),
                bytecode_coord="vendor:api", final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            context = json.loads(
                (report / "evidence/context/context.json").read_text(encoding="utf-8")
            )

        self.assertEqual(context["jdk_current"], "17")

    def test_bytecode_materialization_rejects_ambiguous_artifact_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application.jar"
            nested_jar = io.BytesIO()
            with zipfile.ZipFile(nested_jar, "w") as nested:
                nested.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class")
                archive.writestr("BOOT-INF/lib/dubbo-3.3.7.jar", nested_jar.getvalue())
                archive.writestr(
                    "BOOT-INF/lib/dubbo-common-3.3.7.jar", nested_jar.getvalue()
                )
            case = realreg.RealProjectCase(
                name="ambiguous",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("org/apache/dubbo/",),
                bytecode_coord="org.apache.dubbo:dubbo",
                final_artifact=artifact,
            )
            report = root / "report"

            with patch.object(realreg, "discover_calls", return_value=[]):
                realreg.materialize_bytecode_changed_apis(case, root, report)

            _, rows = realreg._csv_rows(
                report / "evidence/dependencies/deps_current_resolved.csv"
            )
            self.assertEqual(rows[0]["lib_entry"], "")
            self.assertEqual(rows[0]["resolution_status"], "unresolved")

    def test_collect_source_shape_metrics_counts_files_and_occurrences(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src/main/java/demo/App.java"
            src.parent.mkdir(parents=True)
            src.write_text(
                "\n".join(
                    [
                        "import static org.apache.dubbo.common.utils.StringUtils.isBlank;",
                        "class App {",
                        "  void run() { Runnable r = () -> {}; Class.forName(\"demo.X\"); }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            metrics = realreg.collect_source_shape_metrics(
                root,
                {
                    "static_stringutils_import": r"import\s+static\s+org\.apache\.dubbo\.common\.utils\.StringUtils\.",
                    "lambda_expression": r"->",
                    "class_for_name": r"\bClass\.forName\s*\(",
                },
            )

        self.assertEqual(metrics["static_stringutils_import"], {"files": 1, "occurrences": 1})
        self.assertEqual(metrics["lambda_expression"], {"files": 1, "occurrences": 1})
        self.assertEqual(metrics["class_for_name"], {"files": 1, "occurrences": 1})

    def test_collect_baseline_files_can_filter_by_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            included = root / "src/main/java/demo/Included.java"
            excluded = root / "src/main/java/demo/Excluded.java"
            included.parent.mkdir(parents=True)
            content = (
                "import org.apache.commons.lang3.ArrayUtils;\n"
                "class X { boolean x(char[] chars) { return ArrayUtils.isEmpty(chars); } }\n"
            )
            included.write_text(content, encoding="utf-8")
            excluded.write_text(content, encoding="utf-8")

            production, tests, occurrences = realreg.collect_baseline_files(
                root,
                realreg.BaselineSpec(
                    symbol="org.apache.commons.lang3.ArrayUtils.isEmpty",
                    pattern=r"\bArrayUtils\s*\.\s*isEmpty\s*\(\s*chars\s*\)",
                    import_pattern=r"import\s+org\.apache\.commons\.lang3\.ArrayUtils\s*;",
                    file_path_pattern=r"Included\.java$",
                ),
            )

        self.assertEqual(occurrences, 1)
        self.assertEqual(len(production), 1)
        self.assertIn("Included.java", next(iter(production)))
        self.assertEqual(tests, set())

    def test_output_audit_matches_qualified_changed_symbol_to_simple_chain_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed.write_text(
                "api_name,api_signature,symbol_kind\n"
                "cn.hutool.core.collection.CollUtil.isEmpty,(java.util.Collection),method\n",
                encoding="utf-8",
            )
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "conclusion", "change_summary", "review_reason", "chain_summary",
                    "chain_target", "chain_detail", "path_text", "changed_symbol",
                    "api_signature", "symbol_kind", "path_status",
                ])
                writer.writeheader()
                writer.writerow({
                    "conclusion": "已确认影响：存在业务路径",
                    "change_summary": "删除方法",
                    "review_reason": "业务制品直接调用",
                    "chain_summary": "一跳调用",
                    "chain_target": "cn.hutool.core.collection.CollUtil.isEmpty(Collection)",
                    "chain_detail": "app.Entry.run() -> cn.hutool.core.collection.CollUtil.isEmpty(Collection)",
                    "path_text": "app.Entry.run() -> cn.hutool.core.collection.CollUtil.isEmpty(Collection)",
                    "changed_symbol": "cn.hutool.core.collection.CollUtil.isEmpty(java.util.Collection)",
                    "api_signature": "(java.util.Collection)",
                    "symbol_kind": "method",
                    "path_status": "reachable",
                })

            result = realreg.audit_analysis_outputs(
                changed, alerts, {"total_apis": 1}
            )

        self.assertNotIn(
            "reachable_chain_missing_target_symbol:1", result["failures"]
        )

    def test_output_audit_rejects_reachable_chain_with_a_different_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = root / "changed.csv"
            alerts = root / "alerts.csv"
            changed.write_text(
                "api_name,api_signature,symbol_kind\n"
                "vendor.Api.call,(java.lang.String),method\n",
                encoding="utf-8",
            )
            with alerts.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "conclusion", "change_summary", "review_reason", "chain_summary",
                    "chain_target", "chain_detail", "path_text", "changed_symbol",
                    "api_signature", "symbol_kind", "path_status",
                ])
                writer.writeheader()
                writer.writerow({
                    "conclusion": "已确认影响：存在业务路径",
                    "change_summary": "删除方法",
                    "review_reason": "业务制品直接调用",
                    "chain_summary": "一跳调用",
                    "chain_target": "vendor.Api.other(String)",
                    "chain_detail": "app.Entry.run() -> vendor.Api.other(String)",
                    "path_text": "app.Entry.run() -> vendor.Api.other(String)",
                    "changed_symbol": "vendor.Api.call(java.lang.String)",
                    "api_signature": "(java.lang.String)",
                    "symbol_kind": "method",
                    "path_status": "reachable",
                })

            result = realreg.audit_analysis_outputs(
                changed, alerts, {"total_apis": 1}
            )

        self.assertIn(
            "reachable_chain_missing_target_symbol:1", result["failures"]
        )

    def test_extract_graph_stats_is_stable_when_summary_is_partial(self):
        stats = realreg.extract_graph_stats(
            {
                "meta": {
                    "graph_stats": {
                        "methods_indexed": 123,
                        "reverse_edges_indexed": 456,
                        "parser_usage": {"tree_sitter": 7},
                        "truncated": True,
                        "edge_cap_hits": 2,
                    }
                }
            }
        )

        self.assertEqual(stats["methods_indexed"], 123)
        self.assertEqual(stats["reverse_edges_indexed"], 456)
        self.assertEqual(stats["tree_sitter_files"], 7)
        self.assertTrue(stats["truncated"])
        self.assertEqual(stats["edge_cap_hits"], 2)
        self.assertEqual(realreg.extract_graph_stats({})["methods_indexed"], 0)

    def test_select_step4_changed_apis_filters_expected_names_and_reports_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "all_changed_apis.csv"
            selected = Path(tmp) / "selected_all_changed_apis.csv"
            source.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.URL.valueOf,valueOf,method,(java.lang.String),true,P1,old_jar\n"
                "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.URL.valueOf,valueOf,method,\"(java.lang.String, boolean)\",true,P1,old_jar\n"
                "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.utils.NetUtils.getLocalHost,getLocalHost,method,(),true,P1,old_jar\n",
                encoding="utf-8",
            )

            result = realreg.select_step4_changed_apis(
                source,
                (
                    "org.apache.dubbo.common.URL.valueOf",
                    "org.apache.dubbo.common.Missing.call",
                ),
                selected,
            )

            with selected.open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))

        self.assertEqual(result["total_rows"], 3)
        self.assertEqual(result["selected_rows"], 2)
        self.assertEqual(result["missing_api_names"], ["org.apache.dubbo.common.Missing.call"])
        self.assertEqual({row["api_name"] for row in rows}, {"org.apache.dubbo.common.URL.valueOf"})

    def test_run_case_flags_source_shape_graph_and_performance_regressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            java_file = root / "src/main/java/demo/App.java"
            java_file.parent.mkdir(parents=True)
            java_file.write_text(
                "import org.apache.dubbo.common.utils.StringUtils;\n"
                "class App { void run() { StringUtils.isBlank(\"x\"); } }\n",
                encoding="utf-8",
            )
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            with changed_apis.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "coord",
                        "old_version",
                        "new_version",
                        "change_type",
                        "api_name",
                        "api_simple",
                        "symbol_kind",
                        "api_signature",
                        "confirmed",
                        "severity",
                        "source",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "org.apache.dubbo:dubbo-common",
                        "old_version": "1",
                        "new_version": "-",
                        "change_type": "REMOVED",
                        "api_name": "org.apache.dubbo.common.utils.StringUtils.isBlank",
                        "api_simple": "isBlank",
                        "symbol_kind": "method",
                        "api_signature": "(String)",
                        "confirmed": "true",
                        "severity": "P1",
                        "source": "test",
                    }
                )
            case = realreg.RealProjectCase(
                name="mini",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(
                    realreg.BaselineSpec(
                        symbol="org.apache.dubbo.common.utils.StringUtils.isBlank",
                        pattern=r"\bStringUtils\s*\.\s*isBlank\s*\(",
                        import_pattern=r"import\s+org\.apache\.dubbo\.common\.utils\.StringUtils\s*;",
                    ),
                ),
                source_shape_patterns={"lambda_expression": r"->"},
                min_source_shape_files={"lambda_expression": 1},
                min_methods_indexed=10,
                min_reverse_edges_indexed=20,
                max_elapsed_seconds=1.0,
            )

            def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                self._write_readable_alerts(
                    output / "alerts.csv",
                    "org.apache.dubbo.common.utils.StringUtils.isBlank",
                    java_file,
                )
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 1,
                            "reachable": 1,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {
                                "graph_stats": {
                                    "methods_indexed": 1,
                                    "reverse_edges_indexed": 2,
                                    "parser_usage": {"tree_sitter": 1},
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 2.5

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, changed_apis, report_root)

        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(item.startswith("source_shape:lambda_expression") for item in result["failures"]))
        self.assertTrue(any(item.startswith("graph_stats: methods_indexed") for item in result["failures"]))
        self.assertTrue(any(item.startswith("graph_stats: reverse_edges_indexed") for item in result["failures"]))
        self.assertTrue(any(item.startswith("performance:") for item in result["failures"]))
        self.assertIn("alerts_reachable.csv missing", result["warnings"])
        self.assertTrue(
            any(item["signal_type"] == "performance_regression" for item in result["quality_signals"])
        )
        self.assertFalse(result["performance_envelope"]["within_budget"])

    def test_run_case_emits_quality_signals_for_blocking_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            changed_apis.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "demo:dep,1,-,REMOVED,demo.Api.removed,removed,method,(String),true,P1,test\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="mini",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(),
            )

            def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                (output / "alerts.csv").write_text("changed_symbol,evidence_files\n", encoding="utf-8")
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 1,
                            "reachable": 0,
                            "uncertain": 0,
                            "not_analyzed": 1,
                            "not_found_in_static_analysis": 0,
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, changed_apis, report_root)

        signals = result["quality_signals"]
        self.assertTrue(any(item["signal_type"] == "capability_gap" for item in signals))
        self.assertTrue(any(item["blocking"] for item in signals))

    def test_verified_static_absence_is_not_reported_as_a_capability_gap(self):
        case = realreg.RealProjectCase("verified-absence", Path("."), Path("apis.csv"), ())
        signals = realreg.build_quality_signals(
            case,
            summary={
                "not_analyzed": 0,
                "not_found_in_static_analysis": 2,
                "uncertain": 0,
            },
            checks=[],
            failures=[],
            result_audit={},
            report_dir=Path("report"),
            oracle_audit={
                "ledger": [
                    {
                        "analyzer_conclusion": "not_found_in_static_analysis",
                        "verdict": "correct",
                    },
                    {
                        "analyzer_conclusion": "not_found_in_static_analysis",
                        "verdict": "correct",
                    },
                ],
            },
        )

        self.assertFalse(any(item["signal_type"] == "capability_gap" for item in signals))

    def test_oracle_expected_uncertain_is_not_reported_as_a_capability_gap(self):
        case = realreg.RealProjectCase("expected-uncertain", Path("."), Path("apis.csv"), ())
        signals = realreg.build_quality_signals(
            case,
            summary={
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "uncertain": 1,
            },
            checks=[],
            failures=[],
            result_audit={},
            report_dir=Path("report"),
            expected_uncertain=1,
        )

        self.assertFalse(any(item["signal_type"] == "capability_gap" for item in signals))

    def test_pinned_expected_static_absence_is_not_reported_as_a_capability_gap(self):
        case = realreg.RealProjectCase("expected-absence", Path("."), Path("apis.csv"), ())
        signals = realreg.build_quality_signals(
            case,
            summary={
                "not_analyzed": 0,
                "not_found_in_static_analysis": 2,
                "uncertain": 0,
            },
            checks=[],
            failures=[],
            result_audit={},
            report_dir=Path("report"),
            expected_not_found=2,
        )

        self.assertFalse(any(item["signal_type"] == "capability_gap" for item in signals))

    def test_run_case_includes_real_project_matrix_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            java_file = root / "src/main/java/demo/App.java"
            java_file.parent.mkdir(parents=True)
            java_file.write_text("class App {}\n", encoding="utf-8")
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            changed_apis.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "demo:dep,1,-,REMOVED,demo.Api.removed,removed,method,(String),true,P1,test\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="mini",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(),
            )

            def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                self._write_readable_alerts(output / "alerts.csv", "demo.Api.removed", java_file)
                (output / "alerts_reachable.csv").write_text(
                    (output / "alerts.csv").read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 1,
                            "reachable": 1,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {"graph_stats": {}},
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, changed_apis, report_root)

        policy = result["matrix_policy"]
        self.assertEqual(policy["role"], "problem_finder")
        self.assertIn("exploration", policy["lifecycle"])
        self.assertIn("fixture_debt", policy["promotion_rules"])
        self.assertIn("rotate_to_new_project", policy["promotion_rules"])
        self.assertFalse(result["topology_coverage"]["complete"])
        self.assertIn(
            "topology_evidence_invalid",
            {item["signal_type"] for item in result["quality_signals"]},
        )
        self.assertTrue(result["topology_coverage_files"]["json"].endswith("topology_coverage.json"))
        self.assertTrue(result["topology_coverage_files"]["csv"].endswith("topology_coverage.csv"))

    def test_run_case_reports_invalid_real_project_asset_before_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            source = root / "src/main/java/demo/App.java"
            source.parent.mkdir(parents=True)
            source.write_text("class App {}\n", encoding="utf-8")
            (root / ".git").mkdir()
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            changed_apis.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "demo:dep,1,-,REMOVED,demo.Api.removed,removed,method,(String),true,P1,test\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="invalid-asset",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(),
                require_valid_git=True,
                min_project_java_files=10,
                min_main_java_files=5,
                max_generated_java_ratio=0.5,
            )

            with patch.object(realreg, "run_step5") as fake_run_step5:
                result = realreg.run_case(case, root, changed_apis, report_root)

        fake_run_step5.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "project asset invalid")
        self.assertLess(result["project_asset_health"]["java_files"], 10)
        self.assertTrue(
            any(item["signal_type"] == "project_asset_invalid" for item in result["quality_signals"])
        )
        self.assertTrue(any(item["blocking"] for item in result["quality_signals"]))

    def test_run_case_fails_closed_when_discovery_artifact_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            case = realreg.RealProjectCase(
                name="missing-artifact",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                bytecode_owner_prefixes=("vendor/Api",),
                bytecode_coord="vendor:api",
                final_artifact=root / "target/missing.jar",
            )

            result = realreg.run_case(case, root, Path(""), Path(tmp) / "reports")

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "current final artifact unavailable")
        self.assertTrue(any(
            signal["signal_type"] == "project_asset_invalid"
            and signal["blocking"]
            and signal["fixture_status"] == "missing"
            for signal in result["quality_signals"]
        ))

    def test_run_case_fails_closed_when_topology_artifact_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            case = realreg.RealProjectCase(
                name="missing-topology-artifact",
                default_project=root,
                default_changed_apis=Path(""),
                baseline_specs=(),
                required_topologies=("business_direct",),
            )

            with patch.object(realreg, "run_step5") as run_step5:
                result = realreg.run_case(
                    case, root, Path(""), Path(tmp) / "reports"
                )

        run_step5.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "current final artifact unavailable")

    def test_run_case_prefers_embedded_changed_api_rows_over_existing_external_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            java_file = root / "src/main/java/demo/App.java"
            java_file.parent.mkdir(parents=True)
            java_file.write_text(
                "import org.apache.dubbo.common.utils.StringUtils;\n"
                "class App { void run() { StringUtils.isBlank(\"x\"); } }\n",
                encoding="utf-8",
            )
            external = Path(tmp) / "external.csv"
            external.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "bad:coord,1,-,REMOVED,bad.Api.call,call,method,(),true,P1,external\n",
                encoding="utf-8",
            )
            embedded_row = {
                "coord": "org.apache.dubbo:dubbo-common",
                "old_version": "1",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "org.apache.dubbo.common.utils.StringUtils.isBlank",
                "api_simple": "isBlank",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P1",
                "source": "embedded",
            }
            case = realreg.RealProjectCase(
                name="mini",
                default_project=root,
                default_changed_apis=external,
                changed_api_rows=(embedded_row,),
                prefer_embedded_changed_api_rows=True,
                baseline_specs=(),
            )

            def fake_run_step5(_case, _project_root, changed_apis, report_dir):
                with changed_apis.open(encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
                self.assertEqual(rows[0]["api_name"], embedded_row["api_name"])
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                self._write_readable_alerts(
                    output / "alerts.csv",
                    embedded_row["api_name"],
                    java_file,
                )
                (output / "alerts_reachable.csv").write_text("changed_symbol\n", encoding="utf-8")
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 1,
                            "reachable": 1,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {"graph_stats": {}},
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, external, report_root)

        self.assertEqual(result["status"], "failed")
        self.assertIn(
            "topology_evidence_invalid",
            {item["signal_type"] for item in result["quality_signals"]},
        )
        self.assertTrue(str(result["changed_apis"]).endswith("evidence/api_changes/all_changed_apis.csv"))

    def test_run_case_can_feed_step5_from_step4_selected_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            java_file = root / "src/main/java/demo/App.java"
            java_file.parent.mkdir(parents=True)
            java_file.write_text(
                "import org.apache.dubbo.common.URL;\n"
                "class App { void run(String s) { URL.valueOf(s); } }\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="dubbo-step4-mini",
                default_project=root,
                default_changed_apis=Path(""),
                changed_api_rows=(
                    {
                        "coord": "org.apache.dubbo:dubbo-common",
                        "old_version": "3.3.7-SNAPSHOT",
                        "new_version": "-",
                        "change_type": "REMOVED",
                        "api_name": "org.apache.dubbo.common.URL.valueOf",
                        "api_simple": "valueOf",
                        "symbol_kind": "method",
                        "api_signature": "(String)",
                        "confirmed": "true",
                        "severity": "P1",
                        "source": "test",
                    },
                ),
                run_step4=True,
                step4_dep_rows=(
                    {
                        "coord": "org.apache.dubbo:dubbo-common",
                        "old_version": "3.3.7-SNAPSHOT",
                        "new_version": "-",
                        "change_type": "移除",
                    },
                ),
                expected_step4_api_names=("org.apache.dubbo.common.URL.valueOf",),
                baseline_specs=(),
            )

            def fake_run_step4(_case, report_dir):
                output = report_dir / "evidence" / "api_changes"
                output.mkdir(parents=True)
                all_changed = output / "all_changed_apis.csv"
                all_changed.write_text(
                    "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                    "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.URL.valueOf,valueOf,method,(java.lang.String),true,P1,old_jar\n"
                    "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.URL.valueOf,valueOf,method,\"(java.lang.String, boolean)\",true,P1,old_jar\n"
                    "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.utils.NetUtils.getLocalHost,getLocalHost,method,(),true,P1,old_jar\n",
                    encoding="utf-8",
                )
                return {
                    "returncode": 0,
                    "elapsed_seconds": 0.2,
                    "all_changed_apis": str(all_changed),
                    "output_dir": str(output),
                }

            def fake_run_step5(_case, _project_root, changed_apis, report_dir):
                self.assertEqual(changed_apis.name, "selected_all_changed_apis.csv")
                with changed_apis.open(encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
                self.assertEqual(len(rows), 2)
                self.assertEqual({row["source"] for row in rows}, {"old_jar"})
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                self._write_readable_alerts(
                    output / "alerts.csv",
                    "org.apache.dubbo.common.URL.valueOf",
                    java_file,
                    signature="(java.lang.String)",
                )
                with (output / "alerts.csv").open(encoding="utf-8") as read_fh:
                    alert_fields = list(csv.DictReader(read_fh).fieldnames or [])
                with (output / "alerts.csv").open("a", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=alert_fields)
                    writer.writerow({
                        "conclusion": "已确认影响：已找到业务入口到变更 API 的完整调用链",
                        "change_summary": "删除方法，valueOf，参数：java.lang.String, boolean，严重级别：P1",
                        "review_reason": "已找到从系统代码到变更 API 的调用链",
                        "chain_summary": (
                            "入口：demo.App.run；终点："
                            "org.apache.dubbo.common.URL.valueOf(java.lang.String, boolean)；1 跳"
                        ),
                        "chain_entry": "demo.App.run",
                        "chain_target": "org.apache.dubbo.common.URL.valueOf(java.lang.String, boolean)",
                        "chain_hop_count": "1",
                        "chain_detail": (
                            "1. demo.App.run -> 2. "
                            "org.apache.dubbo.common.URL.valueOf(java.lang.String, boolean)"
                        ),
                        "changed_symbol": "org.apache.dubbo.common.URL.valueOf",
                        "api_signature": "(java.lang.String, boolean)",
                        "symbol_kind": "method",
                        "path_status": "reachable",
                        "path_text": (
                            "demo.App.run -> "
                            "org.apache.dubbo.common.URL.valueOf(java.lang.String, boolean)"
                        ),
                        "evidence_files": str(java_file),
                    })
                (output / "alerts_reachable.csv").write_text(
                    (output / "alerts.csv").read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 2,
                            "reachable": 1,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {"graph_stats": {}},
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step4", side_effect=fake_run_step4), \
                 patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, Path(""), report_root)

        self.assertEqual(result["status"], "failed")
        self.assertIn(
            "topology_evidence_invalid",
            {item["signal_type"] for item in result["quality_signals"]},
        )
        self.assertEqual(result["step4_selection"]["selected_rows"], 2)
        self.assertEqual(result["step4_selection"]["missing_api_names"], [])
        self.assertTrue(str(result["changed_apis"]).endswith("selected_all_changed_apis.csv"))

    def test_run_case_fails_when_step4_output_misses_expected_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            case = realreg.RealProjectCase(
                name="dubbo-step4-missing",
                default_project=root,
                default_changed_apis=Path(""),
                run_step4=True,
                step4_dep_rows=(
                    {
                        "coord": "org.apache.dubbo:dubbo-common",
                        "old_version": "3.3.7-SNAPSHOT",
                        "new_version": "-",
                        "change_type": "移除",
                    },
                ),
                expected_step4_api_names=("org.apache.dubbo.common.URL.valueOf",),
                baseline_specs=(),
            )

            def fake_run_step4(_case, report_dir):
                output = report_dir / "evidence" / "api_changes"
                output.mkdir(parents=True)
                all_changed = output / "all_changed_apis.csv"
                all_changed.write_text(
                    "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                    "org.apache.dubbo:dubbo-common,3.3.7-SNAPSHOT,-,REMOVED,org.apache.dubbo.common.utils.NetUtils.getLocalHost,getLocalHost,method,(),true,P1,old_jar\n",
                    encoding="utf-8",
                )
                return {
                    "returncode": 0,
                    "elapsed_seconds": 0.1,
                    "all_changed_apis": str(all_changed),
                    "output_dir": str(output),
                }

            def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                (output / "alerts.csv").write_text("changed_symbol,evidence_files\n", encoding="utf-8")
                (output / "alerts_reachable.csv").write_text("changed_symbol\n", encoding="utf-8")
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 0,
                            "reachable": 0,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {"graph_stats": {}},
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step4", side_effect=fake_run_step4), \
                 patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(case, root, Path(""), report_root)

        self.assertEqual(result["status"], "failed")
        self.assertIn("step4_missing_expected_api:org.apache.dubbo.common.URL.valueOf", result["failures"])
        self.assertIn("step4_selected_changed_apis_empty", result["failures"])

    def test_run_case_reports_failure_when_step4_does_not_materialize_changed_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            case = realreg.RealProjectCase(
                name="dubbo-step4-no-output",
                default_project=root,
                default_changed_apis=Path(""),
                run_step4=True,
                step4_dep_rows=(
                    {
                        "coord": "org.apache.dubbo:dubbo-common",
                        "old_version": "3.3.7-SNAPSHOT",
                        "new_version": "-",
                        "change_type": "移除",
                    },
                ),
                expected_step4_api_names=("org.apache.dubbo.common.URL.valueOf",),
                baseline_specs=(),
            )

            def fake_run_step4(_case, report_dir):
                output = report_dir / "evidence" / "api_changes"
                output.mkdir(parents=True)
                return {
                    "returncode": 1,
                    "elapsed_seconds": 0.1,
                    "all_changed_apis": str(output / "all_changed_apis.csv"),
                    "output_dir": str(output),
                }

            with patch.object(realreg, "run_step4", side_effect=fake_run_step4):
                result = realreg.run_case(case, root, Path(""), report_root)

        self.assertEqual(result["status"], "failed")
        self.assertIn("step4_returncode=1", result["failures"])
        self.assertTrue(any(item.startswith("changed APIs missing:") for item in result["failures"]))

    def test_run_case_can_validate_step6_report_and_query_for_user_journey(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            java_file = root / "src/main/java/demo/App.java"
            java_file.parent.mkdir(parents=True)
            java_file.write_text(
                "import org.apache.dubbo.common.URL;\n"
                "class App { void run(String s) { URL.valueOf(s); } }\n",
                encoding="utf-8",
            )
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            changed_apis.write_text(
                "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
                "org.apache.dubbo:dubbo-common,probe,-,REMOVED,org.apache.dubbo.common.URL.valueOf,valueOf,method,(String),true,P1,test\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="dubbo-user-mini",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(
                    realreg.BaselineSpec(
                        symbol="org.apache.dubbo.common.URL.valueOf",
                        pattern=r"\bURL\s*\.\s*valueOf\s*\(",
                        import_pattern=r"import\s+org\.apache\.dubbo\.common\.URL\s*;",
                    ),
                ),
                run_step6_report=True,
                query_methods=("org.apache.dubbo.common.URL.valueOf(String)",),
            )

            def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                self._write_readable_alerts(
                    output / "alerts.csv",
                    "org.apache.dubbo.common.URL.valueOf",
                    java_file,
                    signature="(String)",
                )
                (output / "alerts_reachable.csv").write_text(
                    (output / "alerts.csv").read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                (output / "summary.json").write_text(
                    json.dumps(
                        {
                            "total_apis": 1,
                            "reachable": 1,
                            "uncertain": 0,
                            "not_analyzed": 0,
                            "not_found_in_static_analysis": 0,
                            "meta": {"graph_stats": {"methods_indexed": 10, "reverse_edges_indexed": 20}},
                        }
                    ),
                    encoding="utf-8",
                )
                return 0, 0.5

            def fake_run_step6(report_dir):
                report = report_dir / "deliverables" / "report.md"
                findings = report_dir / ".runtime" / "findings" / "s6_findings.json"
                report.parent.mkdir(parents=True)
                findings.parent.mkdir(parents=True)
                report.write_text(
                    "org.apache.dubbo:dubbo-common\norg.apache.dubbo.common.URL.valueOf\n",
                    encoding="utf-8",
                )
                findings.write_text("{}", encoding="utf-8")
                return {
                    "returncode": 0,
                    "elapsed_seconds": 0.1,
                    "findings": str(findings),
                    "report": str(report),
                }

            def fake_query_step5(_report_dir, method):
                return {
                    "method": method,
                    "returncode": 0,
                    "stdout": "找到 1 条调用链：\n1. demo.App.run → org.apache.dubbo.common.URL.valueOf(String)",
                    "stderr": "",
                }

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5), \
                 patch.object(realreg, "run_step6", side_effect=fake_run_step6), \
                 patch.object(realreg, "query_step5", side_effect=fake_query_step5):
                result = realreg.run_case(case, root, changed_apis, report_root)

        self.assertEqual(result["status"], "failed")
        self.assertIn(
            "topology_evidence_invalid",
            {item["signal_type"] for item in result["quality_signals"]},
        )
        self.assertEqual(result["step6"]["returncode"], 0)
        self.assertEqual(result["queries"][0]["returncode"], 0)


class RealProjectRegressionTests(unittest.TestCase):
    def test_guard_selector_contains_only_guard_cases(self):
        selected = realreg.select_case_names("guard")

        self.assertTrue(selected)
        self.assertEqual(selected, sorted(selected))
        self.assertTrue(all(realreg.CASES[name].case_mode == "guard" for name in selected))
        self.assertTrue(all(realreg.CASES[name].fixture_manifest for name in selected))
        self.assertNotIn("spring-petclinic", selected)
        self.assertNotIn("seata", selected)

    def test_complete_edge_oracle_treats_exact_absence_as_a_fact(self):
        selected = [{
            "coord": "g:a", "api_name": "p.Api.removed", "api_signature": "()",
            "symbol_kind": "method", "change_type": "REMOVED",
        }]
        identity = realreg.serialized_api_identity(selected[0])

        retained, reachability, errors = realreg._retain_authoritative_api_path(
            selected, [], absence_is_authoritative=True
        )

        self.assertEqual(retained, [])
        self.assertEqual(reachability[identity], "not_found_in_static_analysis")
        self.assertEqual(errors, [])

    def test_edge_oracle_abstains_for_final_artifact_verified_framework_target(self):
        selected = [{
            "coord": "g:a", "api_name": "p.Proxy.invoke", "api_signature": "()",
            "symbol_kind": "method", "change_type": "REMOVED",
        }]
        identity = realreg.serialized_api_identity(selected[0])

        retained, reachability, errors = realreg._retain_authoritative_api_path(
            selected, [], {identity}
        )

        self.assertEqual(retained, [])
        self.assertEqual(reachability[identity], "uncertain")
        self.assertEqual(errors, [])

    def test_dubbo_spring6_security_reflection_guard(self):
        fixture_dir = ROOT / "tests" / "fixtures" / "real_projects"
        manifest = json.loads(
            (fixture_dir / "dubbo-spring6-security.json").read_text(encoding="utf-8")
        )
        with (fixture_dir / "dubbo-spring6-security-changed-apis.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            changed_rows = list(csv.DictReader(handle))
        case = realreg.CASES["dubbo-spring6-security"]

        self.assertEqual(len(changed_rows), 1)
        self.assertEqual(changed_rows[0]["symbol_kind"], "class")
        self.assertEqual(manifest["required_topologies"], ["reflection"])
        self.assertEqual(manifest["apis"][0]["expected_conclusion"], "uncertain")
        self.assertEqual(len(manifest["canonical_semantic_references"]), 1)
        self.assertEqual(manifest["canonical_edges"], [])
        self.assertEqual(case.fixture_manifest, fixture_dir / "dubbo-spring6-security.json")

    def _manifest_with_expected_physical_edges(self, manifest):
        return {
            **manifest,
            "canonical_edges": [
                {**edge, "instruction_offset": str(edge.get("instruction_offset", index * 4))}
                for index, edge in enumerate(manifest["canonical_edges"])
            ],
        }

    def _passing_gs_guard_result(self, manifest, *, ledger=None):
        if ledger is None:
            ledger = []
            for index, edge in enumerate(manifest["canonical_edges"]):
                production_edge = {
                    **edge,
                    "instruction_offset": str(edge.get("instruction_offset", index * 4)),
                }
                occurrence = realreg.physical_edge_occurrence(production_edge)
                for side, nested_key in (("analyzer", "analyzer_row"), ("oracle", "oracle_row")):
                    ledger.append({
                        "side": side,
                        "verdict": "correct",
                        "identity": realreg.canonical_edge_identity(production_edge),
                        "physical_occurrence": occurrence,
                        nested_key: production_edge,
                    })
        return {
            "api_coverage_complete": True,
            "summary": {
                "reachable": 1,
                "uncertain": 0,
                "not_analyzed": 0,
                "not_found_in_static_analysis": 0,
                "reachable_apis": [{
                    "api": "com.example.multimodule.service.ServiceProperties.getMessage",
                    "coord": manifest["api"]["coord"],
                    "symbol_kind": manifest["api"]["symbol_kind"],
                    "api_signature": "()",
                    "analysis_status": "reachable",
                    "call_paths": [],
                    "path_details": [{
                        "path_text": " → ".join(manifest["expected_chain"][:-1])
                        + " → 变更 API： " + manifest["expected_chain"][-1] + "()",
                    }],
                }],
                "uncertain_apis": [],
            },
            "topology_coverage": {
                "complete": True,
                "observed": manifest["required_topologies"],
            },
            "edge_truth": {
                "complete": True,
                "blocking": False,
                "ledger": ledger,
            },
            "quality_signals": [],
        }

    def test_gs_multi_module_same_coordinate_guard(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        case = realreg.CASES["gs-multi-module"]

        self.assertEqual(manifest["git_revision"], "d88a2b721bda3798a6a934987157498e66da06c5")
        self.assertEqual(
            manifest["artifact_sha256"],
            "609d58279a4c509da5cf453cf57ae2e28b41f3e42ec2f4789710db6c68e2c523",
        )

        self.assertEqual(case.required_topologies, (
            "business_to_same_jar_bridge",
            "same_coord_multimodule",
        ))
        self.assertEqual(manifest["api"]["descriptor"], "()Ljava/lang/String;")
        self.assertEqual(manifest["expected_conclusion"], "reachable")
        self.assertEqual(manifest["expected_chain"], [
            "com.example.multimodule.application.DemoApplication.home",
            "com.example:library:com.example.multimodule.service.MyService.message",
            "com.example.multimodule.service.ServiceProperties.getMessage",
        ])
        self.assertEqual(len(manifest["canonical_edges"]), 2)
        self.assertEqual(
            [edge["instruction_offset"] for edge in manifest["canonical_edges"]], [4, 4]
        )
        self.assertEqual(
            [realreg.canonical_edge_identity(row) for row in manifest["canonical_edges"]],
            [
                "609d58279a4c509da5cf453cf57ae2e28b41f3e42ec2f4789710db6c68e2c523|"
                "com.example.multimodule.application.DemoApplication|home|()Ljava/lang/String;|"
                "com.example.multimodule.service.MyService|message|()Ljava/lang/String;|invokevirtual",
                "609d58279a4c509da5cf453cf57ae2e28b41f3e42ec2f4789710db6c68e2c523|"
                "com.example.multimodule.service.MyService|message|()Ljava/lang/String;|"
                "com.example.multimodule.service.ServiceProperties|getMessage|()Ljava/lang/String;|invokevirtual",
            ],
        )

        guard = realreg.evaluate_pinned_guard_contract(manifest, {
            "summary": {
                "reachable": 0,
                "uncertain_apis": [{"reason_code": "SOURCE_BYTECODE_EDGE_CONFLICT"}],
            },
            "topology_coverage": {"complete": True, "observed": list(case.required_topologies)},
            "edge_truth": {"complete": True, "blocking": False, "ledger": []},
        })

        self.assertFalse(guard["passed"])
        self.assertIn("SOURCE_BYTECODE_EDGE_CONFLICT", guard["errors"])

    def test_gs_messaging_rabbitmq_reflection_callback_guard(self):
        manifest_path = (
            ROOT / "tests" / "fixtures" / "real_projects" /
            "gs-messaging-rabbitmq.json"
        )
        changed_path = (
            ROOT / "tests" / "fixtures" / "real_projects" /
            "gs-messaging-rabbitmq-changed-apis.csv"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with changed_path.open(newline="", encoding="utf-8") as handle:
            changed_rows = list(csv.DictReader(handle))
        case = realreg.CASES["gs-messaging-rabbitmq"]

        self.assertEqual(
            manifest["git_revision"],
            "3e112f5e956bf61e6cc1ec92c8a5a9a96f738d86",
        )
        self.assertEqual(
            manifest["artifact_sha256"],
            "6dd4d51c963f6826ec2bba476d1f4e2d763378491e28e0c763ba7066ad852688",
        )
        self.assertEqual(case.default_changed_apis, changed_path)
        self.assertEqual(
            case.required_topologies,
            ("business_direct", "framework_callback"),
        )
        self.assertEqual(
            case.required_fault_injections,
            realreg.STANDARD_FAULT_INJECTIONS,
        )
        self.assertTrue(case.require_relative_performance_baseline)
        self.assertEqual(
            manifest["performance_baseline"]["git_revision"],
            manifest["git_revision"],
        )
        self.assertEqual(
            manifest["performance_baseline"]["artifact_sha256"],
            manifest["artifact_sha256"],
        )
        self.assertEqual(
            manifest["performance_baseline"]["scope"]["fault_injection_detected_count"],
            1,
        )
        self.assertEqual(len(changed_rows), 3)
        self.assertEqual(len(manifest["apis"]), len(changed_rows))
        self.assertEqual(len(manifest["canonical_edges"]), 5)
        self.assertEqual(
            {
                (row["api_name"], row["api_signature"], row["symbol_kind"])
                for row in changed_rows
            },
            {
                ("java.lang.System.out", "", "field"),
                ("java.io.PrintStream.println", "(String)", "method"),
                ("java.util.concurrent.CountDownLatch.countDown", "()", "method"),
            },
        )
        self.assertEqual(manifest["framework_callback"], {
            "registration_owner": "com.example.messagingrabbitmq.MessagingRabbitmqApplication",
            "registration_member": "listenerAdapter",
            "callback_owner": "com.example.messagingrabbitmq.Receiver",
            "callback_member": "receiveMessage",
            "callback_descriptor": "(Ljava/lang/String;)V",
            "adapter_owner": (
                "org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter"
            ),
            "registration_instruction_offset": 7,
        })
        self.assertTrue(all(
            expected["expected_chain"][1] == "Spring Boot框架注册"
            for expected in manifest["apis"]
        ))
        callback_edges = [
            edge for edge in manifest["canonical_edges"]
            if edge["caller_member"] == "receiveMessage"
        ]
        self.assertEqual(len(callback_edges), len(changed_rows))
        self.assertEqual(
            {edge["instruction_offset"] for edge in callback_edges},
            {0, 9, 16},
        )
        runner_edges = [
            edge for edge in manifest["canonical_edges"]
            if edge["caller_member"] == "run"
        ]
        self.assertEqual(
            {(edge["callee_owner"], edge["callee_member"], edge["instruction_offset"])
             for edge in runner_edges},
            {
                ("java.lang.System", "out", 0),
                ("java.io.PrintStream", "println", 5),
            },
        )

    def test_gs_managing_transactions_proxy_guard(self):
        fixture_dir = ROOT / "tests" / "fixtures" / "real_projects"
        manifest = json.loads(
            (fixture_dir / "gs-managing-transactions.json").read_text(encoding="utf-8")
        )
        with (fixture_dir / "gs-managing-transactions-changed-apis.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            changed_rows = list(csv.DictReader(handle))
        with (fixture_dir / "gs-managing-transactions-oracle.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            oracle_rows = list(csv.DictReader(handle))
        case = realreg.CASES["gs-managing-transactions"]

        self.assertEqual(
            manifest["git_revision"],
            "efa693451b6a6ca123476c9c6e65eedab9048e2c",
        )
        self.assertEqual(
            manifest["artifact_sha256"],
            "fd0b8883214c641685ab8f0e7b583ec2f8150112f9679161908eb6829bd98b90",
        )
        self.assertEqual(case.case_mode, "guard")
        self.assertEqual(case.required_topologies, ("framework_proxy",))
        self.assertEqual(case.required_fault_injections, realreg.STANDARD_FAULT_INJECTIONS)
        self.assertTrue(case.require_relative_performance_baseline)
        self.assertEqual(len(changed_rows), 3)
        self.assertEqual(len(oracle_rows), len(changed_rows))
        self.assertTrue(all(row["oracle_conclusion"] == "reachable" for row in oracle_rows))
        self.assertTrue(all(row["evidence_mode"] == "project_test" for row in oracle_rows))
        identity = lambda row: (
            row["coord"], row["api_name"], row["symbol_kind"], row["api_signature"]
        )
        self.assertEqual(
            {identity(row) for row in changed_rows},
            {identity(row) for row in oracle_rows},
        )
        self.assertEqual(len(manifest["canonical_edges"]), 1)
        self.assertEqual(
            manifest["performance_baseline"]["scope"]["selected_api_count"],
            3,
        )

    def test_pinned_guard_evaluates_every_api_in_callback_manifest(self):
        manifest = json.loads((
            ROOT / "tests" / "fixtures" / "real_projects" /
            "gs-messaging-rabbitmq.json"
        ).read_text(encoding="utf-8"))
        reachable = []
        for expected in manifest["apis"]:
            target = f"{expected['owner']}.{expected['member']}"
            signature = {
                "java.lang.System.out": "",
                "java.io.PrintStream.println": "(String)",
                "java.util.concurrent.CountDownLatch.countDown": "()",
            }[target]
            reachable.append({
                "api": target,
                "coord": expected["coord"],
                "symbol_kind": expected["symbol_kind"],
                "api_signature": signature,
                "analysis_status": expected["expected_conclusion"],
                "path_details": [{
                    "path_text": " -> ".join([
                        *expected["expected_chain"][:-1],
                        target + signature,
                    ]),
                }],
            })
        ledger = []
        for edge in manifest["canonical_edges"]:
            occurrence = realreg.physical_edge_occurrence(edge)
            identity = realreg.canonical_edge_identity(edge)
            for side, row_key in (("analyzer", "analyzer_row"), ("oracle", "oracle_row")):
                ledger.append({
                    "side": side,
                    "verdict": "correct",
                    "identity": identity,
                    "physical_occurrence": occurrence,
                    row_key: edge,
                })
        result = {
            "summary": {
                "reachable_apis": reachable,
                "uncertain_apis": [],
                "not_analyzed_apis": [],
                "not_found_apis": [],
            },
            "topology_coverage": {
                "complete": True,
                "observed": manifest["required_topologies"],
            },
            "edge_truth": {
                "complete": True,
                "blocking": False,
                "ledger": ledger,
            },
        }

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertEqual(guard, {
            "passed": True,
            "errors": [],
            "api_count": 3,
            "expected_physical_edge_count": 5,
            "expected_semantic_reference_count": 0,
        })

    def test_callback_chain_match_ignores_business_artifact_display_prefix(self):
        expected_api = {
            "owner": "java.util.concurrent.CountDownLatch",
            "member": "countDown",
            "descriptor": "()V",
            "symbol_kind": "method",
        }
        expected_chain = [
            "com.example.messagingrabbitmq.MessagingRabbitmqApplication.main",
            "Spring Boot框架注册",
            "com.example.messagingrabbitmq.Receiver.receiveMessage",
            "java.util.concurrent.CountDownLatch.countDown",
        ]
        rendered_path = (
            "com.example.messagingrabbitmq.MessagingRabbitmqApplication.main -> "
            "Spring Boot框架注册 -> "
            "业务制品：com.example.messagingrabbitmq.Receiver.receiveMessage(String) -> "
            "java.util.concurrent.CountDownLatch.countDown()"
        )

        self.assertTrue(realreg._matches_expected_call_chain(
            rendered_path, expected_chain, expected_api
        ))

    def test_guard_chain_matches_equivalent_nested_class_renderings(self):
        expected_api = {
            "owner": (
                "org.springframework.security.authorization.method."
                "AuthorizationAdvisorProxyFactory$TargetVisitor"
            ),
            "member": "of",
            "descriptor": (
                "([Lorg/springframework/security/authorization/method/"
                "AuthorizationAdvisorProxyFactory$TargetVisitor;)"
                "Lorg/springframework/security/authorization/method/"
                "AuthorizationAdvisorProxyFactory$TargetVisitor;"
            ),
            "symbol_kind": "method",
        }
        expected_chain = [
            "example.Configuration$Nested.configure",
            expected_api["owner"] + ".of",
        ]
        rendered_path = (
            "业务制品：example.Configuration.Nested.configure(ObjectProvider) -> "
            "org.springframework.security.authorization.method."
            "AuthorizationAdvisorProxyFactory$TargetVisitor."
            "of(AuthorizationAdvisorProxyFactory$TargetVisitor[])"
        )

        self.assertTrue(realreg._matches_expected_call_chain(
            rendered_path, expected_chain, expected_api
        ))

    def test_pinned_guard_accepts_runtime_rendered_signature_on_bridge_node(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        result = self._passing_gs_guard_result(manifest)
        expected = manifest["expected_chain"]
        result["summary"]["reachable_apis"][0]["path_details"] = [{
            "path_text": " -> ".join((
                expected[0], expected[1] + "()", expected[2] + "()",
            )),
        }]

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertTrue(guard["passed"], guard["errors"])

    def test_gs_multi_module_limits_business_sources_to_the_packaged_application_module(self):
        case = realreg.CASES["gs-multi-module"]
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "checkout"
            changed_apis = Path(tmp) / "changed.csv"
            report_dir = Path(tmp) / "report"
            checkout.mkdir()
            changed_apis.write_text("api_name\n", encoding="utf-8")
            captured = {}

            def fake_run(command, **_kwargs):
                captured["command"] = command
                return type("Completed", (), {"returncode": 0})()

            with patch.object(realreg.subprocess, "run", side_effect=fake_run):
                realreg.run_step5(case, checkout, changed_apis, report_dir)

        source_index = captured["command"].index("--source-dirs") + 1
        self.assertEqual(
            captured["command"][source_index],
            str(checkout / "application" / "src" / "main" / "java"),
        )
        self.assertNotIn(str(checkout / "library" / "src" / "main" / "java"), captured["command"])

    def test_run_step5_enforces_case_budget_and_records_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed_apis = root / "changed.csv"
            changed_apis.write_text("api_name\n", encoding="utf-8")
            report_dir = root / "report"
            case = realreg.RealProjectCase(
                name="budgeted", default_project=root, default_changed_apis=changed_apis,
                baseline_specs=(), max_elapsed_seconds=1.5,
            )
            captured = {}

            def timeout_run(command, **kwargs):
                captured["timeout"] = kwargs.get("timeout")
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

            with patch.object(realreg.subprocess, "run", side_effect=timeout_run):
                returncode, elapsed = realreg.run_step5(
                    case, root, changed_apis, report_dir
                )

            timeout_record = json.loads(
                (report_dir / "evidence/quality/step5_timeout.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(captured["timeout"], 1.5)
        self.assertEqual(returncode, 124)
        self.assertGreaterEqual(elapsed, 0.0)
        self.assertEqual(timeout_record["reason"], "STEP5_PERFORMANCE_BUDGET_EXCEEDED")
        self.assertEqual(timeout_record["timeout_seconds"], 1.5)

    def test_run_case_skips_edge_oracle_when_step5_did_not_produce_a_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            changed_apis = Path(tmp) / "changed.csv"
            changed_apis.write_text(
                "coord,api_name,api_signature,symbol_kind,change_type\n"
                "g:a,com.example.Target.call,(),method,REMOVED\n",
                encoding="utf-8",
            )
            case = realreg.RealProjectCase(
                name="timed-out",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(),
            )

            with patch.object(realreg, "run_step5", return_value=(124, 1.0)), patch.object(
                realreg, "reconcile_final_artifact_edges"
            ) as reconcile:
                result = realreg.run_case(
                    case, root, changed_apis, report_root
                )

        reconcile.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertIn("step5_returncode=124", result["failures"])

    def test_full_step4_run_uses_full_api_budget_for_step5_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            report_root = Path(tmp) / "reports"
            root.mkdir()
            changed_apis = Path(tmp) / "all_changed_apis.csv"
            changed_apis.write_text("api_name\ncom.example.Target.call\n", encoding="utf-8")
            case = realreg.RealProjectCase(
                name="full-budget",
                default_project=root,
                default_changed_apis=changed_apis,
                baseline_specs=(),
                max_elapsed_seconds=1.0,
                max_full_step4_api_elapsed_seconds=7.5,
            )
            captured = {}

            def fake_run_step5(execution_case, _project_root, _changed_apis, report_dir):
                captured["budget"] = execution_case.max_elapsed_seconds
                output = report_dir / "evidence" / "call_chain"
                output.mkdir(parents=True)
                (output / "summary.json").write_text(
                    json.dumps({"total_apis": 1, "meta": {"graph_stats": {}}}),
                    encoding="utf-8",
                )
                return 0, 0.1

            with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
                result = realreg.run_case(
                    case, root, changed_apis, report_root, full_step4_apis=True
                )

        self.assertEqual(captured["budget"], 7.5)
        self.assertEqual(result["performance_budget_seconds"], 7.5)

    def test_pinned_asset_preparation_maps_same_coordinate_nested_library_to_runtime_catalog(self):
        case = realreg.CASES["gs-multi-module"]
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            with realreg.zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/app/App.class", b"class")
                archive.writestr("BOOT-INF/lib/library-0.0.1-SNAPSHOT.jar", b"nested")
            asset_gate = {
                "artifact_path": str(artifact),
                "artifact_sha256": realreg.hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }

            realreg.write_pinned_final_artifact_provenance(report_dir, asset_gate, case)

            with (report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv").open(
                newline="", encoding="utf-8-sig"
            ) as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows, [{
            "coord": "com.example:library",
            "version": "0.0.1-SNAPSHOT",
            "scope": "compile",
            "lib_entry": "BOOT-INF/lib/library-0.0.1-SNAPSHOT.jar",
            "resolution_status": "resolved",
        }])

    def test_pinned_source_build_provenance_preserves_revision_alignment(self):
        case = realreg.CASES["gs-managing-transactions"]
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            artifact = Path(tmp) / "application.jar"
            with realreg.zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("app/App.class", b"class")
            revision = "a" * 40
            asset_gate = {
                "artifact_path": str(artifact),
                "artifact_sha256": realreg.hashlib.sha256(
                    artifact.read_bytes()
                ).hexdigest(),
                "actual_git_revision": revision,
                "source_mode": "checkout_build",
            }

            output = realreg.write_pinned_final_artifact_provenance(
                report_dir, asset_gate, case
            )
            current = json.loads(output.read_text(encoding="utf-8"))["sides"][0]

        self.assertEqual(current["revision"], revision)
        self.assertEqual(current["source_mode"], "checkout_build")

    def test_published_artifact_manifest_does_not_claim_checkout_build_alignment(self):
        self.assertEqual(
            realreg.pinned_source_mode({
                "materialization": {"kind": "published_artifact"}
            }),
            "provided_artifact",
        )
        self.assertEqual(
            realreg.pinned_source_mode({
                "materialization": {"kind": "source_build"}
            }),
            "checkout_build",
        )

    def test_pinned_fat_jar_preparation_enumerates_all_runtime_libraries(self):
        case = realreg.CASES["gs-messaging-rabbitmq"]
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "report"
            nested = realreg.io.BytesIO()
            with realreg.zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("org/example/Runtime.class", b"class")
                archive.writestr(
                    "META-INF/maven/org.example/runtime/pom.properties",
                    "groupId=org.example\nartifactId=runtime\nversion=1.2.3\n",
                )
            artifact = Path(tmp) / "application.jar"
            with realreg.zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/app/App.class",
                    b"\xca\xfe\xba\xbe\x00\x00\x00=",
                )
                archive.writestr("BOOT-INF/lib/runtime-1.2.3.jar", nested.getvalue())
            asset_gate = {
                "artifact_path": str(artifact),
                "artifact_sha256": realreg.hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }

            realreg.write_pinned_final_artifact_provenance(report_dir, asset_gate, case)

            with (report_dir / "evidence" / "dependencies" / "deps_current_resolved.csv").open(
                newline="", encoding="utf-8-sig"
            ) as handle:
                rows = list(csv.DictReader(handle))
            context = json.loads(
                (report_dir / "evidence/context/context.json").read_text(encoding="utf-8")
            )

        self.assertEqual(rows, [{
            "coord": "org.example:runtime",
            "version": "1.2.3",
            "scope": "runtime",
            "lib_entry": "BOOT-INF/lib/runtime-1.2.3.jar",
            "resolution_status": "resolved",
        }])
        self.assertEqual(context["jdk_current"], "17")

    def test_pinned_asset_gate_rejects_revision_and_final_artifact_sha_mismatch(self):
        manifest = {
            "git_revision": "a" * 40,
            "artifact_path": "application/target/application.jar",
            "artifact_sha256": "b" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / manifest["artifact_path"]
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"wrong artifact")
            completed = realreg.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="c" * 40 + "\n", stderr=""
            )
            with patch.object(realreg.subprocess, "run", return_value=completed):
                gate = realreg.validate_pinned_asset(manifest, root)

        self.assertFalse(gate["passed"])
        self.assertIn("git_revision_mismatch", gate["errors"])
        self.assertIn("final_artifact_sha256_mismatch", gate["errors"])

    def test_pinned_guard_requires_reachable_exact_chain_and_two_correct_physical_edges(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        result = self._passing_gs_guard_result(manifest)
        ledger = result["edge_truth"]["ledger"]

        passing = realreg.evaluate_pinned_guard_contract(manifest, result)
        missing_edge = realreg.evaluate_pinned_guard_contract(
            manifest,
            {**result, "edge_truth": {**result["edge_truth"], "ledger": ledger[:2]}},
        )

        self.assertTrue(passing["passed"], passing["errors"])
        self.assertFalse(missing_edge["passed"])
        self.assertIn("expected_physical_edge_missing", missing_edge["errors"])

    def test_pinned_guard_accepts_a_zero_instruction_offset_physical_edge(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        manifest["canonical_edges"][0]["instruction_offset"] = 0
        result = self._passing_gs_guard_result(manifest)

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertTrue(guard["passed"], guard["errors"])
        self.assertIn("|0", realreg.physical_edge_occurrence(manifest["canonical_edges"][0]))

    def test_pinned_guard_rejects_a_different_overload_with_the_same_name(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        result = self._passing_gs_guard_result(manifest)
        manifest["api"]["descriptor"] = "(I)Ljava/lang/String;"
        manifest["expected_chain"] = []

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertFalse(guard["passed"])
        self.assertIn("expected_conclusion_missing", guard["errors"])

    def test_pinned_guard_rejects_nested_reconciliation_rows_at_wrong_instruction_offset(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        result = self._passing_gs_guard_result(manifest)
        expected = manifest["canonical_edges"][1]
        for entry in result["edge_truth"]["ledger"]:
            nested_key = "analyzer_row" if entry["side"] == "analyzer" else "oracle_row"
            row = entry[nested_key]
            if realreg.canonical_edge_identity(row) != realreg.canonical_edge_identity(expected):
                continue
            mismatched = {**row, "instruction_offset": "999"}
            entry[nested_key] = mismatched
            entry["physical_occurrence"] = realreg.physical_edge_occurrence(mismatched)

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertFalse(guard["passed"])
        self.assertIn("expected_physical_edge_missing", guard["errors"])

    def test_pinned_guard_accepts_production_reconciliation_ledger_shape(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        ledger = []
        for index, edge in enumerate(manifest["canonical_edges"]):
            production_edge = {
                **edge,
                "instruction_offset": str(edge.get("instruction_offset", index * 4)),
            }
            occurrence = realreg.physical_edge_occurrence(production_edge)
            for side, nested_key in (("analyzer", "analyzer_row"), ("oracle", "oracle_row")):
                ledger.append({
                    "side": side,
                    "index": index,
                    "verdict": "correct",
                    "identity": realreg.canonical_edge_identity(production_edge),
                    "artifact_sha256": production_edge["artifact_sha256"],
                    "artifact_entry": production_edge["artifact_entry"],
                    "api_identity": "selected-api",
                    "physical_occurrence": occurrence,
                    nested_key: production_edge,
                })
        result = self._passing_gs_guard_result(manifest, ledger=ledger)

        guard = realreg.evaluate_pinned_guard_contract(manifest, result)

        self.assertTrue(guard["passed"], guard["errors"])

    def test_pinned_guard_rejects_reordered_or_extra_chain_nodes(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest["expected_chain"]
        cases = (
            [expected[1], expected[0], expected[2]],
            [expected[0], "com.example.Unrelated.extra", expected[1], expected[2]],
        )
        for nodes in cases:
            with self.subTest(nodes=nodes):
                result = self._passing_gs_guard_result(manifest)
                result["summary"]["reachable_apis"][0]["path_details"] = [{
                    "path_text": " → ".join(nodes[:-1])
                    + " → 变更 API： " + nodes[-1] + "()",
                }]
                result["summary"]["reachable_apis"][0]["call_paths"] = [
                    " → ".join(nodes)
                ]

                guard = realreg.evaluate_pinned_guard_contract(manifest, result)

                self.assertFalse(guard["passed"])
                self.assertIn("expected_chain_missing", guard["errors"])

    def test_pinned_guard_rejects_marker_before_terminal_or_terminal_without_target_descriptor(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        expected = manifest["expected_chain"]
        paths = (
            " → ".join((expected[0], f"变更 API： {expected[1]}", expected[2] + "()")),
            " → ".join((expected[0], expected[1], f"变更 API： {expected[2]}")),
        )
        for path_text in paths:
            with self.subTest(path_text=path_text):
                result = self._passing_gs_guard_result(manifest)
                result["summary"]["reachable_apis"][0]["path_details"] = [{
                    "path_text": path_text,
                }]

                guard = realreg.evaluate_pinned_guard_contract(manifest, result)

                self.assertFalse(guard["passed"])
                self.assertIn("expected_chain_missing", guard["errors"])

    def test_topology_gate_propagates_incomplete_and_missing_required_contract_errors(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        asset = {"name": "asset", "passed": True, "errors": []}
        lifecycle = realreg.evaluate_finding_lifecycle([], [])
        for topology in (
            {"complete": False, "observed": manifest["required_topologies"]},
            {"complete": True, "observed": manifest["required_topologies"][:1]},
        ):
            with self.subTest(topology=topology):
                result = self._passing_gs_guard_result(manifest)
                result["topology_coverage"] = topology

                gates = realreg.build_v3_gates(manifest, result, asset, lifecycle)

                self.assertFalse(gates["topology_coverage"]["passed"])
                self.assertIn("required_topology_missing", gates["topology_coverage"]["errors"])

    def test_fixture_debt_accepts_fixed_planned_and_unexpired_waiver_states(self):
        signals = [
            {"signal_type": "capability_gap", "severity": "P1", "blocking": True,
             "fixture_debt_id": "planned-gap"},
            {"signal_type": "evidence_weakness", "severity": "P0", "blocking": True,
             "fixture_debt_id": "waived-gap"},
        ]
        declarations = [
            {"finding_id": "fixed-gap", "state": "fixed", "fixture":
             "tests.test_real_project_regression.RealProjectRegressionTests."
             "test_gs_multi_module_same_coordinate_guard"},
            {"finding_id": "planned-gap", "state": "planned", "target_fixture": "L1 nested jar"},
            {"finding_id": "waived-gap", "state": "waived_until", "reason": "JDK variance",
             "expires": "2026-07-13"},
        ]

        lifecycle = realreg.evaluate_finding_lifecycle(signals, declarations, today="2026-07-12")
        result = realreg.evaluate_fixture_debt(
            lifecycle, {name: True for name in realreg.V3_GATE_NAMES}
        )

        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual({row["state"] for row in result["rows"]}, {
            "fixed", "planned", "waived_until"
        })

    def test_fixture_debt_blocks_missing_and_expired_states(self):
        signals = [
            {"signal_type": "capability_gap", "severity": "P1", "blocking": True,
             "fixture_debt_id": "missing-gap"},
            {"signal_type": "evidence_weakness", "severity": "P0", "blocking": True,
             "fixture_debt_id": "expired-gap"},
        ]
        declarations = [{
            "finding_id": "expired-gap", "state": "waived_until", "reason": "temporary",
            "expires": "2026-07-11",
        }]

        lifecycle = realreg.evaluate_finding_lifecycle(signals, declarations, today="2026-07-12")
        result = realreg.evaluate_fixture_debt(
            lifecycle, {name: True for name in realreg.V3_GATE_NAMES}
        )

        self.assertFalse(result["passed"])
        self.assertIn("missing-gap:missing_state", result["errors"])
        self.assertIn("expired-gap:waiver_expired", result["errors"])

    def test_fixed_fixture_debt_requires_real_unittest_and_all_seven_gates(self):
        declarations = [{
            "finding_id": "fixed-gap",
            "state": "fixed",
            "fixture": "tests.test_real_project_regression.RealProjectRegressionTests.not_a_test",
        }]
        invalid_fixture = realreg.evaluate_finding_lifecycle([], declarations)
        valid_declarations = [{
            **declarations[0],
            "fixture": "tests.test_real_project_regression.RealProjectRegressionTests."
                       "test_gs_multi_module_same_coordinate_guard",
        }]
        valid_lifecycle = realreg.evaluate_finding_lifecycle([], valid_declarations)
        gate_states = {name: True for name in realreg.V3_GATE_NAMES}
        gate_states["performance"] = False

        unresolved = realreg.evaluate_fixture_debt(
            invalid_fixture, {name: True for name in realreg.V3_GATE_NAMES}
        )
        incomplete = realreg.evaluate_fixture_debt(valid_lifecycle, gate_states)

        self.assertIn("fixed-gap:fixed_fixture_not_unittest", unresolved["errors"])
        self.assertIn("fixed-gap:fixed_gates_incomplete:performance", incomplete["errors"])

    def test_fixed_fixture_debt_reopens_only_from_explicit_finding_recurrence(self):
        declaration = [{
            "finding_id": "same_coordinate_multimodule_bridge",
            "state": "fixed",
            "fixture": "tests.test_real_project_regression.RealProjectRegressionTests."
                       "test_gs_multi_module_same_coordinate_guard",
        }]
        recurrence = [{
            "fixture_debt_id": "same_coordinate_multimodule_bridge",
            "severity": "P1",
            "lifecycle_result": "recurred",
        }]

        lifecycle = realreg.evaluate_finding_lifecycle(recurrence, declaration)
        result = realreg.evaluate_fixture_debt(
            lifecycle, {name: True for name in realreg.V3_GATE_NAMES}
        )

        self.assertFalse(result["passed"])
        self.assertIn(
            "same_coordinate_multimodule_bridge:finding_recurred_after_fixed",
            result["errors"],
        )

    def test_v3_guard_reports_all_seven_independent_gates(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        result = self._passing_gs_guard_result(manifest)
        asset = {"name": "asset", "passed": True, "errors": []}
        lifecycle = realreg.evaluate_finding_lifecycle(
            [], manifest["fixture_debt"], today="2026-07-12"
        )
        debt = realreg.evaluate_fixture_debt(
            lifecycle, {name: True for name in realreg.V3_GATE_NAMES}
        )

        gates = realreg.build_v3_gates(manifest, result, asset, debt)

        self.assertEqual(list(gates), [
            "asset", "api_coverage", "topology_coverage", "edge_truth",
            "conclusion", "performance", "fixture_debt",
        ])
        self.assertTrue(all(gate["passed"] for gate in gates.values()), gates)

    def test_run_case_checks_pinned_final_artifact_before_step5_and_writes_gate_outputs(self):
        case = realreg.CASES["gs-multi-module"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-checkout"
            report_root = Path(tmp) / "reports"
            with patch.object(realreg, "run_step5") as run_step5:
                result = realreg.run_case(case, root, Path(""), report_root)

            gates_path = report_root / case.name / "evidence" / "quality" / "v3_gates.json"
            debt_json = report_root / case.name / "evidence" / "quality" / "fixture_debt.json"
            debt_csv = report_root / case.name / "evidence" / "quality" / "fixture_debt.csv"

            self.assertTrue(gates_path.is_file())
            self.assertTrue(debt_json.is_file())
            self.assertTrue(debt_csv.is_file())

        run_step5.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(set(result["gates"]), {
            "asset", "api_coverage", "topology_coverage", "edge_truth",
            "conclusion", "performance", "fixture_debt",
        })
        self.assertFalse(result["gates"]["asset"]["passed"])
        self.assertIn("project_checkout_missing", result["gates"]["asset"]["errors"])

    def test_pinned_guard_marks_original_finding_fixed_only_while_contract_passes(self):
        manifest_path = ROOT / "tests" / "fixtures" / "real_projects" / "gs-multi-module.json"
        manifest = self._manifest_with_expected_physical_edges(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )
        base = {"status": "passed", **self._passing_gs_guard_result(manifest)}
        asset = {"name": "asset", "passed": True, "errors": []}

        with tempfile.TemporaryDirectory() as tmp:
            passing = realreg.finalize_pinned_guard(manifest, dict(base), asset, Path(tmp) / "pass")
            conflict = json.loads(json.dumps(base))
            conflict["summary"]["reachable"] = 0
            conflict["summary"]["reachable_apis"] = []
            conflict["summary"]["uncertain"] = 1
            conflict["summary"]["uncertain_apis"] = [{
                "reason_code": "SOURCE_BYTECODE_EDGE_CONFLICT"
            }]
            failing = realreg.finalize_pinned_guard(
                manifest, conflict, asset, Path(tmp) / "fail"
            )

        self.assertEqual(passing["status"], "passed")
        self.assertTrue(passing["gates"]["fixture_debt"]["passed"])
        self.assertEqual(failing["status"], "failed")
        self.assertFalse(failing["gates"]["conclusion"]["passed"])
        self.assertFalse(failing["gates"]["fixture_debt"]["passed"])
        self.assertIn(
            "same_coordinate_multimodule_bridge:fixed_gates_incomplete:conclusion",
            failing["fixture_debt"]["errors"],
        )

    def test_cli_prints_all_seven_gate_results_on_asset_failure(self):
        gate_names = (
            "asset", "api_coverage", "topology_coverage", "edge_truth",
            "conclusion", "performance", "fixture_debt",
        )
        result = {
            "case": "gs-multi-module",
            "status": "failed",
            "reason": "pinned project asset invalid",
            "gates": {
                name: {"name": name, "passed": name != "asset", "errors": ["missing"] if name == "asset" else []}
                for name in gate_names
            },
        }
        output = __import__("io").StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(realreg, "run_case", return_value=result), patch("sys.stdout", output):
                returncode = realreg.main([
                    "--case", "gs-multi-module", "--report-root", tmp,
                ])

        self.assertEqual(returncode, 1)
        for name in gate_names:
            self.assertIn(f"gate {name}:", output.getvalue())

    def test_cli_passes_custom_oracle_manifest_to_single_real_project_case(self):
        result = {
            "case": "spring-petclinic", "status": "passed",
            "elapsed_seconds": 0.0, "report_dir": "/tmp/report",
            "summary": {}, "failures": [], "warnings": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            oracle_manifest = Path(tmp) / "project-test-oracle.csv"
            oracle_manifest.write_text("authority\nproject-tests\n", encoding="utf-8")
            with patch.object(realreg, "run_case", return_value=result) as run_case:
                returncode = realreg.main([
                    "--case", "spring-petclinic",
                    "--report-root", tmp,
                    "--oracle-manifest", str(oracle_manifest),
                    "--required-topology", "same_jar_bridge",
                ])

        self.assertEqual(returncode, 0)
        self.assertEqual(
            run_case.call_args.kwargs["oracle_manifest"], oracle_manifest
        )
        self.assertEqual(
            run_case.call_args.args[0].required_topologies,
            ("same_jar_bridge",),
        )


if __name__ == "__main__":
    unittest.main()
