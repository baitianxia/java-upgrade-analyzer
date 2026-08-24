from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_validation_oracle as oracle
from binary_tool_execution import BinaryToolFailure, BinaryToolResult


def scan_evidence():
    artifact_sha = "a" * 64
    return oracle._OracleScanEvidence(
        artifact_sha256=artifact_sha,
        complete=True,
        failures=(),
        direct_truth=oracle._DirectEdgeTruth(
            artifact_sha256=artifact_sha,
            direct_edges=frozenset({("caller", "target")}),
            dynamic_handle_edges=frozenset(),
            discovery_classes=frozenset({"p.C"}),
        ),
        structural_truth=oracle._StructuralTruth(
            type_edges=frozenset({("caller", "type")}),
            class_init_edges=frozenset({("caller", "clinit")}),
            clinit_classes=frozenset({"p.C"}),
            semantic_instructions=frozenset({("caller", "invoke", "target")}),
            declared_members=frozenset({("p.C", "m", "()V")}),
            failures=(),
        ),
        structural_class_names=frozenset({"p.C"}),
    )


class OracleProgressAndSidecarContractTest(unittest.TestCase):
    def test_environment_progress_callback_is_absent_without_report_and_bound_with_it(self):
        with patch.dict(os.environ, {"UPGRADE_REPORT_DIR": ""}, clear=False):
            self.assertIsNone(oracle._environment_progress_callback())

        with patch.dict(os.environ, {"UPGRADE_REPORT_DIR": "/report"}, clear=False), patch.object(
            oracle, "emit_progress",
        ) as emit:
            callback = oracle._environment_progress_callback()
            self.assertIsNotNone(callback)
            callback("phase", "message", 1, 2, "item")
        emit.assert_called_once()
        self.assertEqual(emit.call_args.args[:3], ("step4", "phase", "message"))
        self.assertEqual(emit.call_args.kwargs["report_dir"], "/report")

    def test_sidecar_stream_progress_is_attributed_to_sidecar_and_field(self):
        observed = []

        def canonical_rows(_path, _field, *, progress_callback=None):
            if progress_callback:
                progress_callback(5, 10)
            yield {"id": 1}

        with patch.object(
            oracle, "iter_canonical_json_object_array", side_effect=canonical_rows,
        ):
            rows = list(oracle._iter_sidecar_object_rows(
                Path("generation"), "binary_decisions.json", "facts",
                progress_callback=lambda *args: observed.append(args),
                progress_phase="phase",
            ))
        self.assertEqual(rows, [{"id": 1}])
        self.assertEqual(observed, [(
            "phase", "流式校验 binary_decisions.json:facts", 5, 10,
            "binary_decisions.json",
        )])


class OraclePersistenceContractTest(unittest.TestCase):
    def test_sqlite_logical_hash_ignores_only_header_change_counters(self):
        with tempfile.TemporaryDirectory() as temporary:
            left = Path(temporary) / "left.sqlite"
            connection = sqlite3.connect(left)
            connection.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO facts(value) VALUES ('one')")
            connection.commit()
            connection.close()

            raw = bytearray(left.read_bytes())
            self.assertTrue(raw.startswith(b"SQLite format 3\x00"))
            for start, end in ((24, 28), (40, 44), (92, 96)):
                raw[start:end] = bytes((value + 1) % 256 for value in raw[start:end])
            right = Path(temporary) / "right.sqlite"
            right.write_bytes(raw)
            self.assertEqual(
                oracle._sqlite_logical_content_sha256(left),
                oracle._sqlite_logical_content_sha256(right),
            )

            ordinary = Path(temporary) / "ordinary.bin"
            ordinary.write_bytes(b"not sqlite")
            self.assertEqual(
                oracle._sqlite_logical_content_sha256(ordinary),
                oracle._sha256_file(ordinary),
            )

    def test_rows_returns_independent_mappings_from_sqlite_rows(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE facts(id INTEGER, value TEXT)")
        connection.executemany("INSERT INTO facts VALUES (?, ?)", [(1, "a"), (2, "b")])
        try:
            self.assertEqual(oracle._rows(connection, "facts"), [
                {"id": 1, "value": "a"}, {"id": 2, "value": "b"},
            ])
        finally:
            connection.close()

    def test_scan_spool_len_and_repeatable_instruction_iteration_are_exact(self):
        cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=0)
        key = ("a" * 64, "javap")
        cache.put_evidence(key, scan_evidence())
        self.assertEqual(len(cache), 1)
        source = oracle._SpoolStructuralInstructionSource(
            cache, [{"sha256": "a" * 64}], "javap",
        )
        expected = [("caller", "invoke", "target")]
        self.assertEqual(list(source), expected)
        self.assertEqual(list(source), expected)
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_scan_spool_projects_raw_and_incomplete_views_without_false_truth(self):
        cache = oracle._OracleScanSpoolCache(memory_limit_per_entry=0)
        complete_key = ("b" * 64, "javap")
        cache.put_result(complete_key, {
            "artifact_sha256": "b" * 64,
            "complete": True,
            "failures": [],
            "edges": [],
            "structural_facts": {
                "type_edges": [],
                "class_init_edges": [],
                "clinit_classes": [],
                "semantic_instructions": [],
                "declared_members": [],
                "class_names": [],
            },
        })
        self.assertEqual(
            cache.get_projection(complete_key, "direct_edges"), frozenset(),
        )

        structural_key = ("c" * 64, "javap")
        cache.put_result(structural_key, {
            "artifact_sha256": "c" * 64,
            "complete": True,
            "failures": [],
            "edges": [],
            "structural_facts": {},
        })
        self.assertTrue(cache.get_structural_evidence(structural_key).complete)

        raw_incomplete_key = ("d" * 64, "javap")
        cache.put_result(raw_incomplete_key, {
            "artifact_sha256": "d" * 64,
            "complete": False,
            "failures": ["javap_failed"],
        })
        raw_incomplete = cache.get_direct_evidence(raw_incomplete_key)
        self.assertFalse(raw_incomplete.complete)
        self.assertEqual(raw_incomplete.failures, ("javap_failed",))

        projected_incomplete_key = ("e" * 64, "javap")
        cache.put_evidence(
            projected_incomplete_key,
            oracle._incomplete_oracle_scan_evidence(
                "e" * 64, ("partial_scan",),
            ),
        )
        self.assertFalse(
            cache.get_direct_evidence(projected_incomplete_key).complete
        )
        self.assertFalse(
            cache.get_structural_evidence(projected_incomplete_key).complete
        )
        self.assertFalse(cache.get_evidence(projected_incomplete_key).complete)

        pool = {}
        compacted = cache._compact_projection_rows(
            [("owner", ["nested", "value"])], pool,
        )
        self.assertEqual(
            compacted,
            frozenset({("owner", ("nested", "value"))}),
        )
        cache.clear()

    def test_non_sqlite_logical_comparison_delegates_to_streaming_equality(self):
        with tempfile.TemporaryDirectory() as temporary:
            left = Path(temporary) / "left.bin"
            right = Path(temporary) / "right.bin"
            left.write_bytes(b"same non-sqlite bytes")
            right.write_bytes(b"same non-sqlite bytes")
            self.assertTrue(oracle._sqlite_logical_contents_equal(left, right))

    def test_compile_oracle_retries_retryable_failure_and_reports_exhaustion(self):
        failure = BinaryToolFailure(
            stage="binary_oracle.compile",
            reason_code="BINARY_ORACLE_COMPILE_TIMEOUT",
            failure_kind="timeout",
            command=("javac",),
            timeout_seconds=1.0,
            returncode=None,
            stderr="timeout",
        )
        result = BinaryToolResult("", "timeout", -1, failure)
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            oracle, "jdk_tool_path", return_value=Path("/jdk/bin/javac"),
        ), patch.object(
            oracle, "execute_binary_tool", return_value=result,
        ) as execute:
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._compile_oracle(
                    Path(temporary) / "jdk",
                    Path(temporary) / "classes",
                    max_attempts=2,
                )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_ORACLE_COMPILE_RETRY_EXHAUSTED",
        )
        self.assertEqual(execute.call_count, 2)

    def test_owned_descriptor_preserves_primary_error_when_close_fails(self):
        class CloseFailingOs:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def close(_descriptor):
                raise OSError("close failed")

        primary = RuntimeError("primary")
        with patch.object(oracle, "os", CloseFailingOs()):
            with self.assertRaises(RuntimeError) as raised:
                with oracle._owned_descriptor(17, "fixture"):
                    raise primary
        self.assertIs(raised.exception, primary)
        self.assertTrue(any(
            "cleanup failed (close fixture)" in note
            for note in primary.__notes__
        ))

    def test_attachment_dispatch_uses_portable_writer_when_dirfd_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            oracle, "_secure_validation_dirfd_supported", return_value=False,
        ):
            generation = Path(temporary)
            destination = oracle._write_validation_attachment(
                generation, "validation-run", {"status": "passed"},
            )
            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"status": "passed"},
            )

    def test_portable_attachment_preserves_publish_error_and_cleanup_note(self):
        class LinkFailingOs:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def link(*_args, **_kwargs):
                raise OSError(errno.EIO, "publish failed")

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            oracle, "os", LinkFailingOs(),
        ), patch.object(
            Path, "unlink", side_effect=OSError(errno.EIO, "cleanup failed"),
        ):
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._write_validation_attachment_portable(
                    Path(temporary), "result.json", {"status": "failed"},
                )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertTrue(any(
            "cleanup failed (unlink temporary validation attachment" in note
            for note in raised.exception.__cause__.__notes__
        ))

    def test_dirfd_attachment_preserves_publish_error_and_cleanup_note(self):
        class PublishAndCleanupFailingOs:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def link(*_args, **_kwargs):
                raise OSError(errno.EIO, "publish failed")

            @staticmethod
            def unlink(*_args, **_kwargs):
                raise OSError(errno.EIO, "cleanup failed")

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            oracle, "os", PublishAndCleanupFailingOs(),
        ):
            with self.assertRaises(oracle.BinaryValidationError) as raised:
                oracle._write_validation_attachment_dirfd(
                    Path(temporary), "result.json", {"status": "failed"},
                )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_VALIDATION_ATTACHMENT_PATH_INVALID",
        )
        self.assertTrue(any(
            "cleanup failed (unlink temporary validation attachment" in note
            for note in raised.exception.__cause__.__notes__
        ))

    def test_cleanup_failure_note_is_attached_to_primary_exception(self):
        primary = RuntimeError("primary")
        oracle._add_validation_cleanup_note(primary, "cleanup failed")
        self.assertIn("cleanup failed", primary.__notes__)


class OracleIndependentFactContractTest(unittest.TestCase):
    def test_xml_facts_resolve_nested_refs_values_and_registration_types(self):
        content = b"""<beans xmlns:context="urn:context" xmlns:task="urn:task">
          <bean id="target" class="com.acme.Target" primary="true" init-method="start"/>
          <bean id="holder" class="com.acme.Holder">
            <property name="delegate"><ref bean="target"/></property>
          </bean>
          <bean id="job" class="org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean">
            <property name="targetObject" ref="target"/>
            <property name="targetMethod"><value>run</value></property>
          </bean>
          <context:component-scan base-package="com.acme"/>
          <task:scheduled target="target.tick"/>
          <mapper namespace="com.acme.Mapper"><select id="find" typeHandler="com.acme.Handler"/></mapper>
        </beans>"""
        facts = {tuple(item) for item in oracle._independent_xml_facts(content)}
        self.assertIn(("spring_bean_class", "target|com.acme.Target"), facts)
        self.assertIn(("spring_bean_primary", "target|com.acme.Target"), facts)
        self.assertIn(("spring_init_method", "target|com.acme.Target|start"), facts)
        self.assertIn(
            ("spring_bean_property_ref", "holder|com.acme.Holder|delegate|target|com.acme.Target"),
            facts,
        )
        self.assertIn(("spring_quartz_method", "target|com.acme.Target|run"), facts)
        self.assertIn(("spring_component_scan", "com.acme"), facts)
        self.assertIn(("spring_scheduled_method", "target|com.acme.Target|tick"), facts)
        self.assertIn(("mybatis_mapper_namespace", "com.acme.Mapper"), facts)
        self.assertIn(("mybatis_statement", "find"), facts)

        self.assertEqual(
            oracle._independent_xml_facts(b"<!DOCTYPE x [<!ENTITY y 'z'>]><x/>"),
            [["xml_parse_gap", "doctype_or_entity_rejected"]],
        )
        self.assertEqual(
            oracle._independent_xml_facts(b"<broken>"),
            [["xml_parse_gap", "malformed_xml"]],
        )

    def test_structural_raw_scan_compacts_every_tuple_family_before_comparison(self):
        type_edge = ("instance", "Owner", "m", "()V", "Target", "new")
        class_init = ("instance", "Owner", "Target", "trigger")
        semantic = ("instance", "Owner", "invoke", "Target")
        declared = ("instance", "Owner", "m", "()V")
        raw = {
            "type_edges": [type_edge],
            "class_init_edges": [class_init],
            "clinit_classes": ["Owner"],
            "semantic_instructions": [semantic],
            "declared_members": [declared],
            "failures": [],
        }
        artifact = {
            "loader_realm": "", "slot": 0, "path": "/artifact.jar", "sha256": "sha",
        }
        inventory = {"classes": {}}
        with patch.object(
            oracle, "_artifact_instance_bindings", return_value=({("", 0): "instance"}, []),
        ), patch.object(oracle, "_sha256_file", return_value="sha"), patch.object(
            oracle, "_production_structural_truth_for_artifact",
            return_value=(frozenset({type_edge}), frozenset({class_init})),
        ), patch.object(oracle, "_scan_structural_edges", return_value=raw):
            issues, truth = oracle._validate_structural_edges(
                MagicMock(), [artifact], [inventory], javap="javap",
                string_pool={}, retain_truth_rows=True,
            )
        self.assertEqual(issues, [])
        self.assertEqual(truth["type_edges"], [type_edge])
        self.assertEqual(truth["class_init_edges"], [class_init])
        self.assertEqual(truth["semantic_instructions"], [semantic])
        self.assertEqual(truth["declared_members"], [declared])

    def test_packaged_manifest_is_independently_parsed_for_main_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_path = root / "application.jar"
            with zipfile.ZipFile(artifact_path, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMain-Class: app.Main\n\n",
                )
            (root / "binary_entrypoints.json").write_text(
                json.dumps({
                    "records": [],
                    "coverage_status": "complete",
                    "coverage_gaps": [],
                }),
                encoding="utf-8",
            )
            issues, truth = oracle._validate_entrypoint_discovery(
                root,
                {
                    "runtime_profile": {
                        "business_entrypoint_profile": {},
                        "entrypoint_discovery_coverage_gaps": [],
                        "loader_topology": {
                            "entrypoint_realms": [], "realms": [],
                        },
                        "container_and_launcher_kind": "java-jar",
                    }
                },
                [{
                    "path": str(artifact_path),
                    "path_kind": "application",
                    "loader_realm": "application",
                    "slot": 0,
                }],
                {},
                [],
                [],
                [],
            )
        self.assertIsInstance(issues, list)
        self.assertEqual(truth["exact_entrypoint_count"], 0)


class OracleSemanticValidationContractTest(unittest.TestCase):
    def test_jdk8_provider_and_jfr_synthetic_dispatch_are_independently_checked(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE direct_edges("
            "direct_edge_identity TEXT PRIMARY KEY, edge_kind TEXT, "
            "symbolic_owner TEXT, symbolic_name TEXT, "
            "symbolic_descriptor TEXT, opcode INTEGER)"
        )
        connection.execute(
            "CREATE TABLE members("
            "member_identity TEXT PRIMARY KEY, class_name TEXT, "
            "member_name TEXT, descriptor TEXT)"
        )
        connection.execute(
            "INSERT INTO direct_edges VALUES(?,?,?,?,?,?)",
            ("edge-1", "method", "app/Event", "begin", "()V", 182),
        )
        connection.execute(
            "INSERT INTO members VALUES(?,?,?,?)",
            ("target-1", "app/Unexpected", "begin", "()V"),
        )
        observations = {
            "app/Event": {
                "status": "definition_ready",
                "provider_url": "",
                "provider_resource_url": "",
                "super_name": "jdk/jfr/Event",
                "interfaces": [],
                "members": ["method|begin|()V|4096"],
                "modifiers": 1,
            },
            "jdk/jfr/Event": {
                "status": "definition_ready",
                "provider_url": "",
                "provider_resource_url": "",
                "super_name": "",
                "interfaces": [],
                "members": [],
                "modifiers": 1,
            },
        }
        records = {
            "provider_binding": [],
            "class_definition": [],
            "member_resolution": [],
            "dispatch_resolution": [{
                "direct_edge_identity": "edge-1",
                "implementation_target_identities": ["target-1"],
                "dispatch_status": "exact",
            }],
        }
        try:
            with tempfile.TemporaryDirectory() as temporary:
                jdk_home = Path(temporary) / "jdk8"
                runtime_lib = jdk_home / "jre" / "lib"
                runtime_lib.mkdir(parents=True)
                (jdk_home / "release").write_text(
                    'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8",
                )
                runtime_archive = runtime_lib / "rt.jar"
                runtime_archive.write_bytes(b"runtime")
                provider_url = f"jar:{runtime_archive.as_uri()}!/app/Event.class"
                observations["app/Event"]["provider_resource_url"] = provider_url
                observations["app/Event"]["provider_url"] = runtime_archive.as_uri()
                observations["jdk/jfr/Event"]["provider_resource_url"] = (
                    f"jar:{runtime_archive.as_uri()}!/jdk/jfr/Event.class"
                )
                observations["jdk/jfr/Event"]["provider_url"] = (
                    runtime_archive.as_uri()
                )
                records["provider_binding"] = [{
                    "initiating_loader_realm_identity": "application",
                    "class_name": class_name,
                    "class_provider_status": "resolved",
                    "selected_artifact_instance_identity": "platform-image:jre",
                } for class_name in observations]
                records["class_definition"] = [{
                    "initiating_loader_realm_identity": "application",
                    "class_name": class_name,
                    "class_definition_status": "definition_ready",
                    "class_load_status": "ready",
                } for class_name in observations]
                with patch.object(
                    oracle, "_artifact_instance_bindings", return_value=({}, []),
                ), patch.object(
                    oracle, "_iter_reconciliation",
                    side_effect=lambda _connection, kind: iter(records[kind]),
                ):
                    issues, truth = oracle._validate_runtime_outcomes(
                        connection,
                        [],
                        [],
                        [{"classes": {"app/Event": "app/Event.class"}}],
                        observations,
                        ["application"],
                        ["app/Event"],
                        "platform",
                        jdk_home,
                    )
            self.assertEqual(truth["dispatch_count"], 1)
            self.assertIn(
                "ORACLE_DISPATCH_TARGET_MISMATCH",
                {item["reason_code"] for item in issues},
            )
        finally:
            connection.close()

    def test_pairing_resource_source_and_cross_version_mismatches_are_issues(self):
        with tempfile.TemporaryDirectory() as temporary:
            generation = Path(temporary)
            (generation / "binary_pairings.json").write_text(
                json.dumps({"pairings": []}), encoding="utf-8",
            )
            pairing_issues, pairing_truth = oracle._validate_pairings(
                generation,
                [{"lineage": "g:a"}],
                [{"lineage": "g:a"}],
            )
            self.assertEqual(pairing_truth["pairings"], {"g:a": "exact"})
            self.assertEqual(
                pairing_issues[0]["reason_code"], "ORACLE_PAIRING_MISMATCH",
            )

            with patch.object(oracle, "_reconciliation", return_value=[{
                "initiating_loader_realm_identity": "application",
                "resource_name": "META-INF/unexpected",
                "resource_mechanism": "classloader_first",
                "selected_resources": [],
            }]):
                resource_issues, _resource_truth = (
                    oracle._validate_resource_selections(
                        MagicMock(), [], [], [], {"realms": []},
                    )
                )
            self.assertEqual(
                resource_issues[0]["reason_code"],
                "ORACLE_RESOURCE_SELECTION_UNEXPECTED",
            )

            (generation / "binary_source_attestation.json").write_text(
                "{}", encoding="utf-8",
            )
            source_issues, source_truth = oracle._validate_source_attestation(
                generation, {},
            )
            self.assertEqual(source_truth["source_input_status"], "not_provided")
            self.assertEqual(
                source_issues[0]["reason_code"],
                "ORACLE_UNEXPECTED_SOURCE_ATTESTATION_PRESENT",
            )

            extra_decision = {
                "reason_code": "RUNTIME_MEMBER_RESOLUTION_CHANGED",
                "fact_scope": {
                    "class_name": "missing.Owner",
                    "member_name": "run",
                    "descriptor": "()V",
                },
                "evidence": {
                    "semantic_caller_edge": {
                        "caller_class": "app.Caller",
                        "caller_member": "call",
                        "caller_descriptor": "()V",
                        "bytecode_offset": 7,
                    },
                    "base_resolution": {"resolved_owner": "base.Owner"},
                    "current_resolution": {"resolved_owner": "current.Owner"},
                },
            }
            (generation / "binary_decisions.json").write_text(
                json.dumps({"authoritative_change_facts": [extra_decision]}),
                encoding="utf-8",
            )
            (generation / "binary_formal_results.json").write_text(
                json.dumps({"resource_activation_results": []}),
                encoding="utf-8",
            )
            cross_issues, _cross_truth = oracle._validate_cross_version_semantics(
                generation,
                {"current": {"runtime_profile": {
                    "business_entrypoint_profile": {"methods": []},
                }}},
                {
                    "base": {"direct_edges": [], "resource_selections": []},
                    "current": {
                        "direct_edges": [], "type_edges": [],
                        "resource_selections": [],
                    },
                },
                {"base": {}, "current": {}},
            )
            self.assertEqual(
                cross_issues[0]["reason_code"],
                "ORACLE_MEMBER_RESOLUTION_CHANGE_EXTRA",
            )


class OracleClosedWorldContractTest(unittest.TestCase):
    def test_closed_world_graph_admits_resolved_unresolved_type_init_and_semantic_edges(self):
        edges = [
            {
                "direct_edge_identity": "e1", "caller_member_identity": "caller1",
                "edge_kind": "method", "symbolic_owner": "p/Target",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
            },
            {
                "direct_edge_identity": "e2", "caller_member_identity": "caller2",
                "edge_kind": "field", "symbolic_owner": "p/Missing",
                "symbolic_name": "VALUE", "symbolic_descriptor": "I",
            },
        ]
        reconciliations = {
            "member_resolution": [
                {
                    "direct_edge_identity": "e1", "member_resolution_status": "resolved",
                    "resolved_member_identity": "target1",
                },
                {
                    "direct_edge_identity": "e2", "member_resolution_status": "no_such_member",
                    "resolved_member_identity": "",
                },
            ],
            "dispatch_resolution": [],
            "type_resolution": [{
                "direct_edge_identity": "e1", "type_resolution_status": "resolved",
            }],
            "class_initialization_resolution": [{
                "direct_edge_identity": "e1", "class_initialization_status": "resolved",
                "initializer_target_identities": ["clinit1"],
            }],
            "linkage_resolution": [{"direct_edge_identity": "e1", "status": "resolved"}],
        }
        connection = MagicMock()
        connection.row_factory = None
        decisions = {"authoritative_change_facts": [{
            "fact_scope": {
                "member_kind": "field", "member_change_kind": "removed",
                "class_name": "p.Missing", "member_name": "VALUE", "descriptor": "I",
            },
            "dependency_artifacts": [{"side": "base"}, {"side": "current"}],
            "evidence": {"current_unresolved_direct_edge_identities": ["e2"]},
        }]}
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            oracle, "_open_immutable_sqlite", return_value=connection,
        ), patch.object(oracle, "_rows", return_value=edges), patch.object(
            oracle, "_reconciliation", side_effect=lambda _conn, table: reconciliations[table],
        ), patch.object(
            oracle, "_iter_sidecar_object_rows",
            return_value=iter(decisions["authoritative_change_facts"]),
        ):
            transitions, relations, resolutions, linkages = oracle._load_closed_world_graph(
                Path(temporary),
                {"rows": [{
                    "caller_member_identity": "caller3",
                    "target_member_identity": "target3",
                    "path_certainty": "possible",
                    "semantic_edge_identity": "semantic1",
                }]},
            )
        connection.close.assert_called_once_with()
        self.assertIn(("target1", "exact", "e1"), transitions["caller1"])
        self.assertIn(("target3", "possible", "semantic1"), transitions["caller3"])
        self.assertTrue(any(item[1] == "exact" for item in transitions["caller2"]))
        self.assertIn("semantic1", relations)
        self.assertEqual(resolutions["e1"]["resolved_member_identity"], "target1")
        self.assertEqual(linkages["e1"]["status"], "resolved")


class OracleCliContractTest(unittest.TestCase):
    def test_cli_writes_optional_result_and_returns_validation_status(self):
        result = {"status": "passed", "issues": []}
        with patch.object(oracle, "_load_json", return_value={"config": True}), patch.object(
            oracle, "validate_generation", return_value=result,
        ) as validate, patch.object(oracle, "write_json_streaming_atomic") as write, patch.object(
            oracle, "stream_json",
        ) as stream:
            code = oracle.main([
                "--config", "config.json", "--generation-directory", "generation",
                "--output", "result.json",
            ])
        self.assertEqual(code, 0)
        validate.assert_called_once_with({"config": True}, "generation")
        write.assert_called_once_with(Path("result.json"), result, indent=2)
        stream.assert_called_once_with(result, oracle.sys.stdout, indent=2)

        with patch.object(oracle, "_load_json", return_value={}), patch.object(
            oracle, "validate_generation", return_value={"status": "failed"},
        ), patch.object(oracle, "stream_json"):
            self.assertEqual(
                oracle.main(["--config", "c", "--generation-directory", "g"]),
                1,
            )


if __name__ == "__main__":
    unittest.main()
