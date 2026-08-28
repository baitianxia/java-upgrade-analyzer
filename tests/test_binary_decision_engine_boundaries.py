import hashlib
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from tests import test_binary_decision_engine as existing


engine_module = existing.binary_decision_engine
BinaryDecisionEngine = existing.BinaryDecisionEngine
BinaryFactStore = existing.BinaryFactStore
BinaryFirstContractError = existing.BinaryFirstContractError


def runtime(
    identity="runtime",
    *,
    providers=(),
    definitions=(),
    members=(),
    resources=(),
    coverage_status="complete",
    coverage_gaps=(),
    runtime_profile_identity="profile",
):
    return SimpleNamespace(
        identity=identity,
        runtime_profile_identity=runtime_profile_identity,
        provider_bindings=tuple(providers),
        class_definitions=tuple(definitions),
        member_resolutions=tuple(members),
        dispatch_resolutions=(),
        type_resolutions=(),
        class_initialization_resolutions=(),
        linkage_resolutions=(),
        resource_selections=tuple(resources),
        coverage_status=coverage_status,
        coverage_gaps=tuple(coverage_gaps),
    )


def provider(
    class_name="demo/Api",
    *,
    realm="application-loader",
    status="resolved",
    artifact="artifact",
    variant="variant",
    identity="provider",
    evidence=None,
):
    return {
        "initiating_loader_realm_identity": realm,
        "class_name": class_name,
        "class_provider_status": status,
        "provider_binding_identity": identity,
        "selected_artifact_instance_identity": artifact,
        "selected_class_variant_identity": variant,
        "selected_defining_loader_realm_identity": realm,
        "selection_evidence": evidence or {},
    }


def definition(
    class_name="demo/Api",
    *,
    realm="application-loader",
    status="definition_ready",
    load_status="ready",
    identity="definition",
    evidence=None,
):
    return {
        "initiating_loader_realm_identity": realm,
        "class_name": class_name,
        "class_definition_status": status,
        "class_load_status": load_status,
        "class_definition_resolution_identity": identity,
        "evidence": evidence or {},
    }


class DecisionEngineBoundaryTest(unittest.TestCase):
    def test_empty_artifact_diffs_do_not_resolve_unused_dependency_rows(self):
        decision_engine = self.engine(diffs=({
            "base_artifact_instance_identity": "base-artifact",
            "current_artifact_instance_identity": "current-artifact",
            "logical_dependency_lineage": "unchanged",
            "entry_deltas": [],
        },))
        decision_engine._dependency_artifacts = lambda *_args, **_kwargs: (
            (_ for _ in ()).throw(
                AssertionError("empty diff resolved dependency rows")
            )
        )

        decision_engine._process_artifact_diffs()

        self.assertEqual(decision_engine.authoritative, [])
        self.assertEqual(decision_engine.diagnostic, [])
        self.assertEqual(decision_engine.excluded, [])

    def setUp(self):
        self.base_store = BinaryFactStore()
        self.current_store = BinaryFactStore()

    def tearDown(self):
        self.base_store.close()
        self.current_store.close()

    def engine(
        self,
        *,
        base_runtime=None,
        current_runtime=None,
        diffs=(),
        rules=None,
        context="analysis-context",
        comparison="runtime-comparison",
        shared=False,
    ):
        base_runtime = base_runtime or runtime()
        current_runtime = current_runtime or base_runtime
        arguments = {
            "analysis_context_identity": context,
            "runtime_comparison_identity": comparison,
            "base_store": self.base_store,
            "current_store": self.current_store,
            "base_reconciliation": base_runtime,
            "current_reconciliation": current_runtime,
            "artifact_local_diffs": diffs,
            "shared_runtime_evidence": shared,
        }
        if rules is not None:
            arguments["projection_rules"] = rules
        return BinaryDecisionEngine(**arguments)

    @staticmethod
    def add_artifact(
        store,
        artifact_identity,
        *,
        coord="g:a:1",
        path_kind="classpath",
        slot=0,
        origin="origin",
    ):
        store.connection.execute(
            """
            INSERT INTO artifact_instances(
                artifact_instance_identity,coord,outer_artifact_sha256,
                container_entry,content_sha256,runtime_profile_identity,
                loader_realm_identity,runtime_path_kind,
                runtime_classpath_index,container_loader_policy_version,
                runtime_code_source_origin_identity,inventory_digest,
                parser_identity,coverage_status
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                artifact_identity, coord, "outer", "<artifact>", "content",
                "profile", "application-loader", path_kind, slot,
                "flat-parent-first-v1", origin, "inventory", "parser",
                "complete",
            ),
        )

    @classmethod
    def add_class_edge(
        cls,
        store,
        *,
        artifact="artifact",
        variant="variant",
        class_name="demo/Caller",
        member="member",
        edge="edge",
        edge_kind="method",
        instruction_index=1,
        bytecode_offset=2,
        opcode=182,
        symbolic_owner="demo/Api",
        symbolic_name="value",
        symbolic_descriptor="()I",
        path_kind="classpath",
        slot=0,
        fact=None,
    ):
        if store.connection.execute(
            "SELECT 1 FROM artifact_instances WHERE artifact_instance_identity=?",
            (artifact,),
        ).fetchone() is None:
            cls.add_artifact(
                store, artifact, path_kind=path_kind, slot=slot,
            )
        entry = f"entry-{variant}"
        if store.connection.execute(
            "SELECT 1 FROM archive_entries WHERE physical_entry_identity=?",
            (entry,),
        ).fetchone() is None:
            store.connection.execute(
                """
                INSERT INTO archive_entries(
                    physical_entry_identity,artifact_instance_identity,name,
                    name_ordinal,archive_ordinal,kind,content_sha256,
                    byte_length,logical_class_entry,logical_resource_entry,
                    multi_release_version,resource_category,
                    normalized_resource_digest,resource_semantic_json,
                    entry_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    entry, artifact, f"{class_name}.class", 0, 0, "class",
                    "class-sha", 1, f"{class_name}.class", "", 0, "",
                    "", "{}", "{}",
                ),
            )
        fact = fact or {
            "class_name": class_name,
            "super_name": "java/lang/Object",
            "interfaces": [],
        }
        fact_zlib = zlib.compress(json.dumps(fact).encode("utf-8"))
        if store.connection.execute(
            "SELECT 1 FROM classes WHERE class_variant_identity=?", (variant,),
        ).fetchone() is None:
            store.connection.execute(
                """
                INSERT INTO classes(
                    class_variant_identity,artifact_instance_identity,
                    physical_entry_identity,physical_entry_label,class_name,
                    class_major,multi_release_version,class_bytes_sha256,
                    class_contract_digest,parse_status,failure_kind,
                    class_access,super_name,interfaces_json,nest_host,
                    nest_members_json,has_runtime_annotations,
                    class_bytes_zlib,fact_zlib,fact_zlib_sha256
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    variant, artifact, entry, f"{class_name}.class#occurrence=0",
                    class_name, 61, 0, "class-sha", "contract", "parsed", "",
                    1, fact.get("super_name"), json.dumps(fact.get("interfaces", [])),
                    None, "[]", 0, zlib.compress(b"class"),
                    fact_zlib, hashlib.sha256(fact_zlib).hexdigest(),
                ),
            )
        if store.connection.execute(
            "SELECT 1 FROM members WHERE member_identity=?", (member,),
        ).fetchone() is None:
            store.connection.execute(
                """
                INSERT INTO members(
                    member_identity,class_variant_identity,
                    artifact_instance_identity,class_name,member_kind,
                    member_name,descriptor,access_flags,contract_json,
                    implementation_digest
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    member, variant, artifact, class_name, "method", "call",
                    "()V", 1, "{}", "implementation",
                ),
            )
        store.connection.execute(
            """
            INSERT INTO direct_edges(
                direct_edge_identity,caller_member_identity,
                caller_artifact_instance_identity,caller_class_variant_identity,
                instruction_index,bytecode_offset,edge_kind,opcode,
                symbolic_owner,symbolic_name,symbolic_descriptor,edge_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                edge, member, artifact, variant, instruction_index,
                bytecode_offset, edge_kind, opcode, symbolic_owner,
                symbolic_name, symbolic_descriptor, "{}",
            ),
        )

    def test_json_and_compact_mapping_boundaries(self):
        same = engine_module._same_json_value
        self.assertTrue(same({}, {}))
        self.assertTrue(same({"a": [1, ("x",)]}, {"a": (1, ["x"])}))
        self.assertFalse(same({"a": 1}, {"b": 1}))
        self.assertFalse(same({"a": 1}, {"a": 2}))
        self.assertFalse(same([1], [1, 2]))
        self.assertFalse(same([1, True], [1, 1]))
        self.assertFalse(same({"a": 1}, [("a", 1)]))
        self.assertFalse(same([1], {"0": 1}))
        self.assertFalse(same(True, 1))
        self.assertTrue(same(None, None))

        fields = ("a", "b")
        first = engine_module._CompactDecisionRecord(
            {"a": 1, "extra": 2, "ignored": 3},
            fields,
            excluded_fields=frozenset({"ignored"}),
        )
        second = engine_module._CompactDecisionRecord({"a": 4, "b": 5}, fields)
        self.assertIs(first._index, second._index)
        self.assertEqual(dict(first), {"a": 1, "extra": 2})
        self.assertEqual(first["extra"], 2)
        with self.assertRaises(KeyError):
            _ = first["b"]
        with self.assertRaises(KeyError):
            _ = first["missing"]
        self.assertEqual(tuple(second), ("a", "b"))
        self.assertEqual(len(second), 2)

        pool = {}
        realm_left = bytes("application-loader", "utf-8").decode("utf-8")
        realm_right = bytes("application-loader", "utf-8").decode("utf-8")
        class_left = bytes("demo/Api", "utf-8").decode("utf-8")
        class_right = bytes("demo/Api", "utf-8").decode("utf-8")
        self.assertIsNot(realm_left, realm_right)
        self.assertIsNot(class_left, class_right)
        compact_fields = (
            "initiating_loader_realm_identity",
            "class_name",
            "class_provider_status",
        )
        left = engine_module._CompactDecisionRecord(
            {
                "initiating_loader_realm_identity": realm_left,
                "class_name": class_left,
                "class_provider_status": "resolved",
            },
            compact_fields,
            string_pool=pool,
        )
        right = engine_module._CompactDecisionRecord(
            {
                "initiating_loader_realm_identity": realm_right,
                "class_name": class_right,
                "class_provider_status": "resolved",
            },
            compact_fields,
            string_pool=pool,
        )
        self.assertEqual(dict(left), dict(right))
        self.assertIs(
            left["initiating_loader_realm_identity"],
            right["initiating_loader_realm_identity"],
        )
        self.assertIs(
            left["class_provider_status"],
            right["class_provider_status"],
        )
        self.assertIsNot(left["class_name"], right["class_name"])
        self.assertEqual(
            set(pool), {"application-loader", "resolved"}
        )

    def test_projection_rule_explicit_and_derived_identity(self):
        derived = engine_module.ProjectionRule("resource", "resource")
        explicit = engine_module.ProjectionRule(
            "resource", "resource", identity="third-party-rule",
        )
        self.assertTrue(derived.identity)
        self.assertEqual(explicit.identity, "third-party-rule")

    def test_shared_runtime_evidence_rejects_alias_and_transactions(self):
        reconciled = runtime()
        connection = self.base_store.connection
        same_connection_store = SimpleNamespace(connection=connection)
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._validate_shared_runtime_evidence(
                shared_runtime_evidence=True,
                base_store=self.base_store,
                current_store=same_connection_store,
                base_reconciliation=reconciled,
                current_reconciliation=reconciled,
            )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_DECISION_SHARED_RUNTIME_STORE_ALIAS",
        )

        for active_store in (self.base_store, self.current_store):
            with self.subTest(active_store=active_store is self.base_store):
                active_store.connection.execute("BEGIN")
                with self.assertRaises(BinaryFirstContractError) as raised:
                    BinaryDecisionEngine._validate_shared_runtime_evidence(
                        shared_runtime_evidence=True,
                        base_store=self.base_store,
                        current_store=self.current_store,
                        base_reconciliation=reconciled,
                        current_reconciliation=reconciled,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "BINARY_DECISION_SHARED_RUNTIME_STORE_UNCOMMITTED",
                )
                active_store.connection.rollback()

        BinaryDecisionEngine._validate_shared_runtime_evidence(
            shared_runtime_evidence=False,
            base_store=self.base_store,
            current_store=self.current_store,
            base_reconciliation=reconciled,
            current_reconciliation=reconciled,
        )

    def test_constructor_and_reconciliation_record_sources(self):
        in_memory_provider = provider()
        in_memory_definition = definition()
        reconciled = runtime(
            providers=(in_memory_provider,), definitions=(in_memory_definition,)
        )
        custom = engine_module.ProjectionRule(
            "custom", "type", identity="custom-rule",
        )
        built = self.engine(
            base_runtime=reconciled,
            current_runtime=reconciled,
            rules={"custom": custom},
            context="",
            comparison="",
        )
        self.assertEqual(built.context, "")
        self.assertEqual(built.runtime_comparison_identity, "")
        self.assertEqual(built.rules, {"custom": custom})
        self.assertEqual(
            tuple(BinaryDecisionEngine._reconciliation_records(
                self.base_store, reconciled, "provider_bindings",
                "provider_binding",
            )),
            (in_memory_provider,),
        )

        self.base_store.add_reconciliation_record(
            analysis_context_identity="analysis-context",
            record_kind="provider_binding",
            status="resolved",
            subject_identity="provider",
            payload=in_memory_provider,
        )
        fallback = runtime()
        self.assertEqual(
            tuple(BinaryDecisionEngine._reconciliation_records(
                self.base_store, fallback, "provider_bindings",
                "provider_binding",
            )),
            (in_memory_provider,),
        )

    def test_unique_indexes_lineages_and_observed_identity_contracts(self):
        rows = [
            {"realm": "a", "name": "x", "id": "first"},
            {"realm": "b", "name": "x", "id": "second"},
        ]
        indexed = BinaryDecisionEngine._unique_index(
            rows, ("realm", "name"), duplicate_code="DUP", identity_field="id",
        )
        self.assertEqual(set(indexed), {("a", "x"), ("b", "x")})
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._unique_index(
                [rows[0], dict(rows[0], id="duplicate")],
                ("realm", "name"), duplicate_code="DUP", identity_field="id",
            )
        self.assertEqual(raised.exception.reason_code, "DUP")

        diffs = (
            {
                "base_artifact_instance_identity": "",
                "current_artifact_instance_identity": "ABSENT:current",
                "logical_dependency_lineage": "ignored",
            },
            {
                "base_artifact_instance_identity": "artifact",
                "current_artifact_instance_identity": "current",
                "logical_dependency_lineage": " lineage ",
            },
            {
                "base_artifact_instance_identity": "artifact",
                "current_artifact_instance_identity": "other",
                "logical_dependency_lineage": "lineage",
            },
        )
        decision_engine = self.engine(diffs=diffs)
        self.assertEqual(decision_engine._base_artifact_lineages, {
            "artifact": "lineage",
        })
        with self.assertRaises(BinaryFirstContractError) as raised:
            self.engine(diffs=(
                {
                    "base_artifact_instance_identity": "artifact",
                    "current_artifact_instance_identity": "one",
                    "logical_dependency_lineage": "first",
                },
                {
                    "base_artifact_instance_identity": "artifact",
                    "current_artifact_instance_identity": "two",
                    "logical_dependency_lineage": "second",
                },
            ))
        self.assertEqual(
            raised.exception.reason_code, "ARTIFACT_LINEAGE_IDENTITY_CONFLICT",
        )
        self.assertEqual(
            BinaryDecisionEngine._upstream_observed_identity(
                {"observed_delta_identity": " observed "}, label="row",
            ),
            "observed",
        )
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._upstream_observed_identity({}, label="row")
        self.assertEqual(
            raised.exception.reason_code,
            "ARTIFACT_OBSERVED_DELTA_IDENTITY_MISSING",
        )

    def test_definition_payload_compact_and_persisted_paths(self):
        decision_engine = self.engine()
        key = ("application-loader", "demo/Api")
        self.assertIsNone(decision_engine._definition_payload("base", key))

        inline = definition(evidence={"inline": True})
        decision_engine._base_definitions[key] = inline
        self.assertEqual(decision_engine._definition_payload("base", key), inline)

        compact = engine_module._CompactDecisionRecord(
            definition(evidence={"persisted": True}),
            engine_module._DEFINITION_DECISION_FIELDS,
            excluded_fields=frozenset({"evidence"}),
        )
        decision_engine._base_definitions[key] = compact
        self.base_store.add_reconciliation_record(
            analysis_context_identity="analysis-context",
            record_kind="class_definition",
            status="resolved",
            subject_identity="definition",
            payload=definition(evidence={"persisted": True}),
        )
        self.assertEqual(
            decision_engine._definition_payload("base", key)["evidence"],
            {"persisted": True},
        )
        self.assertEqual(
            decision_engine._definition_payload("base", key)["evidence"],
            {"persisted": True},
        )

        decision_engine._current_definitions[key] = inline
        self.assertEqual(
            decision_engine._definition_payload("current", key), inline,
        )
        current_compact = engine_module._CompactDecisionRecord(
            definition(evidence={"current-persisted": True}),
            engine_module._DEFINITION_DECISION_FIELDS,
            excluded_fields=frozenset({"evidence"}),
        )
        decision_engine._current_definitions[key] = current_compact
        self.current_store.add_reconciliation_record(
            analysis_context_identity="analysis-context",
            record_kind="class_definition",
            status="resolved",
            subject_identity="current-definition",
            payload=definition(evidence={"current-persisted": True}),
        )
        self.assertEqual(
            decision_engine._definition_payload("current", key)["evidence"],
            {"current-persisted": True},
        )
        self.assertEqual(
            decision_engine._definition_payload("current", key)["evidence"],
            {"current-persisted": True},
        )

    def test_provider_resource_fingerprints_and_payload_variants(self):
        decision_engine = self.engine()
        self.assertIsNone(decision_engine._provider_payload(None))
        self.assertEqual(
            decision_engine._provider_payload({"a": 1}), {"a": 1},
        )
        self.assertEqual(
            decision_engine._provider_outcome_payload(
                self.base_store, None, {},
            ),
            None,
        )
        unresolved = provider(status="ambiguous", evidence={"why": "two"})
        self.assertEqual(
            decision_engine._provider_outcome_payload(
                self.base_store, unresolved, {},
            ),
            {"status": "ambiguous", "evidence": {"why": "two"}},
        )

        self.add_class_edge(self.base_store)
        resolved = provider()
        payload = decision_engine._provider_outcome_payload(
            self.base_store, resolved, {"artifact": "dependency:api"},
        )
        self.assertEqual(payload["logical_dependency_lineage"], "dependency:api")
        self.assertEqual(payload["runtime_path_kind"], "classpath")
        cached_metadata = decision_engine._artifact_runtime_metadata(
            self.base_store
        )
        self.assertIs(
            cached_metadata,
            decision_engine._artifact_runtime_metadata(self.base_store),
        )

        without_artifact = dict(resolved, selected_artifact_instance_identity="missing")
        fallback = decision_engine._provider_outcome_payload(
            self.base_store, without_artifact, {},
        )
        self.assertEqual(
            fallback["logical_dependency_lineage"], "runtime-slot:None:None",
        )
        empty_artifact = dict(resolved, selected_artifact_instance_identity="")
        empty_artifact_payload = decision_engine._provider_outcome_payload(
            self.base_store, empty_artifact, {},
        )
        self.assertEqual(
            empty_artifact_payload["logical_dependency_lineage"],
            "runtime-slot:None:None",
        )
        platform = dict(resolved, selected_class_variant_identity="platform-variant")
        platform_payload = decision_engine._provider_outcome_payload(
            self.base_store, platform, {},
        )
        self.assertEqual(
            platform_payload["platform_class_variant_identity"],
            "platform-variant",
        )
        self.assertEqual(
            decision_engine._provider_fingerprint(self.base_store, None, {}),
            "ABSENT",
        )
        self.assertNotEqual(
            decision_engine._provider_fingerprint(
                self.base_store, unresolved, {},
            ),
            "ABSENT",
        )

        self.assertEqual(
            BinaryDecisionEngine._resource_fingerprint(None), "ABSENT",
        )
        normalized = BinaryDecisionEngine._resource_fingerprint({
            "resource_name": "META-INF/LICENSE",
            "resource_category": "distribution_metadata",
            "resource_mechanism": "classloader_resource",
            "resource_selection_status": "resolved",
            "selected_resources": [{
                "runtime_classpath_index": 0,
                "runtime_code_source_origin_identity": "origin",
                "normalized_resource_digest": "normalized",
                "content_sha256": "bytes",
            }],
        })
        content = BinaryDecisionEngine._resource_fingerprint({
            "resource_name": "config.bin",
            "resource_category": "unknown",
            "resource_mechanism": "classloader_resource",
            "resource_selection_status": "resolved",
            "selected_resources": [{
                "runtime_classpath_index": 0,
                "runtime_code_source_origin_identity": "origin",
                "normalized_resource_digest": "normalized",
                "content_sha256": "bytes",
            }],
        })
        empty = BinaryDecisionEngine._resource_fingerprint({
            "resource_name": "empty", "selected_resources": None,
        })
        self.assertEqual(len({normalized, content, empty}), 3)

    def test_artifact_references_and_resource_dependency_deduplication(self):
        decision_engine = self.engine()
        self.assertIsNone(decision_engine._artifact_reference("base", ""))
        self.assertIsNone(
            decision_engine._artifact_reference("base", "ABSENT:base")
        )
        platform = decision_engine._artifact_reference(
            "base", "platform-image:java.base",
        )
        self.assertEqual(platform["coord"], "JDK_PLATFORM:java.base")
        self.assertIsNone(
            decision_engine._artifact_reference("base", "not-present")
        )

        self.add_artifact(
            self.base_store, "base-artifact", coord="", path_kind="", origin="",
        )
        reference = decision_engine._artifact_reference(
            "base", "base-artifact", lineage="dependency:api",
        )
        self.assertEqual(reference["logical_dependency_lineage"], "dependency:api")
        self.assertEqual(reference["coord"], "")
        dependencies = decision_engine._dependency_artifacts(
            "base-artifact", "platform-image:java.logging", lineage="same",
        )
        self.assertEqual([item["side"] for item in dependencies], ["base", "current"])

        resource_record = {
            "selected_resources": [
                {"artifact_instance_identity": "base-artifact"},
                {"artifact_instance_identity": "base-artifact"},
                {"artifact_instance_identity": "missing"},
                {"artifact_instance_identity": ""},
            ],
        }
        resource_dependencies = decision_engine._resource_dependency_artifacts(
            resource_record, None,
        )
        self.assertEqual(len(resource_dependencies), 1)

    def test_decision_channels_assessments_candidates_and_duplicates(self):
        decision_engine = self.engine()
        authoritative = decision_engine._decision(
            observed_identity="authoritative-observed",
            channel="authoritative",
            reason_code="CONFIRMED",
            fact_kind="method",
            fact_scope={"member": "m"},
            target_identity="target",
            coverage_gaps=("gap", "gap"),
            dependency_artifacts=(
                {"logical_dependency_lineage": "dependency:a"},
                {"logical_dependency_lineage": ""},
            ),
        )
        self.assertEqual(authoritative["change_fact_status"], "confirmed")
        self.assertEqual(
            decision_engine.assessments[-1]["projection_coverage_status"],
            "partial",
        )
        diagnostic = decision_engine._decision(
            observed_identity="diagnostic-observed",
            channel="diagnostic",
            reason_code="CANDIDATE",
            fact_kind="method",
            fact_scope={},
            target_identity="target",
        )
        self.assertEqual(diagnostic["candidate_fact_status"], "candidate")
        self.assertEqual(
            decision_engine.candidate_plans[-1]["planning_status"], "targetable",
        )
        incomplete = decision_engine._decision(
            observed_identity="incomplete-observed",
            channel="diagnostic",
            reason_code="INCOMPLETE",
            fact_kind="unknown",
            fact_scope={},
            coverage_gaps=("missing",),
        )
        self.assertEqual(incomplete["candidate_fact_status"], "incomplete")
        self.assertEqual(
            decision_engine.candidate_plans[-1]["planning_status"], "unbound",
        )
        excluded = decision_engine._decision(
            observed_identity="excluded-observed",
            channel="excluded",
            reason_code="EXCLUDED",
            fact_kind="unknown",
            fact_scope={},
        )
        self.assertEqual(excluded["exclusion_status"], "excluded")

        unsupported = {
            "decision_identity": "unsupported-decision",
            "change_fact_identity": "change",
            "fact_kind": "unknown",
            "analysis_target_identity": "",
        }
        decision_engine._assess(unsupported)
        self.assertEqual(
            decision_engine.assessments[-1]["analysis_projection_status"],
            "unsupported",
        )
        known_but_unbound = dict(unsupported, fact_kind="method")
        decision_engine._assess(known_but_unbound)
        decision_engine._candidate_plan(known_but_unbound | {
            "reason_code": "NO_TARGET", "coverage_gaps": (),
        })
        self.assertEqual(
            decision_engine.candidate_plans[-1]["planning_status"], "unbound",
        )

        with self.assertRaises(BinaryFirstContractError) as raised:
            decision_engine._decision(
                observed_identity="excluded-observed",
                channel="excluded",
                reason_code="EXCLUDED",
                fact_kind="unknown",
                fact_scope={},
            )
        self.assertEqual(
            raised.exception.reason_code, "DISPOSITION_OBLIGATION_DUPLICATE",
        )

    def test_resource_outcome_decision_matrix(self):
        records = {
            ("realm", "same", "loader"): ({
                "resource_name": "same", "resource_mechanism": "loader",
            }, {
                "resource_name": "same", "resource_mechanism": "loader",
            }),
            ("realm", "license", "loader"): ({
                "resource_name": "license", "resource_mechanism": "loader",
                "resource_category": "distribution_metadata",
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
            }, None),
            ("realm", "runtime", "loader"): (None, {
                "resource_name": "runtime", "resource_mechanism": "loader",
                "resource_category": "runtime_topology",
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
            }),
            ("realm", "partial", "loader"): ({
                "resource_name": "partial", "resource_mechanism": "loader",
                "resource_category": "unknown",
                "resource_selection_status": "old",
                "coverage_status": "partial",
                "coverage_gaps": ["base-gap"],
            }, {
                "resource_name": "partial", "resource_mechanism": "loader",
                "resource_category": "unknown",
                "resource_selection_status": "new",
                "coverage_status": "partial",
                "coverage_gaps": ["current-gap"],
            }),
            ("realm", "empty-gaps", "loader"): ({
                "resource_name": "empty-gaps", "resource_mechanism": "loader",
                "resource_category": "",
                "resource_selection_status": "old",
                "coverage_status": "partial",
                "coverage_gaps": [],
            }, {
                "resource_name": "empty-gaps", "resource_mechanism": "loader",
                "resource_category": "",
                "resource_selection_status": "new",
                "coverage_status": "complete",
            }),
        }
        base = {key: pair[0] for key, pair in records.items() if pair[0]}
        current = {key: pair[1] for key, pair in records.items() if pair[1]}
        decision_engine = self.engine(
            base_runtime=runtime(
                "base", coverage_status="partial", coverage_gaps=("runtime-base",)
            ),
            current_runtime=runtime(
                "current", coverage_status="partial",
                coverage_gaps=("runtime-current",),
            ),
        )
        decision_engine._base_resources = base
        decision_engine._current_resources = current
        decisions = []
        decision_engine._decision = lambda **item: decisions.append(item)
        decision_engine._resource_dependency_artifacts = lambda *_args: ()
        decision_engine._process_resource_outcome_deltas()
        self.assertEqual(len(decisions), 4)
        self.assertTrue(all(item["channel"] == "diagnostic" for item in decisions))

        complete_engine = self.engine(
            base_runtime=runtime("base"), current_runtime=runtime("current"),
        )
        complete_engine._base_resources = {
            key: value for key, value in base.items() if key[1] != "partial"
        }
        complete_engine._current_resources = {
            key: value for key, value in current.items() if key[1] != "partial"
        }
        complete_decisions = []
        complete_engine._decision = lambda **item: complete_decisions.append(item)
        complete_engine._resource_dependency_artifacts = lambda *_args: ()
        complete_engine._process_resource_outcome_deltas()
        by_name = {
            item["fact_scope"]["resource_name"]: item
            for item in complete_decisions
        }
        self.assertEqual(by_name["license"]["channel"], "excluded")
        self.assertEqual(by_name["runtime"]["channel"], "authoritative")

        partial_resource_engine = self.engine()
        partial_resource = []
        partial_resource_engine._decision = lambda **item: partial_resource.append(item)
        partial_resource_engine._process_resource_delta(
            {
                "entry_scope": {"entry_kind": "resource", "entry_name": "x"},
                "observed_delta_identity": "partial-resource-observed",
            },
            False,
            (),
        )
        self.assertEqual(
            partial_resource[0]["evidence"]["artifact_comparison_coverage_status"],
            "partial",
        )

    def test_artifact_diff_decision_matrix(self):
        class_scope = {
            "entry_name": "demo/Api.class",
            "name_ordinal": 0,
            "entry_kind": "class",
        }
        member_scope = {
            **class_scope,
            "member_kind": "method",
            "member_name": "value",
            "descriptor": "()I",
        }

        def artifact_diff(
            *, base="base-artifact", current="current-artifact",
            complete=True, entry=None,
        ):
            return {
                "base_artifact_instance_identity": base,
                "current_artifact_instance_identity": current,
                "logical_dependency_lineage": "dependency:api",
                "class_comparison_coverage_status": (
                    "complete" if complete else "partial"
                ),
                "entry_deltas": [entry],
            }

        ignored = {
            "entry_scope": class_scope,
            "runtime_effective_analysis": False,
        }
        resource_entry = {
            "entry_scope": {**class_scope, "entry_kind": "resource"},
            "observed_delta_identity": "resource-observed",
        }
        synthesized = {
            "entry_scope": class_scope,
            "base_content_sha256": "old",
            "current_content_sha256": "new",
            "class_change_category": "implementation_changed",
            "observed_delta_identity": "class-observed",
        }
        explicit_member = {
            **synthesized,
            "member_deltas": [{
                "member_scope": member_scope,
                "member_change_kind": "removed",
                "base_member_fingerprint": "old-member",
                "current_member_fingerprint": "",
                "observed_delta_identity": "member-observed",
            }],
        }

        selected = provider(artifact="base-artifact", identity="base-provider")
        current_selected = provider(
            artifact="current-artifact", identity="current-provider",
        )
        complete_runtime = runtime(
            providers=(selected,), definitions=(definition(),),
        )
        decision_engine = self.engine(
            base_runtime=complete_runtime,
            current_runtime=runtime(
                providers=(current_selected,), definitions=(definition(),),
            ),
            diffs=(
                artifact_diff(entry=ignored),
                artifact_diff(entry=resource_entry),
                artifact_diff(entry=synthesized),
                artifact_diff(entry=explicit_member),
            ),
        )
        decisions = []
        decision_engine._decision = lambda **item: decisions.append(item)
        decision_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        decision_engine._removed_member_consumer_edges = lambda: {
            (
                "application-loader", "demo/Api", "method", "value", "()I",
            ): ("unresolved-edge",),
        }
        decision_engine._process_artifact_diffs()
        self.assertEqual(len(decisions), 3)
        resource_decision = next(
            item for item in decisions if item["fact_kind"] == "resource"
        )
        self.assertEqual(
            resource_decision["reason_code"],
            "ARTIFACT_RESOURCE_OBSERVATION_RECONCILED_BY_SELECTION_VIEW",
        )
        removed = next(
            item for item in decisions
            if item["fact_scope"].get("member_change_kind") == "removed"
        )
        self.assertEqual(
            removed["evidence"]["current_unresolved_direct_edge_identities"],
            ["unresolved-edge"],
        )
        self.assertTrue(all(item["channel"] != "diagnostic" for item in decisions))

        shadowed_engine = self.engine(
            base_runtime=runtime(
                providers=(provider(artifact="other-base"),),
            ),
            current_runtime=runtime(
                providers=(provider(artifact="other-current"),),
            ),
            diffs=(artifact_diff(entry=explicit_member),),
        )
        shadowed = []
        shadowed_engine._decision = lambda **item: shadowed.append(item)
        shadowed_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        shadowed_engine._process_artifact_diffs()
        self.assertEqual(shadowed[0]["channel"], "excluded")

        incomplete_engine = self.engine(
            base_runtime=runtime(
                providers=(selected,), coverage_status="partial",
                coverage_gaps=("base-runtime-gap",),
            ),
            current_runtime=runtime(
                providers=(provider(status="ambiguous", artifact="other"),),
                coverage_status="partial",
                coverage_gaps=("current-runtime-gap",),
            ),
            diffs=(artifact_diff(complete=False, entry={
                **explicit_member, "class_change_category": "incomplete",
            }),),
        )
        incomplete = []
        incomplete_engine._decision = lambda **item: incomplete.append(item)
        incomplete_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        incomplete_engine._process_artifact_diffs()
        self.assertEqual(incomplete[0]["channel"], "diagnostic")
        self.assertIn(
            "artifact_delta_provider_correspondence_changed",
            incomplete[0]["coverage_gaps"],
        )
        self.assertIn(
            "base_class_definition_not_ready", incomplete[0]["coverage_gaps"],
        )

        absent_current = provider(status="missing", artifact="")
        removal_engine = self.engine(
            base_runtime=runtime(
                providers=(selected,), definitions=(definition(),),
            ),
            current_runtime=runtime(providers=(absent_current,)),
            diffs=(artifact_diff(entry=explicit_member),),
        )
        removal = []
        removal_engine._decision = lambda **item: removal.append(item)
        removal_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        removal_engine._removed_member_consumer_edges = lambda: {}
        removal_engine._process_artifact_diffs()
        self.assertNotIn(
            "artifact_delta_provider_correspondence_changed",
            removal[0]["coverage_gaps"],
        )

        added_entry = {
            **explicit_member,
            "member_deltas": [{
                **explicit_member["member_deltas"][0],
                "member_change_kind": "added",
            }],
        }
        addition_engine = self.engine(
            base_runtime=runtime(providers=(provider(status="missing", artifact=""),)),
            current_runtime=runtime(
                providers=(current_selected,), definitions=(definition(),),
            ),
            diffs=(artifact_diff(entry=added_entry),),
        )
        addition = []
        addition_engine._decision = lambda **item: addition.append(item)
        addition_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        addition_engine._process_artifact_diffs()
        self.assertNotIn(
            "artifact_delta_provider_correspondence_changed",
            addition[0]["coverage_gaps"],
        )

        current_only = provider(
            artifact="current-artifact", identity="", variant="variant",
        )
        base_only = provider(
            artifact="base-artifact", identity="", variant="variant",
        )
        empty_member_scope = {
            **class_scope,
            "member_kind": "method",
            "member_name": "",
            "descriptor": "",
        }
        edge_engine = self.engine(
            base_runtime=runtime(
                providers=(
                    base_only,
                    provider(
                        "demo/BaseOnly", artifact="base-artifact",
                        identity="", variant="base-only-variant",
                    ),
                ),
                definitions=(
                    definition(status="definition_failed"),
                    definition(
                        "demo/BaseOnly", status="definition_failed",
                    ),
                ),
            ),
            current_runtime=runtime(
                providers=(
                    current_only,
                    provider(
                        "demo/CurrentOnly", artifact="current-artifact",
                        identity="", variant="current-only-variant",
                    ),
                ),
                definitions=(
                    definition(status="definition_failed"),
                    definition(
                        "demo/CurrentOnly", status="definition_failed",
                    ),
                ),
            ),
            diffs=(
                artifact_diff(entry={
                    **synthesized,
                    "class_change_category": "incomplete",
                    "member_deltas": [{
                        "member_scope": empty_member_scope,
                        "member_change_kind": "removed",
                        "base_member_fingerprint": "",
                        "current_member_fingerprint": "",
                        "observed_delta_identity": "empty-member-observed",
                    }],
                }),
                {
                    **artifact_diff(entry={
                        **synthesized,
                        "entry_scope": {
                            **class_scope, "entry_name": "demo/BaseOnly.class",
                        },
                        "member_deltas": [{
                            "member_scope": {
                                **class_scope,
                                "entry_name": "demo/BaseOnly.class",
                                "member_kind": "class",
                                "member_name": "gone",
                                "descriptor": "Ldemo/BaseOnly;",
                            },
                            "member_change_kind": "removed",
                            "base_member_fingerprint": "old",
                            "current_member_fingerprint": "",
                            "observed_delta_identity": "base-only-observed",
                        }],
                    }),
                    "current_artifact_instance_identity": "other-current",
                },
                {
                    **artifact_diff(entry={
                        **synthesized,
                        "entry_scope": {
                            **class_scope, "entry_name": "demo/CurrentOnly.class",
                        },
                        "member_deltas": [{
                            "member_scope": {
                                **class_scope,
                                "entry_name": "demo/CurrentOnly.class",
                                "member_kind": "method",
                                "member_name": "added",
                                "descriptor": "()V",
                            },
                            "member_change_kind": "added",
                            "base_member_fingerprint": "",
                            "current_member_fingerprint": "new",
                            "observed_delta_identity": "current-only-observed",
                        }],
                    }),
                    "base_artifact_instance_identity": "other-base",
                },
            ),
        )
        edge_decisions = []
        edge_engine._decision = lambda **item: edge_decisions.append(item)
        edge_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        edge_engine._removed_member_consumer_edges = lambda: {}
        edge_engine._process_artifact_diffs()
        self.assertEqual(len(edge_decisions), 3)

        missing_current_definition_engine = self.engine(
            base_runtime=runtime(providers=(selected,), definitions=(definition(),)),
            current_runtime=runtime(providers=(current_selected,)),
            diffs=(artifact_diff(entry=explicit_member),),
        )
        missing_current_definition = []
        missing_current_definition_engine._decision = (
            lambda **item: missing_current_definition.append(item)
        )
        missing_current_definition_engine._dependency_artifacts = (
            lambda *_args, **_kwargs: ()
        )
        missing_current_definition_engine._removed_member_consumer_edges = lambda: {}
        missing_current_definition_engine._process_artifact_diffs()
        self.assertIn(
            "current_class_definition_not_ready",
            missing_current_definition[0]["coverage_gaps"],
        )

    def test_runtime_outcome_decision_matrix(self):
        same_missing = provider(status="missing", artifact="", variant="")
        base_records = (
            same_missing,
            provider("demo/Provider", status="ambiguous", artifact="", variant=""),
            provider("demo/Definition", status="missing", artifact="", variant=""),
            provider("demo/Indefinite", status="missing", artifact="", variant=""),
        )
        current_records = (
            same_missing,
            provider("demo/Provider", status="unresolved", artifact="", variant=""),
            provider("demo/Definition", status="missing", artifact="", variant=""),
            provider("demo/Indefinite", status="missing", artifact="", variant=""),
        )
        base_definitions = (
            definition("demo/Definition", status="definition_ready"),
        )
        current_definitions = (
            definition("demo/Definition", status="definition_failed"),
            definition("demo/Indefinite", status="unsupported"),
        )
        decision_engine = self.engine(
            base_runtime=runtime(
                "base", providers=base_records, definitions=base_definitions,
                coverage_status="partial", coverage_gaps=("base-gap",),
            ),
            current_runtime=runtime(
                "current", providers=current_records,
                definitions=current_definitions,
                coverage_status="partial", coverage_gaps=("current-gap",),
            ),
        )
        decisions = []
        decision_engine._decision = lambda **item: decisions.append(item)
        decision_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        decision_engine._process_resource_outcome_deltas = lambda: None
        decision_engine._process_runtime_outcome_deltas()
        self.assertEqual(len(decisions), 3)
        self.assertTrue(all(item["channel"] == "diagnostic" for item in decisions))
        self.assertTrue(any(
            "base_provider_unresolved" in item["coverage_gaps"]
            and "current_provider_unresolved" in item["coverage_gaps"]
            for item in decisions
        ))
        indefinite = next(
            item for item in decisions
            if item["fact_scope"]["class_name"] == "demo/Indefinite"
        )
        self.assertEqual(
            indefinite["coverage_gaps"], ["base-gap", "current-gap"],
        )

        complete_engine = self.engine(
            base_runtime=runtime(
                "base", providers=(same_missing,),
                definitions=(definition(status="definition_ready"),),
            ),
            current_runtime=runtime(
                "current", providers=(provider(status="unresolved", artifact="", variant=""),),
                definitions=(definition(status="definition_failed"),),
            ),
        )
        complete = []
        complete_engine._decision = lambda **item: complete.append(item)
        complete_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        complete_engine._process_resource_outcome_deltas = lambda: None
        complete_engine._process_runtime_outcome_deltas()
        self.assertEqual(
            {item["fact_kind"] for item in complete},
            {"provider_topology", "class_definition"},
        )

        definitive_engine = self.engine(
            base_runtime=runtime(
                "base", providers=(same_missing,),
                definitions=(definition(status="definition_ready"),),
            ),
            current_runtime=runtime(
                "current", providers=(same_missing,),
                definitions=(definition(status="definition_failed"),),
            ),
        )
        definitive = []
        definitive_engine._decision = lambda **item: definitive.append(item)
        definitive_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        definitive_engine._process_resource_outcome_deltas = lambda: None
        definitive_engine._process_runtime_outcome_deltas()
        self.assertEqual(definitive[0]["channel"], "authoritative")

        base_only_provider = provider(
            status="missing", artifact="base-artifact", variant="",
        )
        absent_current_engine = self.engine(
            base_runtime=runtime(
                "base", providers=(base_only_provider,),
                definitions=(definition(status="definition_ready"),),
            ),
            current_runtime=runtime(
                "current", definitions=(definition(status="unsupported"),),
            ),
            diffs=({
                "base_artifact_instance_identity": "base-artifact",
                "current_artifact_instance_identity": "current-artifact",
                "logical_dependency_lineage": "same-lineage",
                "entry_deltas": [],
            },),
        )
        absent_current = []
        absent_current_engine._decision = lambda **item: absent_current.append(item)
        absent_current_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        absent_current_engine._process_resource_outcome_deltas = lambda: None
        absent_current_engine._process_runtime_outcome_deltas()
        self.assertEqual(
            {item["fact_kind"] for item in absent_current},
            {"provider_topology", "class_definition"},
        )
        absent_provider = next(
            item for item in absent_current
            if item["fact_kind"] == "provider_topology"
        )
        self.assertEqual(absent_provider["channel"], "diagnostic")
        self.assertIn(
            "current_provider_observation_missing",
            absent_provider["coverage_gaps"],
        )

        current_only_provider = provider(
            status="unresolved", artifact="current-artifact", variant="",
        )
        current_only_engine = self.engine(
            base_runtime=runtime("base"),
            current_runtime=runtime(
                "current", providers=(current_only_provider,),
                definitions=(definition(status="definition_ready"),),
            ),
            diffs=({
                "base_artifact_instance_identity": "base-artifact",
                "current_artifact_instance_identity": "current-artifact",
                "logical_dependency_lineage": "same-lineage",
                "entry_deltas": [],
            },),
        )
        current_only = []
        current_only_engine._decision = lambda **item: current_only.append(item)
        current_only_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        current_only_engine._process_resource_outcome_deltas = lambda: None
        current_only_engine._process_runtime_outcome_deltas()
        self.assertTrue(current_only)

        lineaged_base = provider(
            status="missing", artifact="base-artifact", variant="",
        )
        lineaged_current = provider(
            status="unresolved", artifact="current-artifact", variant="",
        )
        for current_lineage in ("same-lineage", "different-lineage"):
            with self.subTest(current_lineage=current_lineage):
                lineaged_engine = self.engine(
                    base_runtime=runtime("base", providers=(lineaged_base,)),
                    current_runtime=runtime("current", providers=(lineaged_current,)),
                    diffs=(
                        {
                            "base_artifact_instance_identity": "base-artifact",
                            "current_artifact_instance_identity": "unused-current",
                            "logical_dependency_lineage": "same-lineage",
                            "entry_deltas": [],
                        },
                        {
                            "base_artifact_instance_identity": "unused-base",
                            "current_artifact_instance_identity": "current-artifact",
                            "logical_dependency_lineage": current_lineage,
                            "entry_deltas": [],
                        },
                    ),
                )
                lineaged = []
                lineaged_engine._decision = lambda **item: lineaged.append(item)
                lineaged_engine._dependency_artifacts = lambda *_args, **kwargs: (
                    {"lineage": kwargs.get("lineage")},
                )
                lineaged_engine._process_resource_outcome_deltas = lambda: None
                lineaged_engine._process_runtime_outcome_deltas()
                self.assertEqual(
                    lineaged[0]["dependency_artifacts"][0]["lineage"],
                    "same-lineage" if current_lineage == "same-lineage" else "",
                )

        empty_mapping_engine = self.engine(
            base_runtime=runtime("base", providers=(same_missing,)),
            current_runtime=runtime("current", providers=(same_missing,)),
        )
        key = ("application-loader", "demo/Api")
        empty_mapping_engine._current_providers[key] = {}
        empty_mapping = []
        empty_mapping_engine._decision = lambda **item: empty_mapping.append(item)
        empty_mapping_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        empty_mapping_engine._process_resource_outcome_deltas = lambda: None
        empty_mapping_engine._process_runtime_outcome_deltas()
        self.assertTrue(empty_mapping)

    def test_resolution_payloads_and_legacy_pairing(self):
        self.assertEqual(
            BinaryDecisionEngine._resolution_payloads_for_edges(
                self.base_store, runtime(), set(),
            ),
            {},
        )
        records = (
            {},
            {"direct_edge_identity": "ignored"},
            {"direct_edge_identity": "wanted", "status": "resolved"},
        )
        self.assertEqual(
            BinaryDecisionEngine._resolution_payloads_for_edges(
                self.base_store, runtime(members=records), {"wanted"},
            )["wanted"]["status"],
            "resolved",
        )
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._resolution_payloads_for_edges(
                self.base_store,
                runtime(members=(records[2], dict(records[2]))),
                {"wanted"},
            )
        self.assertEqual(
            raised.exception.reason_code, "MEMBER_RESOLUTION_EDGE_DUPLICATE",
        )
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._resolution_payloads_for_edges(
                self.base_store, runtime(members=records), {"missing"},
            )
        self.assertEqual(
            raised.exception.reason_code, "MEMBER_RESOLUTION_EDGE_MISSING",
        )

        semantic_key = ("lineage",)
        same_resolution = {
            "member_resolution_status": "resolved",
            "resolved_owner": "demo/Api",
            "resolved_defining_loader_realm_identity": "realm",
        }
        changed_resolution = dict(
            same_resolution, member_resolution_status="no_such_member",
        )
        decision_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        decision_engine._paired_semantic_member_outcome_deltas_cache = None
        decision_engine._paired_semantic_member_edges_cache = (
            {
                semantic_key: ({"direct_edge_identity": "base"}, same_resolution, {}),
                ("same",): ({}, {}, {}),
                ("base-only",): ({}, same_resolution, {}),
            },
            {
                semantic_key: ({"direct_edge_identity": "current"}, changed_resolution, {}),
                ("same",): ({}, {}, {}),
                ("current-only",): ({}, same_resolution, {}),
            },
        )
        paired = decision_engine._paired_semantic_member_outcome_deltas()
        self.assertEqual(len(paired), 1)
        self.assertIs(
            paired, decision_engine._paired_semantic_member_outcome_deltas(),
        )

    def test_streaming_pair_merge_orders_and_closes_iterators(self):
        decision_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        decision_engine._paired_semantic_member_outcome_deltas_cache = None
        decision_engine._paired_semantic_member_edges_cache = None
        decision_engine.base_store = self.base_store
        decision_engine.current_store = self.current_store
        decision_engine.base_runtime = runtime(members=({"direct_edge_identity": "base-diff"},))
        decision_engine.current_runtime = runtime(members=({"direct_edge_identity": "current-diff"},))
        decision_engine._base_artifact_lineages = {}
        decision_engine._current_artifact_lineages = {}
        decision_engine._base_providers = {}
        decision_engine._current_providers = {}
        base_rows = [
            (("a",), {"direct_edge_identity": "base-a"}, ("resolved", "A", "r")),
            (("c",), {"direct_edge_identity": "base-diff"}, ("resolved", "A", "r")),
            (("d",), {"direct_edge_identity": "base-d"}, ("resolved", "A", "r")),
        ]
        current_rows = [
            (("b",), {"direct_edge_identity": "current-b"}, ("resolved", "A", "r")),
            (("c",), {"direct_edge_identity": "current-diff"}, ("no_such_member", "", "")),
            (("d",), {"direct_edge_identity": "current-d"}, ("resolved", "A", "r")),
        ]

        def rows(*_args, **_kwargs):
            selected = base_rows if not getattr(rows, "used", False) else current_rows
            rows.used = True
            yield from selected

        rows.used = False
        with patch.object(
            BinaryDecisionEngine, "_iter_semantic_member_edges", side_effect=rows,
        ):
            paired = decision_engine._paired_semantic_member_outcome_deltas()
        self.assertEqual(len(paired), 1)
        self.assertEqual(paired[0][0], ("c",))

        uncached = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        uncached._paired_semantic_member_outcome_deltas_cache = None
        uncached._paired_semantic_member_edges_cache = None
        uncached.base_store = self.base_store
        uncached.current_store = self.current_store
        uncached.base_runtime = runtime()
        uncached.current_runtime = runtime()
        uncached._base_artifact_lineages = {}
        uncached._current_artifact_lineages = {}
        uncached._base_providers = {}
        uncached._current_providers = {}
        with patch.object(
            BinaryDecisionEngine,
            "_iter_semantic_member_edges",
            side_effect=[iter(()), iter(())],
        ):
            self.assertEqual(
                uncached._paired_semantic_member_outcome_deltas(), (),
            )

        one_sided = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        one_sided._paired_semantic_member_outcome_deltas_cache = None
        one_sided._paired_semantic_member_edges_cache = None
        one_sided.base_store = self.base_store
        one_sided.current_store = self.current_store
        one_sided.base_runtime = runtime()
        one_sided.current_runtime = runtime()
        one_sided._base_artifact_lineages = {}
        one_sided._current_artifact_lineages = {}
        one_sided._base_providers = {}
        one_sided._current_providers = {}
        with patch.object(
            BinaryDecisionEngine,
            "_iter_semantic_member_edges",
            side_effect=[
                iter([(("base",), {"direct_edge_identity": "base"}, ("x", "", ""))]),
                iter(()),
            ],
        ):
            self.assertEqual(one_sided._paired_semantic_member_outcome_deltas(), ())

    def test_removed_member_consumer_filtering_and_cache(self):
        decision_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        decision_engine._removed_member_consumer_edges_cache = None
        method_edge = {
            "edge_kind": "method", "symbolic_name": "m",
            "symbolic_descriptor": "()V",
        }
        field_edge = {
            "edge_kind": "field", "symbolic_name": "f",
            "symbolic_descriptor": "I",
        }
        resolved = {
            "member_resolution_status": "resolved",
            "resolved_owner": "demo/Parent",
            "initiating_loader_realm_identity": "base-realm",
        }
        no_such = {
            "member_resolution_status": "no_such_member",
            "initiating_loader_realm_identity": "current-realm",
        }
        decision_engine._paired_semantic_member_outcome_deltas = lambda: (
            ((), method_edge, {**resolved, "member_resolution_status": "ambiguous"},
             {"direct_edge_identity": "ignored-a"}, no_such),
            ((), method_edge, resolved, {"direct_edge_identity": "ignored-b"},
             {**no_such, "member_resolution_status": "resolved"}),
            ((), method_edge, resolved, {"direct_edge_identity": "method-edge"}, no_such),
            ((), field_edge, {**resolved, "initiating_loader_realm_identity": "fallback"},
             {"direct_edge_identity": "field-edge"},
             {"member_resolution_status": "no_such_member"}),
            ((), field_edge, resolved, {"direct_edge_identity": "field-edge"}, no_such),
            (
                (),
                {"edge_kind": "field", "symbolic_name": "", "symbolic_descriptor": ""},
                {
                    "member_resolution_status": "resolved",
                    "resolved_owner": "",
                    "initiating_loader_realm_identity": "",
                },
                {"direct_edge_identity": "empty-edge"},
                {
                    "member_resolution_status": "no_such_member",
                    "initiating_loader_realm_identity": "",
                },
            ),
        )
        grouped = decision_engine._removed_member_consumer_edges()
        self.assertEqual(
            grouped[("current-realm", "demo/Parent", "method", "m", "()V")],
            ("method-edge",),
        )
        self.assertEqual(
            grouped[("current-realm", "demo/Parent", "field", "f", "I")],
            ("field-edge",),
        )
        self.assertIs(grouped, decision_engine._removed_member_consumer_edges())
        self.assertEqual(grouped[("", "", "field", "", "")], ("empty-edge",))

    def test_member_resolution_decision_definite_and_incomplete(self):
        key = (
            "lineage", "classpath", "demo/Caller", "call", "()V", 1, 2,
        )
        base_edge = {
            "direct_edge_identity": "base-edge", "edge_kind": "field",
            "symbolic_owner": "demo/Child", "symbolic_name": "field",
            "symbolic_descriptor": "I",
        }
        current_edge = dict(base_edge, direct_edge_identity="current-edge")
        base_resolution = {
            "member_resolution_status": "resolved",
            "resolved_owner": "demo/Parent",
            "resolved_defining_loader_realm_identity": "base-realm",
            "initiating_loader_realm_identity": "fallback-realm",
        }
        same_resolution = dict(base_resolution)
        incomplete_resolution = {
            "member_resolution_status": "ambiguous",
            "resolved_owner": "",
            "resolved_defining_loader_realm_identity": "",
            "initiating_loader_realm_identity": "",
        }
        decision_engine = self.engine()
        decision_engine._paired_semantic_member_outcome_deltas = lambda: (
            (key, base_edge, base_resolution, current_edge, same_resolution),
            (key, base_edge, base_resolution, current_edge, incomplete_resolution),
            (
                key,
                {
                    "direct_edge_identity": "empty-base-edge",
                    "edge_kind": "method",
                    "symbolic_owner": "",
                    "symbolic_name": "",
                    "symbolic_descriptor": "",
                },
                {
                    "member_resolution_status": "resolved",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
                {
                    "direct_edge_identity": "empty-current-edge",
                    "edge_kind": "method",
                    "symbolic_owner": "",
                    "symbolic_name": "",
                    "symbolic_descriptor": "",
                },
                {
                    "member_resolution_status": "no_such_member",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
            ),
        )
        decision_engine._current_hierarchy_contains = lambda *_args: False
        decision_engine._base_providers = {
            ("fallback-realm", "demo/Child"): provider(
                "demo/Child", realm="fallback-realm", artifact="base-provider-artifact",
            ),
        }
        decision_engine._current_providers = {
            ("fallback-realm", "demo/Child"): provider(
                "demo/Child", realm="fallback-realm",
                artifact="current-provider-artifact",
            ),
        }
        decision_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        decisions = []
        decision_engine._decision = lambda **item: decisions.append(item)
        decision_engine._process_member_resolution_deltas()
        self.assertEqual(len(decisions), 2)
        self.assertEqual(decisions[0]["channel"], "diagnostic")
        self.assertEqual(decisions[0]["fact_kind"], "member_resolution")
        self.assertEqual(decisions[0]["fact_scope"]["member_kind"], "field")

        predicate_engine = self.engine()
        predicate_engine._paired_semantic_member_outcome_deltas = lambda: (
            (
                key,
                dict(base_edge, edge_kind="method"),
                {
                    "member_resolution_status": "",
                    "resolved_owner": "demo/Parent",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
                dict(current_edge, edge_kind="method"),
                {
                    "member_resolution_status": "ambiguous",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
            ),
            (
                key,
                dict(base_edge, edge_kind="method"),
                base_resolution,
                dict(current_edge, edge_kind="method"),
                {
                    "member_resolution_status": "no_such_member",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "fallback-realm",
                },
            ),
            (
                key,
                dict(base_edge, edge_kind="method"),
                {
                    "member_resolution_status": "ambiguous",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
                dict(current_edge, edge_kind="method"),
                {
                    "member_resolution_status": "",
                    "resolved_owner": "",
                    "resolved_defining_loader_realm_identity": "",
                    "initiating_loader_realm_identity": "",
                },
            ),
        )
        predicate_engine._current_hierarchy_contains = lambda *_args: False
        predicate_engine._dependency_artifacts = lambda *_args, **_kwargs: ()
        predicate = []
        predicate_engine._decision = lambda **item: predicate.append(item)
        predicate_engine._process_member_resolution_deltas()
        self.assertEqual(len(predicate), 3)

    def test_current_hierarchy_cycles_empty_parents_and_definition_fallback(self):
        decision_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        decision_engine._current_hierarchy_parent_cache = {}
        graph = {
            "child": ("", "middle"),
            "middle": ("child", "ancestor"),
        }
        decision_engine._current_class_parents = lambda _realm, name: graph.get(name, ())
        self.assertFalse(
            decision_engine._current_hierarchy_contains("realm", "", "ancestor")
        )
        self.assertFalse(
            decision_engine._current_hierarchy_contains("realm", "child", "")
        )
        self.assertTrue(
            decision_engine._current_hierarchy_contains("realm", "child", "child")
        )
        self.assertTrue(
            decision_engine._current_hierarchy_contains("realm", "child", "ancestor")
        )
        self.assertFalse(
            decision_engine._current_hierarchy_contains("realm", "child", "missing")
        )
        cycle_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        cycle_engine._current_class_parents = lambda _realm, name: (name,)
        self.assertFalse(
            cycle_engine._current_hierarchy_contains("realm", "cycle", "missing")
        )
        converging_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        converging_graph = {
            "root": ("shared", "branch"),
            "branch": ("shared",),
        }
        converging_engine._current_class_parents = (
            lambda _realm, name: converging_graph.get(name, ())
        )
        self.assertFalse(
            converging_engine._current_hierarchy_contains(
                "realm", "root", "missing",
            )
        )

        class Result:
            def __init__(self, row):
                self.row = row

            def fetchone(self):
                return self.row

        facts = {
            "tuple-variant": (
                zlib.compress(json.dumps({
                    "super_name": None, "interfaces": [],
                }).encode("utf-8")),
            ),
            "fact-variant": {
                "fact_zlib": zlib.compress(json.dumps({
                    "super_name": "FactParent", "interfaces": ["FactInterface"],
                }).encode("utf-8")),
            },
        }
        connection = SimpleNamespace(
            execute=lambda _query, parameters: Result(facts.get(parameters[0]))
        )
        hierarchy_engine = BinaryDecisionEngine.__new__(BinaryDecisionEngine)
        hierarchy_engine.current_store = SimpleNamespace(connection=connection)
        hierarchy_engine._current_providers = {
            ("realm", "tuple"): {"selected_class_variant_identity": "tuple-variant"},
            ("realm", "fact"): {"selected_class_variant_identity": "fact-variant"},
            ("realm", "missing"): {"selected_class_variant_identity": "missing-variant"},
        }
        hierarchy_engine._current_definitions = {
            ("realm", "tuple"): definition(
                "tuple", realm="realm", evidence={
                    "target_jvm_verification": {
                        "super_name": "VerifierParent",
                        "interfaces": ["VerifierInterface"],
                    },
                },
            ),
        }
        hierarchy_engine._current_hierarchy_parent_cache = None
        self.assertEqual(
            hierarchy_engine._current_class_parents("realm", "fact"),
            ("FactParent", "FactInterface"),
        )
        self.assertEqual(
            hierarchy_engine._current_class_parents("realm", "tuple"),
            ("VerifierParent", "VerifierInterface"),
        )
        self.assertEqual(
            hierarchy_engine._current_class_parents("realm", "missing"), (),
        )
        self.assertEqual(
            hierarchy_engine._current_class_parents("realm", "none"), (),
        )
        self.assertEqual(
            hierarchy_engine._current_class_parents("realm", "fact"),
            ("FactParent", "FactInterface"),
        )

    def test_iter_semantic_edges_filters_duplicates_batch_and_cleanup(self):
        self.add_class_edge(self.base_store, edge="edge")
        resolution = {
            "direct_edge_identity": "edge",
            "member_resolution_status": "resolved",
            "resolved_owner": "demo/Api",
            "resolved_defining_loader_realm_identity": "application-loader",
            "initiating_loader_realm_identity": "application-loader",
        }
        reconciled = runtime(members=(resolution,))
        selected = {
            ("application-loader", "demo/Caller"): provider(
                "demo/Caller", artifact="artifact", variant="variant",
            ),
        }
        rows = list(BinaryDecisionEngine._iter_semantic_member_edges(
            self.base_store, reconciled, {"artifact": "dependency:caller"}, selected,
        ))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0][0], "dependency:caller")
        self.assertEqual(rows[0][2], ("resolved", "demo/Api", "application-loader"))

        self.add_class_edge(
            self.base_store,
            artifact="empty-artifact",
            variant="empty-variant",
            class_name="",
            member="empty-member",
            edge="empty-edge",
            instruction_index=0,
            bytecode_offset=0,
            opcode=None,
            symbolic_owner="",
            symbolic_name="",
            symbolic_descriptor="",
            path_kind="",
        )
        self.base_store.connection.execute(
            "UPDATE members SET member_name='',descriptor='' WHERE member_identity='empty-member'"
        )
        empty_resolution = {
            "direct_edge_identity": "empty-edge",
            "member_resolution_status": "",
            "resolved_owner": "",
            "resolved_defining_loader_realm_identity": "",
            "initiating_loader_realm_identity": "",
        }
        empty_selected = {
            ("", ""): provider(
                "", realm="", artifact="empty-artifact",
                variant="empty-variant",
            ),
        }
        empty_rows = list(BinaryDecisionEngine._iter_semantic_member_edges(
            self.base_store,
            runtime(members=({}, empty_resolution)),
            {},
            empty_selected,
        ))
        self.assertEqual(len(empty_rows), 1)

        for providers in (
            {},
            {("application-loader", "demo/Caller"): provider(
                "demo/Caller", status="unresolved", variant="variant",
            )},
            {("application-loader", "demo/Caller"): provider(
                "demo/Caller", variant="different",
            )},
        ):
            with self.subTest(providers=providers):
                self.assertEqual(list(BinaryDecisionEngine._iter_semantic_member_edges(
                    self.base_store, reconciled, {}, providers,
                )), [])

        duplicate_resolution = runtime(members=(resolution, dict(resolution)))
        with self.assertRaises(BinaryFirstContractError) as raised:
            list(BinaryDecisionEngine._iter_semantic_member_edges(
                self.base_store, duplicate_resolution, {}, selected,
            ))
        self.assertEqual(
            raised.exception.reason_code, "MEMBER_RESOLUTION_EDGE_DUPLICATE",
        )

        bulk = tuple(
            {
                "direct_edge_identity": f"bulk-{index}",
                "member_resolution_status": "resolved",
                "resolved_owner": "demo/Api",
                "resolved_defining_loader_realm_identity": "realm",
                "initiating_loader_realm_identity": "realm",
            }
            for index in range(2_000)
        )
        self.assertEqual(list(BinaryDecisionEngine._iter_semantic_member_edges(
            self.current_store, runtime(members=bulk), {}, {},
        )), [])

        self.add_class_edge(
            self.base_store, edge="duplicate-edge", instruction_index=1,
            bytecode_offset=2,
        )
        duplicate_semantic = runtime(members=(
            resolution,
            dict(resolution, direct_edge_identity="duplicate-edge"),
        ))
        with self.assertRaises(BinaryFirstContractError) as raised:
            list(BinaryDecisionEngine._iter_semantic_member_edges(
                self.base_store, duplicate_semantic, {}, selected,
            ))
        self.assertEqual(
            raised.exception.reason_code, "SEMANTIC_MEMBER_EDGE_KEY_DUPLICATE",
        )

        class FailingConnection:
            def __init__(self, delegate):
                self.delegate = delegate

            def execute(self, query, parameters=()):
                if "SELECT edge.direct_edge_identity" in query:
                    raise sqlite3.OperationalError("injected query failure")
                return self.delegate.execute(query, parameters)

            def executemany(self, query, parameters):
                return self.delegate.executemany(query, parameters)

        failing_store = SimpleNamespace(
            connection=FailingConnection(self.current_store.connection),
        )
        with self.assertRaises(sqlite3.OperationalError):
            list(BinaryDecisionEngine._iter_semantic_member_edges(
                failing_store, runtime(members=(resolution,)), {}, {},
            ))

    def test_compatibility_semantic_edges_filters_fallback_and_duplicates(self):
        self.add_class_edge(self.base_store, edge="edge")
        resolution = {
            "direct_edge_identity": "edge",
            "member_resolution_identity": "resolution",
            "member_resolution_status": "resolved",
            "initiating_loader_realm_identity": "application-loader",
        }
        selected_provider = provider(
            "demo/Caller", artifact="artifact", variant="variant",
        )
        reconciled = runtime(
            providers=(selected_provider,), members=(resolution,),
        )
        rows = BinaryDecisionEngine._semantic_member_edges(
            self.base_store, reconciled, {},
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows.popitem()[0][0], "runtime-slot:classpath:0")

        empty_resolution = {
            "direct_edge_identity": "edge",
            "member_resolution_identity": "empty-resolution",
            "member_resolution_status": "",
            "initiating_loader_realm_identity": "",
        }
        empty_provider = provider(
            "demo/Caller", realm="", artifact="artifact", variant="variant",
        )
        empty_rows = BinaryDecisionEngine._semantic_member_edges(
            self.base_store,
            runtime(providers=(empty_provider,), members=(empty_resolution,)),
            {"artifact": "explicit-lineage"},
        )
        self.assertEqual(len(empty_rows), 1)

        self.add_class_edge(
            self.base_store,
            artifact="empty-artifact",
            variant="empty-variant",
            class_name="",
            member="empty-member",
            edge="empty-edge",
            instruction_index=0,
            bytecode_offset=0,
            opcode=None,
            symbolic_owner="",
            symbolic_name="",
            symbolic_descriptor="",
            path_kind="",
        )
        self.base_store.connection.execute(
            "UPDATE members SET member_name='',descriptor='' WHERE member_identity='empty-member'"
        )
        fully_empty_resolution = {
            "direct_edge_identity": "empty-edge",
            "member_resolution_identity": "fully-empty-resolution",
            "member_resolution_status": "",
            "initiating_loader_realm_identity": "",
        }
        fully_empty_provider = provider(
            "", realm="", artifact="empty-artifact", variant="empty-variant",
        )
        fully_empty_rows = BinaryDecisionEngine._semantic_member_edges(
            self.base_store,
            runtime(
                providers=(fully_empty_provider,),
                members=(fully_empty_resolution,),
            ),
            {"empty-artifact": "explicit-empty-lineage"},
        )
        self.assertEqual(len(fully_empty_rows), 1)

        for member_records, providers in (
            ((), (selected_provider,)),
            ((resolution,), ()),
            ((resolution,), (dict(selected_provider, class_provider_status="unresolved"),)),
            ((resolution,), (dict(selected_provider, selected_class_variant_identity="other"),)),
        ):
            with self.subTest(member_records=member_records, providers=providers):
                empty = BinaryDecisionEngine._semantic_member_edges(
                    self.base_store,
                    runtime(providers=providers, members=member_records),
                    {},
                )
                self.assertEqual(empty, {})

        self.add_class_edge(
            self.base_store, edge="duplicate-edge", instruction_index=1,
            bytecode_offset=2,
        )
        with self.assertRaises(BinaryFirstContractError) as raised:
            BinaryDecisionEngine._semantic_member_edges(
                self.base_store,
                runtime(
                    providers=(selected_provider,),
                    members=(
                        resolution,
                        dict(
                            resolution,
                            direct_edge_identity="duplicate-edge",
                            member_resolution_identity="resolution-2",
                        ),
                    ),
                ),
                {},
            )
        self.assertEqual(
            raised.exception.reason_code, "SEMANTIC_MEMBER_EDGE_KEY_DUPLICATE",
        )

    def test_build_equal_and_changed_runtime_paths(self):
        equal = self.engine()
        equal_bundle = equal.build()
        self.assertEqual(equal_bundle.coverage_status, "complete")
        self.assertEqual(equal_bundle.coverage_gaps, ())

        changed = self.engine(
            base_runtime=runtime("base"), current_runtime=runtime("current"),
        )
        calls = []
        changed._process_artifact_diffs = lambda: calls.append("artifact")
        changed._process_member_resolution_deltas = lambda: calls.append("member")
        changed._process_runtime_outcome_deltas = (
            lambda *_args: calls.append("runtime")
        )
        changed_bundle = changed.build()
        self.assertEqual(calls, ["artifact", "member", "runtime"])
        self.assertEqual(changed_bundle.coverage_status, "complete")

        diagnostic = self.engine()
        diagnostic._decision(
            observed_identity="candidate-without-gaps",
            channel="diagnostic",
            reason_code="CANDIDATE",
            fact_kind="unknown",
            fact_scope={},
        )
        diagnostic_bundle = diagnostic.build()
        self.assertEqual(diagnostic_bundle.coverage_status, "partial")
        self.assertEqual(diagnostic_bundle.coverage_gaps, ())

    def test_member_edge_merge_skips_only_with_complete_semantic_model_proof(self):
        self.add_class_edge(
            self.base_store,
            artifact="base-artifact",
            variant="base-variant",
            class_name="demo/Caller",
            member="base-member",
            edge="base-edge",
        )
        self.add_class_edge(
            self.current_store,
            artifact="current-artifact",
            variant="current-variant",
            class_name="demo/Caller",
            member="current-member",
            edge="current-edge",
        )
        base_runtime = runtime(
            "base-runtime",
            providers=(provider(
                class_name="demo/Caller",
                artifact="base-artifact",
                variant="base-variant",
                identity="base-provider",
            ),),
            definitions=(definition(class_name="demo/Caller"),),
        )
        current_runtime = runtime(
            "current-runtime",
            providers=(provider(
                class_name="demo/Caller",
                artifact="current-artifact",
                variant="current-variant",
                identity="current-provider",
            ),),
            definitions=(definition(class_name="demo/Caller"),),
        )
        preserving_entry = {
            "entry_scope": {
                "entry_kind": "class",
                "entry_name": "demo/Caller.class",
            },
            "runtime_effective_analysis": True,
            "class_change_category": "implementation_changed",
        }
        complete_diff = {
            "base_artifact_instance_identity": "base-artifact",
            "current_artifact_instance_identity": "current-artifact",
            "logical_dependency_lineage": "dependency:caller",
            "class_comparison_coverage_status": "complete",
            "entry_deltas": [preserving_entry],
        }
        decision_engine = self.engine(
            base_runtime=base_runtime,
            current_runtime=current_runtime,
            diffs=(complete_diff,),
        )
        keys, model_equal = decision_engine._runtime_class_delta_plan()
        self.assertEqual(keys, ())
        self.assertTrue(model_equal)
        decision_engine._process_artifact_diffs = lambda: None
        decision_engine._process_member_resolution_deltas = lambda: self.fail(
            "full member-edge merge must be omitted after an exact model proof"
        )
        decision_engine.build()
        self.assertEqual(
            decision_engine._paired_semantic_member_outcome_deltas_cache, ()
        )

        for label, changed_diff, changed_runtime in (
            (
                "contract change",
                {
                    **complete_diff,
                    "entry_deltas": [{
                        **preserving_entry,
                        "class_change_category": "contract_changed",
                    }],
                },
                current_runtime,
            ),
            (
                "incomplete comparison",
                {
                    **complete_diff,
                    "class_comparison_coverage_status": "partial",
                },
                current_runtime,
            ),
            (
                "class load outcome change",
                complete_diff,
                runtime(
                    "current-runtime-load-failed",
                    providers=current_runtime.provider_bindings,
                    definitions=(definition(
                        class_name="demo/Caller",
                        load_status="failed",
                    ),),
                ),
            ),
        ):
            with self.subTest(label=label):
                fallback = self.engine(
                    base_runtime=base_runtime,
                    current_runtime=changed_runtime,
                    diffs=(changed_diff,),
                )
                _keys, equal = fallback._runtime_class_delta_plan()
                self.assertFalse(equal)

    def test_contract_equality_proof_rejects_every_incomplete_lineage_shape(self):
        complete_entry = {
            "entry_scope": {
                "entry_kind": "class",
                "entry_name": "demo/Api.class",
            },
            "runtime_effective_analysis": True,
            "class_change_category": "implementation_changed",
        }
        complete = {
            "base_artifact_instance_identity": "base-artifact",
            "current_artifact_instance_identity": "current-artifact",
            "logical_dependency_lineage": "dependency:api",
            "class_comparison_coverage_status": "complete",
            "entry_deltas": (complete_entry,),
        }
        self.add_artifact(self.base_store, "base-artifact")
        self.add_artifact(self.current_store, "current-artifact")

        def proven(diff):
            decision_engine = self.engine(diffs=(complete,))
            decision_engine.artifact_diffs = tuple(diff)
            return decision_engine._artifact_class_contracts_proven_equal()

        self.assertTrue(proven((complete,)))
        rejected = (
            {**complete, "base_artifact_instance_identity": ""},
            {**complete, "current_artifact_instance_identity": ""},
            {**complete, "logical_dependency_lineage": " "},
            {**complete, "base_artifact_instance_identity": "ABSENT:base"},
            {**complete, "current_artifact_instance_identity": "ABSENT:current"},
            {**complete, "class_comparison_coverage_status": None,
             "comparison_coverage_status": "partial"},
            {**complete, "entry_deltas": ({
                **complete_entry, "class_change_category": "unknown",
            },)},
        )
        for index, diff in enumerate(rejected):
            with self.subTest(index=index):
                self.assertFalse(proven((diff,)))

        tolerated = (
            {**complete, "entry_deltas": ({"entry_scope": None},)},
            {**complete, "entry_deltas": ({
                **complete_entry, "entry_scope": {"entry_kind": "resource"},
            },)},
            {**complete, "entry_deltas": ({
                **complete_entry, "runtime_effective_analysis": False,
                "class_change_category": "contract_changed",
            },)},
        )
        for index, diff in enumerate(tolerated):
            with self.subTest(tolerated=index):
                self.assertTrue(proven((diff,)))

        duplicate_variants = (
            {
                **complete,
                "current_artifact_instance_identity": "current-other",
                "logical_dependency_lineage": "dependency:other",
            },
            {
                **complete,
                "base_artifact_instance_identity": "base-other",
                "logical_dependency_lineage": "dependency:other",
            },
            {
                **complete,
                "base_artifact_instance_identity": "base-other",
                "current_artifact_instance_identity": "current-other",
            },
        )
        for duplicate in duplicate_variants:
            with self.subTest(duplicate=duplicate):
                self.assertFalse(proven((complete, duplicate)))

        self.add_artifact(self.base_store, "base-extra")
        mismatched_store = self.engine(diffs=(complete,))
        self.assertFalse(
            mismatched_store._artifact_class_contracts_proven_equal()
        )

    def test_runtime_delta_and_changed_class_frontier_empty_value_boundaries(self):
        decision_engine = self.engine(diffs=({
            "base_artifact_instance_identity": "base-artifact",
            "current_artifact_instance_identity": "current-artifact",
            "logical_dependency_lineage": "dependency:api",
            "entry_deltas": (
                {"entry_scope": None},
                {
                    "entry_scope": {"entry_kind": "class", "entry_name": None},
                    "runtime_effective_analysis": True,
                },
            ),
        },))
        self.assertIn("", decision_engine._provider_realms_by_changed_class)

        key = ("application-loader", "demo/Api")
        decision_engine._base_providers = {key: provider()}
        decision_engine._current_providers = {key: provider()}
        decision_engine._base_definitions = {}
        decision_engine._current_definitions = {}
        decision_engine._artifact_class_contracts_proven_equal = lambda: True
        keys, equal = decision_engine._runtime_class_delta_plan()
        self.assertEqual(keys, ())
        self.assertTrue(equal)

        decision_engine._base_definitions = {key: {
            "class_definition_status": "definition_ready",
        }}
        decision_engine._current_definitions = {key: {
            "class_definition_status": "failed",
        }}
        keys, equal = decision_engine._runtime_class_delta_plan()
        self.assertEqual(keys, (key,))
        self.assertFalse(equal)

    def test_build_fails_closed_for_unknown_blank_and_unowned_obligations(self):
        def prepared():
            decision_engine = self.engine()
            decision_engine._process_artifact_diffs = lambda: None
            record = decision_engine._decision(
                observed_identity="observed",
                channel="authoritative",
                reason_code="CHANGE",
                fact_kind="class",
                fact_scope={},
            )
            return decision_engine, record

        unknown, _record = prepared()
        unknown._obligation_origins.clear()
        with self.assertRaises(BinaryFirstContractError) as raised:
            unknown.build()
        self.assertEqual(
            raised.exception.reason_code,
            "DISPOSITION_OBLIGATION_CONSERVATION_FAILED",
        )

        for blank in (None, ""):
            decision_engine, record = prepared()
            record["decision_identity"] = blank
            with self.subTest(blank=blank), self.assertRaises(
                BinaryFirstContractError
            ) as raised:
                decision_engine.build()
            self.assertEqual(raised.exception.reason_code, "DECISION_IDENTITY_INVALID")

        unowned, _record = prepared()
        unowned._obligation_origins["unowned"] = {"channel": "authoritative"}
        with self.assertRaises(BinaryFirstContractError) as raised:
            unowned.build()
        self.assertEqual(
            raised.exception.reason_code,
            "DISPOSITION_OBLIGATION_CONSERVATION_FAILED",
        )

    def test_build_conservation_does_not_reconstruct_decision_payloads(self):
        decision_engine = self.engine()
        record = decision_engine._decision(
            observed_identity="already-constructed",
            channel="excluded",
            reason_code="NO_RUNTIME_EFFECT",
            fact_kind="unknown",
            fact_scope={},
        )

        with patch.object(
            engine_module,
            "Decision",
            side_effect=AssertionError(
                "build conservation must use existing decision identities"
            ),
        ):
            bundle = decision_engine.build()

        self.assertEqual(
            bundle.excluded_decisions[0]["decision_identity"],
            record["decision_identity"],
        )


if __name__ == "__main__":
    unittest.main()
