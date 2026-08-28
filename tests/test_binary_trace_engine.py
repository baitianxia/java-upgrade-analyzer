import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_runtime_reconciler  # noqa: E402
import binary_trace_engine  # noqa: E402
from binary_decision_engine import BinaryDecisionEngine  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import (  # noqa: E402
    AnalysisContext, AnalysisScope, ArtifactInstance, RuntimeComparison, RuntimeProfile,
)
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import RuntimeReconciler  # noqa: E402
from binary_trace_engine import BinaryTraceEngine, build_binary_traces  # noqa: E402


def current_jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryTraceFastPathTest(unittest.TestCase):
    def discovery(self):
        return SimpleNamespace(
            exact_member_identities=("entry-member",),
            possible_member_identities=(),
            identity="entrypoint-discovery-1",
            coverage_gaps=(),
            records=({"member_identity": "entry-member"},),
        )

    def empty_discovery(self, *, coverage_gaps=()):
        return SimpleNamespace(
            exact_member_identities=(),
            possible_member_identities=(),
            identity="entrypoint-discovery-empty",
            coverage_gaps=tuple(coverage_gaps),
            records=(),
        )

    def decisions(self, **overrides):
        values = {
            "formal_projections": (),
            "candidate_projection_plans": (),
            "authoritative_decisions": (),
            "analysis_context_identity": "analysis-context-1",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_no_target_fast_path_preserves_empty_results_and_entrypoints(self):
        discovery = self.discovery()
        runtime = SimpleNamespace(coverage_gaps=())
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=discovery,
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            result = build_binary_traces(
                object(), object(), runtime, self.decisions()
            )

        engine.assert_not_called()
        self.assertEqual(result.formal_results, ())
        self.assertEqual(result.candidate_results, ())
        self.assertEqual(result.resource_activation_results, ())
        self.assertEqual(result.entrypoint_records, discovery.records)
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(
            result.graph_stats["graph_materialization_status"], "not_required"
        )

    def test_contract_access_reduction_is_linkage_incompatible_without_a_path(self):
        decision = {
            "fact_scope": {"member_change_kind": "contract_changed"},
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0002},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["evidence"]["current_contract"]["access"] = 0x0001
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_observed_legal_protected_path_refines_access_reduction(self):
        decision = {
            "fact_scope": {
                "member_kind": "method",
                "member_change_kind": "contract_changed",
            },
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0004},
            },
        }

        self.assertTrue(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"definition_ready"},
            )
        )
        for has_path, resolutions, linkages in (
            (False, {"resolved"}, {"resolved"}),
            (True, {"illegal_access"}, {"illegal_access"}),
            (True, {"resolved"}, {"illegal_access"}),
        ):
            with self.subTest(
                has_path=has_path,
                resolutions=resolutions,
                linkages=linkages,
            ):
                self.assertFalse(
                    binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                        decision,
                        has_path=has_path,
                        resolution_statuses=resolutions,
                        linkage_statuses=linkages,
                        caller_definition_statuses={"definition_ready"},
                    )
                )

        decision["evidence"]["current_contract"]["access"] |= 0x0010
        self.assertFalse(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"definition_ready"},
            )
        )

        decision["evidence"]["current_contract"]["access"] = 0x0004
        self.assertFalse(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"verification_failed"},
            )
        )

    def test_concrete_method_becoming_abstract_breaks_binary_compatibility(self):
        decision = {
            "fact_scope": {"member_change_kind": "contract_changed"},
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0001 | 0x0400},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["evidence"]["base_contract"]["access"] |= 0x0400
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_non_final_method_becoming_final_breaks_binary_compatibility(self):
        decision = {
            "fact_scope": {
                "member_kind": "method",
                "member_change_kind": "contract_changed",
            },
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0001 | 0x0010},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["fact_scope"]["member_kind"] = "field"
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_definitive_missing_linkage_edges_are_exact(self):
        self.assertEqual(
            binary_trace_engine._unresolved_edge_certainty("no_such_member"),
            "exact",
        )
        for status in ("no_class_definition", "class_definition_failed"):
            with self.subTest(status=status):
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(
                        status, paired_artifact_change=True,
                    ),
                    "exact",
                )
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(status),
                    "possible",
                )
        for status in ("ambiguous", "unresolved", "unsupported"):
            with self.subTest(status=status):
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(status),
                    "possible",
                )

    def test_every_trace_consumer_routes_to_full_graph_builder(self):
        cases = {
            "formal": self.decisions(formal_projections=({"identity": "p"},)),
            "targetable_candidate": self.decisions(
                candidate_projection_plans=({"planning_status": "targetable"},)
            ),
            "service_activation": self.decisions(authoritative_decisions=({
                "fact_kind": "resource",
                "fact_scope": {"resource_name": "META-INF/services/demo.Api"},
            },)),
        }
        for name, decisions in cases.items():
            with self.subTest(name=name), patch.object(
                binary_trace_engine,
                "discover_binary_entrypoints",
                return_value=self.discovery(),
            ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
                expected = object()
                engine.return_value.build.return_value = expected
                actual = build_binary_traces(
                    object(), object(), SimpleNamespace(coverage_gaps=()), decisions
                )

            self.assertIs(actual, expected)
            engine.assert_called_once()

    def test_full_graph_hydrates_only_runtime_selection_families(self):
        runtime = SimpleNamespace(coverage_gaps=())
        selected = SimpleNamespace(coverage_gaps=())
        decisions = self.decisions(formal_projections=({"identity": "p"},))
        store = object()
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=self.discovery(),
        ), patch.object(
            binary_trace_engine,
            "hydrate_runtime_reconciliation",
            return_value=selected,
        ) as hydrate, patch.object(
            binary_trace_engine, "BinaryTraceEngine"
        ) as engine:
            engine.return_value.build.return_value = "built"
            result = build_binary_traces(store, object(), runtime, decisions)

        self.assertEqual(result, "built")
        hydrate.assert_called_once_with(
            store,
            runtime,
            ("provider_binding", "class_definition"),
        )
        self.assertIs(engine.call_args.args[2], selected)

    def test_constant_dynamic_handles_participate_in_reverse_linkage(self):
        engine = object.__new__(BinaryTraceEngine)
        engine.member_resolutions = {
            "edge-1": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target-member",
                "member_resolution_identity": "resolution-1",
            }
        }
        engine.edges = {
            "edge-1": {
                "edge_kind": "ldc_bootstrap_handle_0",
                "caller_member_identity": "caller-member",
                "symbolic_owner": "demo/Target",
                "symbolic_name": "bootstrapTarget",
                "symbolic_descriptor": "()V",
            }
        }
        engine.dispatch = {}
        engine.linkage_resolutions = {}
        engine.reverse = defaultdict(list)
        engine.unresolved_edge_alias_targets = {}
        engine.paired_artifact_missing_targets = set()
        engine.type_resolutions = {}
        engine.class_initializations = {}
        engine.inline_overlay = SimpleNamespace(rows=())
        engine.semantic_edges = {}

        engine._build_reverse_graph()

        self.assertEqual(
            engine.reverse["target-member"][0]["caller_member_identity"],
            "caller-member",
        )
        self.assertEqual(
            engine.reverse["target-member"][0]["certainty"], "possible"
        )

    def test_deferred_loading_constraint_never_becomes_an_exact_path(self):
        engine = object.__new__(BinaryTraceEngine)
        engine.member_resolutions = {
            "edge-1": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target-member",
                "member_resolution_identity": "resolution-1",
            }
        }
        engine.linkage_resolutions = {
            "edge-1": {
                "linkage_status": "loading_constraint_deferred_conflict",
            }
        }
        engine.edges = {
            "edge-1": {
                "edge_kind": "method",
                "caller_member_identity": "caller-member",
                "symbolic_owner": "demo/Target",
                "symbolic_name": "accept",
                "symbolic_descriptor": "(Lapi/Param;)V",
            }
        }
        engine.dispatch = {
            "edge-1": {
                "dispatch_status": "unresolved",
                "implementation_target_identities": [],
            }
        }
        engine.reverse = defaultdict(list)
        engine.unresolved_edge_alias_targets = {}
        engine.paired_artifact_missing_targets = set()
        engine.type_resolutions = {}
        engine.class_initializations = {}
        engine.inline_overlay = SimpleNamespace(rows=())
        engine.semantic_edges = {}

        engine._build_reverse_graph()

        self.assertEqual(
            engine.reverse["target-member"][0]["certainty"], "possible"
        )

    def test_loading_constraint_evidence_controls_static_linkage_conclusion(self):
        engine = object.__new__(BinaryTraceEngine)
        engine._target_nodes = lambda _decision: ("target-member",)
        engine._trace = lambda _targets: ([{
            "path_certainty": "possible",
            "entrypoint_member_identity": "entry-member",
            "edges": [{
                "direct_edge_identity": "edge-1",
                "caller_member_identity": "caller-member",
            }],
        }], [])
        engine.entrypoint_gaps = ()
        engine.runtime = SimpleNamespace(coverage_gaps=())
        engine.member_resolutions = {
            "edge-1": {
                "member_resolution_status": "resolved",
                "initiating_loader_realm_identity": "caller-loader",
            }
        }
        engine.members = {
            "caller-member": {"class_name": "caller/Caller"},
        }
        engine.class_definition_statuses = {
            ("caller-loader", "caller/Caller"): "definition_ready",
        }
        engine.decisions = SimpleNamespace(
            analysis_context_identity="analysis-context-1"
        )
        engine.profile = SimpleNamespace(identity="runtime-profile-1")
        engine.batch_graph_identity = "batch-graph-1"
        decision = {
            "decision_identity": "decision-1",
            "fact_kind": "method",
            "fact_scope": {"member_change_kind": "implementation_changed"},
            "coverage_gaps": [],
        }

        expected = {
            "loading_constraint_deferred_conflict": "undetermined",
            "loader_constraint_violation": "incompatible_if_executed",
        }
        for status, conclusion in expected.items():
            with self.subTest(status=status):
                engine.linkage_resolutions = {
                    "edge-1": {"linkage_status": status},
                }
                result = engine._result_for(
                    projection_identity="projection-1",
                    decision=decision,
                    assessment_identity="assessment-1",
                    diagnostic=False,
                )
                self.assertEqual(result["static_linkage_status"], conclusion)
                self.assertFalse(result["exact_path_exists"])
                self.assertTrue(result["possible_path_exists"])

    def test_formal_results_with_no_entrypoints_route_to_graph_free_builder(self):
        decisions = self.decisions(formal_projections=({"identity": "p"},))
        store = object()
        runtime = SimpleNamespace(coverage_gaps=())
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=self.empty_discovery(),
        ), patch.object(
            binary_trace_engine,
            "hydrate_runtime_reconciliation",
            return_value=runtime,
        ) as hydrate, patch.object(
            binary_trace_engine,
            "BinaryTraceEngine",
        ) as engine:
            expected = object()
            engine.return_value.build.return_value = expected
            actual = build_binary_traces(
                store, object(), runtime, decisions
            )

        self.assertIs(actual, expected)
        engine.assert_called_once()
        self.assertFalse(engine.call_args.kwargs["materialize_graph"])
        hydrate.assert_called_once_with(
            store, runtime, ("provider_binding",)
        )

    def test_service_activation_with_no_entrypoints_still_uses_full_graph(self):
        decisions = self.decisions(authoritative_decisions=({
            "fact_kind": "resource",
            "fact_scope": {"resource_name": "META-INF/services/demo.Api"},
        },))
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=self.empty_discovery(),
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            expected = object()
            engine.return_value.build.return_value = expected
            actual = build_binary_traces(
                object(), object(), SimpleNamespace(coverage_gaps=()), decisions
            )

        self.assertIs(actual, expected)
        engine.assert_called_once()
        self.assertNotIn("materialize_graph", engine.call_args.kwargs)


class BinaryTraceBoundaryTest(unittest.TestCase):
    def test_compact_row_mapping_and_sqlite_lookup_protocols(self):
        executable = binary_trace_engine._ExecutableResolutionRow("edge")
        self.assertEqual(len(executable), len(executable.FIELDS))
        self.assertEqual(tuple(executable), executable.FIELDS)
        self.assertEqual(executable["direct_edge_identity"], "edge")
        with self.assertRaises(KeyError):
            executable["unknown"]

        empty = binary_trace_engine._IncomingTraceEdge(
            caller_member_identity="caller",
            direct_edge_identity="edge",
            certainty="exact",
        )
        full = binary_trace_engine._IncomingTraceEdge(
            caller_member_identity="caller",
            direct_edge_identity="edge",
            certainty="exact",
            class_initialization_resolution_identity="init",
            inline_overlay_identity="inline",
            semantic_edge_identity="semantic",
        )
        self.assertEqual(len(empty), len(empty.REQUIRED_FIELDS))
        self.assertEqual(
            len(full), len(full.REQUIRED_FIELDS) + len(full.OPTIONAL_FIELDS)
        )
        self.assertEqual(tuple(empty), empty.REQUIRED_FIELDS)
        self.assertEqual(
            tuple(full), full.REQUIRED_FIELDS + full.OPTIONAL_FIELDS
        )
        self.assertEqual(full["inline_overlay_identity"], "inline")
        with self.assertRaises(KeyError):
            empty["inline_overlay_identity"]
        with self.assertRaises(KeyError):
            empty["unknown"]

        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute(
            "CREATE TABLE items(identity TEXT PRIMARY KEY,value TEXT,"
            "caller_member_identity TEXT)"
        )
        connection.executemany(
            "INSERT INTO items VALUES(?,?,?)",
            (("one", "1", "1"), ("two", "2", "2")),
        )
        lookup = binary_trace_engine._SQLiteTraceRowLookup(
            connection, "items", "identity", ("identity", "value")
        )
        self.assertEqual(len(lookup), 2)
        self.assertEqual(set(lookup), {"one", "two"})
        self.assertEqual(lookup["one"]["value"], "1")
        self.assertIs(lookup["one"], lookup["one"])
        with self.assertRaises(KeyError):
            lookup["missing"]
        with patch.object(
            binary_trace_engine._SQLiteTraceRowLookup, "CACHE_LIMIT", 0
        ):
            self.assertEqual(lookup["two"]["value"], "2")
        self.assertEqual(
            list(lookup.iter_graph_items()),
            [("one", {"identity": "one", "value": "1"}),
             ("two", {"identity": "two", "value": "2"})],
        )
        self.assertEqual(
            list(lookup.iter_matching_items(("two", "missing"))),
            [("two", {"identity": "two", "caller_member_identity": "2"})],
        )
        self.assertEqual(list(lookup.iter_service_activation_rows(())), [])

        connection.execute(
            "CREATE TABLE direct_edges("
            "direct_edge_identity TEXT PRIMARY KEY,"
            "caller_member_identity TEXT,edge_kind TEXT,symbolic_owner TEXT,"
            "symbolic_name TEXT,symbolic_descriptor TEXT)"
        )
        connection.executemany(
            "INSERT INTO direct_edges VALUES(?,?,?,?,?,?)",
            (
                (
                    "load", "caller", "method", "java/util/ServiceLoader",
                    "load", "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
                ),
                ("literal", "caller", "type", "demo/Api", "", "Ldemo/Api;"),
            ),
        )
        direct_lookup = binary_trace_engine._SQLiteTraceRowLookup(
            connection,
            "direct_edges",
            "direct_edge_identity",
            (
                "direct_edge_identity", "caller_member_identity", "edge_kind",
                "symbolic_owner", "symbolic_name", "symbolic_descriptor",
            ),
        )
        self.assertEqual(
            {row["direct_edge_identity"] for row in
             direct_lookup.iter_service_activation_rows(("demo/Api",))},
            {"load", "literal"},
        )

    def test_compact_resolution_indexes_and_batched_edge_join_boundaries(self):
        engine = self.graph_engine()
        engine.store = SimpleNamespace()
        engine._node_identity_pool = {}
        reconciliation = SimpleNamespace(
            member_resolutions=(
                {
                    "direct_edge_identity": "",
                    "member_resolution_status": None,
                    "resolved_member_identity": None,
                    "member_resolution_identity": None,
                    "initiating_loader_realm_identity": None,
                },
                {
                    "direct_edge_identity": "member-edge",
                    "member_resolution_status": "resolved",
                    "resolved_member_identity": "target",
                    "member_resolution_identity": "member-resolution",
                    "initiating_loader_realm_identity": "loader",
                },
                {
                    "direct_edge_identity": "member-edge",
                    "member_resolution_status": "ambiguous",
                    "resolved_member_identity": "",
                    "member_resolution_identity": "replacement",
                    "initiating_loader_realm_identity": "loader",
                },
            ),
            dispatch_resolutions=(
                {
                    "direct_edge_identity": "",
                    "dispatch_status": "possible",
                    "implementation_target_identities": (),
                    "dispatch_resolution_identity": "empty-edge",
                },
                {
                    "direct_edge_identity": "dispatch-only",
                    "dispatch_status": None,
                    "implementation_target_identities": (None, "implementation"),
                    "dispatch_resolution_identity": None,
                },
                {
                    "direct_edge_identity": "member-edge",
                    "dispatch_status": "exact",
                    "implementation_target_identities": (),
                    "dispatch_resolution_identity": "dispatch-resolution",
                },
            ),
            linkage_resolutions=(
                {"direct_edge_identity": "", "linkage_status": None},
                {"direct_edge_identity": "missing", "linkage_status": "resolved"},
                {
                    "direct_edge_identity": "member-edge",
                    "linkage_status": "resolved",
                },
            ),
        )
        engine._load_compact_resolution_indexes(reconciliation)

        self.assertIs(engine.member_resolutions, engine.dispatch)
        self.assertIs(engine.member_resolutions, engine.linkage_resolutions)
        self.assertEqual(
            engine.member_resolutions["member-edge"].member_resolution_status,
            "ambiguous",
        )
        self.assertEqual(
            engine.member_resolutions["member-edge"].linkage_status,
            "resolved",
        )
        self.assertEqual(
            engine.member_resolutions["dispatch-only"].implementation_target_identities,
            ("implementation",),
        )
        self.assertIs(engine._trace_reconciliation, reconciliation)

        class MatchingEdges:
            @staticmethod
            def iter_matching_items(identities):
                self.assertEqual(tuple(identities), ("present", "absent"))
                return iter((
                    ("present", {"caller_member_identity": "caller"}),
                    ("not-requested", {"caller_member_identity": "ignored"}),
                ))

        engine.edges = MatchingEdges()
        matched = list(engine._matching_resolution_edges({
            "present": {"direct_edge_identity": "present"},
            "absent": {"direct_edge_identity": "absent"},
        }))
        self.assertEqual(len(matched), 1)

        engine.edges = {
            "implicit": {"caller_member_identity": "implicit-caller"},
            "explicit": {"caller_member_identity": "explicit-caller"},
        }
        matched = list(engine._matching_resolution_edges({
            "implicit": {"status": "resolved"},
            "explicit": {"direct_edge_identity": "explicit"},
            "missing": {"status": "missing"},
        }))
        self.assertEqual(
            matched[0][0]["direct_edge_identity"], "implicit"
        )
        self.assertEqual(
            matched[1][0]["direct_edge_identity"], "explicit"
        )

        records = ({"direct_edge_identity": ""},) + tuple(
            {"direct_edge_identity": f"edge-{index}"} for index in range(2_001)
        )
        with patch.object(
            engine,
            "_matching_resolution_edges",
            side_effect=lambda pending: iter(
                (resolution, {"direct_edge_identity": edge_id})
                for edge_id, resolution in pending.items()
            ),
        ) as matcher:
            self.assertEqual(
                len(list(engine._iter_resolution_edge_batches(records))), 2_001
            )
        self.assertEqual(matcher.call_count, 2)

        del engine._node_identity_pool
        self.assertEqual(engine._node_identity(None), "")
        engine.member_resolutions = {}
        engine.linkage_resolutions = {}
        self.assertEqual(engine._path_edge_outcome({}), (None, None, ""))
        engine._path_outcomes = {"edge": ("resolved", "linked", "loader")}
        self.assertEqual(
            engine._path_edge_outcome({"direct_edge_identity": "edge"}),
            ("resolved", "linked", "loader"),
        )
        engine._path_outcomes = {"empty": ("", "", "")}
        self.assertEqual(
            engine._path_edge_outcome({"direct_edge_identity": "empty"}),
            (None, None, ""),
        )

    @staticmethod
    def discovery(*, exact=(), possible=(), gaps=(), records=()):
        return SimpleNamespace(
            exact_member_identities=tuple(exact),
            possible_member_identities=tuple(possible),
            identity="discovery",
            coverage_gaps=tuple(gaps),
            records=tuple(records),
        )

    @staticmethod
    def runtime(**overrides):
        values = {
            "provider_bindings": (),
            "member_resolutions": (),
            "dispatch_resolutions": (),
            "type_resolutions": (),
            "class_initialization_resolutions": (),
            "linkage_resolutions": (),
            "class_definitions": (),
            "coverage_gaps": (),
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def decisions(**overrides):
        values = {
            "authoritative_decisions": (),
            "diagnostic_decisions": (),
            "excluded_decisions": (),
            "projection_assessments": (),
            "formal_projections": (),
            "candidate_projection_plans": (),
            "analysis_context_identity": "context",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def graph_engine():
        engine = object.__new__(BinaryTraceEngine)
        engine.member_resolutions = {}
        engine.edges = {}
        engine.dispatch = {}
        engine.linkage_resolutions = {}
        engine.reverse = defaultdict(list)
        engine.unresolved_edge_alias_targets = {}
        engine.paired_artifact_missing_targets = set()
        engine.type_resolutions = {}
        engine.class_initializations = {}
        engine.inline_overlay = SimpleNamespace(rows=())
        engine.semantic_edges = {}
        return engine

    def test_scalar_helpers_cover_empty_visibility_and_contract_transition_matrix(self):
        self.assertEqual(binary_trace_engine._loads(None), {})
        self.assertEqual(binary_trace_engine._loads(""), {})
        self.assertEqual(binary_trace_engine._loads('{"a":1}'), {"a": 1})
        for access, rank in (
            (None, 1),
            (0, 1),
            (binary_trace_engine.ACC_PUBLIC, 3),
            (binary_trace_engine.ACC_PROTECTED, 2),
            (binary_trace_engine.ACC_PRIVATE, 0),
        ):
            with self.subTest(access=access):
                self.assertEqual(binary_trace_engine._visibility_rank(access), rank)

        no_change = ({}, {"fact_scope": None}, {
            "fact_scope": {"member_change_kind": "implementation_changed"},
        })
        for decision in no_change:
            self.assertEqual(
                binary_trace_engine._contract_change_linkage_reasons(decision),
                frozenset(),
            )
        malformed = (
            None,
            {"base_contract": None, "current_contract": {}},
            {"base_contract": {}, "current_contract": None},
            {"base_contract": [], "current_contract": {}},
        )
        for evidence in malformed:
            decision = {
                "fact_scope": {"member_change_kind": "contract_changed"},
                "evidence": evidence,
            }
            self.assertEqual(
                binary_trace_engine._contract_change_linkage_reasons(decision),
                frozenset(),
            )

        already_final = {
            "fact_scope": {
                "member_kind": "method",
                "member_change_kind": "contract_changed",
            },
            "evidence": {
                "base_contract": {"access": binary_trace_engine.ACC_FINAL},
                "current_contract": {"access": binary_trace_engine.ACC_FINAL},
            },
        }
        self.assertEqual(
            binary_trace_engine._contract_change_linkage_reasons(already_final),
            frozenset(),
        )

        transitions = (
            ({"access": binary_trace_engine.ACC_PUBLIC}, {"access": 0},
             {"access_reduced"}),
            ({"access": 0}, {"access": binary_trace_engine.ACC_STATIC},
             {"static_instance_changed"}),
            ({"access": 0}, {"access": binary_trace_engine.ACC_ABSTRACT},
             {"became_abstract"}),
            ({"access": 0}, {"access": binary_trace_engine.ACC_FINAL}, set()),
        )
        for base, current, reasons in transitions:
            decision = {
                "fact_scope": {
                    "member_kind": "field",
                    "member_change_kind": "contract_changed",
                },
                "evidence": {"base_contract": base, "current_contract": current},
            }
            with self.subTest(base=base, current=current):
                self.assertEqual(
                    binary_trace_engine._contract_change_linkage_reasons(decision),
                    frozenset(reasons),
                )
        self.assertEqual(
            binary_trace_engine._unresolved_edge_certainty(
                "ambiguous", paired_artifact_change=True
            ),
            "possible",
        )

    def test_constructor_binds_empty_and_partial_decision_evidence_without_graph(self):
        removed = {
            "fact_kind": "method",
            "fact_scope": {
                "class_name": None,
                "member_name": None,
                "descriptor": None,
                "member_kind": None,
                "member_change_kind": "removed",
            },
            "dependency_artifacts": (
                {"side": "base"}, {"side": "current"}, {"side": None},
            ),
            "evidence": {
                "current_unresolved_direct_edge_identities": ("edge-alias",),
            },
            "decision_identity": "removed",
        }
        diagnostic = {
            "fact_kind": "field",
            "fact_scope": {
                "class_name": "demo.Type",
                "member_name": "value",
                "descriptor": "I",
                "member_kind": "field",
            },
            "evidence": None,
            "decision_identity": "diagnostic",
        }
        ignored = {
            "fact_kind": "class",
            "fact_scope": None,
            "decision_identity": "ignored",
        }
        decisions = self.decisions(
            authoritative_decisions=(removed, ignored),
            diagnostic_decisions=(diagnostic,),
            excluded_decisions=({"decision_identity": "excluded"},),
            projection_assessments=({
                "projection_assessment_identity": "assessment",
            },),
        )
        engine = BinaryTraceEngine(
            object(),
            SimpleNamespace(identity="profile"),
            self.runtime(),
            decisions,
            entrypoint_discovery=self.discovery(),
            materialize_graph=False,
        )
        self.assertTrue(engine.paired_artifact_missing_targets)
        self.assertTrue(engine.unresolved_edge_alias_targets)
        self.assertEqual(set(engine.decision_by_identity), {
            "removed", "ignored", "diagnostic", "excluded",
        })
        self.assertIn("assessment", engine.assessment_by_identity)

        explicit_removed = dict(
            removed,
            decision_identity="explicit-removed",
            fact_scope={
                "class_name": "demo.Type",
                "member_name": "run",
                "descriptor": "()V",
                "member_kind": "method",
                "member_change_kind": "removed",
            },
            dependency_artifacts=({"side": "base"}, {"side": "current"}),
            evidence=None,
        )
        no_artifacts_removed = dict(
            explicit_removed,
            decision_identity="no-artifacts-removed",
            dependency_artifacts=None,
        )
        explicit = BinaryTraceEngine(
            object(), SimpleNamespace(identity="profile"), self.runtime(),
            self.decisions(authoritative_decisions=(
                explicit_removed, no_artifacts_removed,
            )),
            entrypoint_discovery=self.discovery(), materialize_graph=False,
            semantic_overlay=SimpleNamespace(identity="semantic", rows=()),
        )
        self.assertTrue(explicit.paired_artifact_missing_targets)

        with self.assertRaises(ValueError):
            BinaryTraceEngine(
                object(),
                SimpleNamespace(identity="profile"),
                self.runtime(),
                self.decisions(),
                entrypoint_discovery=self.discovery(exact=("entry",)),
                materialize_graph=False,
            )

    def test_constructor_materializes_nonempty_semantic_and_resolution_rows(self):
        class Connection:
            def execute(self, statement):
                if "FROM members" in statement:
                    return ({
                        "member_identity": "member",
                        "class_name": "demo/Member",
                        "member_name": "run",
                        "descriptor": "()V",
                    },)
                if "FROM direct_edges" in statement:
                    return ()
                raise AssertionError(statement)

        store = SimpleNamespace(connection=Connection())
        semantic = SimpleNamespace(
            identity="semantic",
            rows=({
                "semantic_edge_identity": "semantic-edge",
                "caller_member_identity": "member",
                "target_member_identity": "target",
                "path_certainty": "exact",
            },),
        )
        runtime = self.runtime(
            type_resolutions=({
                "direct_edge_identity": "type-resolution-edge",
            },),
            class_definitions=({
                "initiating_loader_realm_identity": None,
                "class_name": None,
                "class_definition_status": None,
            },),
        )
        engine = BinaryTraceEngine(
            store, SimpleNamespace(identity="profile"), runtime,
            self.decisions(), entrypoint_discovery=self.discovery(),
            semantic_overlay=semantic,
        )
        self.assertIn("semantic-edge", engine.semantic_edges)
        self.assertIn("target", engine.reverse)
        self.assertEqual(engine.graph_stats["runtime_semantic_overlay_identity"], "semantic")

    def test_constructor_streams_store_edges_and_releases_full_resolution_payloads(self):
        class Connection:
            def __init__(self):
                self.statements = []

            def execute(self, statement, parameters=()):
                normalized = " ".join(statement.split())
                self.statements.append((normalized, tuple(parameters)))
                if "FROM direct_edges" in normalized and "WHERE" not in normalized:
                    return ({
                        "direct_edge_identity": "edge",
                        "caller_member_identity": "root",
                        "caller_artifact_instance_identity": "artifact",
                        "instruction_index": 0,
                        "bytecode_offset": 0,
                        "edge_kind": "method",
                        "opcode": 184,
                        "symbolic_owner": "demo/Target",
                        "symbolic_name": "run",
                        "symbolic_descriptor": "()V",
                        "edge_json": "{}",
                    },)
                if "FROM members" in normalized and "WHERE" in normalized:
                    return ({
                        "member_identity": "root",
                        "class_name": "demo/Root",
                        "member_name": "main",
                        "descriptor": "()V",
                    },)
                raise AssertionError((normalized, parameters))

        connection = Connection()
        store = SimpleNamespace(connection=connection)
        runtime = self.runtime(
            member_resolutions=({
                "direct_edge_identity": "edge",
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target",
                "member_resolution_identity": "resolution",
                "initiating_loader_realm_identity": "loader",
                "loading_constraints": [{"unused": "x" * 100_000}],
            },),
            dispatch_resolutions=({
                "direct_edge_identity": "edge",
                "dispatch_status": "exact",
                "implementation_target_identities": ("target",),
                "dispatch_resolution_identity": "dispatch",
            },),
            linkage_resolutions=({
                "direct_edge_identity": "edge",
                "linkage_status": "resolved",
                "loading_constraints": [{"unused": "x" * 100_000}],
            },),
        )
        engine = BinaryTraceEngine(
            store,
            SimpleNamespace(identity="profile"),
            runtime,
            self.decisions(),
            entrypoint_discovery=self.discovery(exact=("root",)),
        )

        self.assertNotIsInstance(engine.edges, dict)
        self.assertEqual(engine.member_resolutions, {})
        self.assertEqual(engine.dispatch, {})
        self.assertEqual(engine.linkage_resolutions, {})
        incoming = engine.reverse["target"][0]
        self.assertEqual(dict(incoming), {
            "caller_member_identity": "root",
            "direct_edge_identity": "edge",
            "certainty": "exact",
            "member_resolution_identity": "resolution",
            "dispatch_resolution_identity": "dispatch",
        })
        self.assertLess(sys.getsizeof(incoming), sys.getsizeof(dict(incoming)))
        self.assertEqual(
            sum("FROM direct_edges" in statement and "WHERE" not in statement
                for statement, _parameters in connection.statements),
            1,
        )
        self.assertFalse(any(
            "FROM members" in statement and "WHERE" not in statement
            for statement, _parameters in connection.statements
        ))

    def test_reverse_graph_admits_only_reconciled_executable_edges_and_overlays(self):
        engine = self.graph_engine()
        engine.member_resolutions = {
            "no-status": {"member_resolution_identity": "r-no-status"},
            "missing-edge": {"member_resolution_status": "resolved"},
            "unsupported": {
                "member_resolution_status": "resolved",
                "member_resolution_identity": "r-unsupported",
            },
            "resolved": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target-resolved",
                "member_resolution_identity": "r-resolved",
            },
            "resolved-no-identities": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "target-no-identities",
            },
            "possible": {
                "member_resolution_status": "resolved",
                "member_resolution_identity": "r-possible",
            },
            "resolved-empty": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "",
                "member_resolution_identity": "r-empty",
            },
            "missing-kind": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "unused",
                "member_resolution_identity": "r-missing-kind",
            },
            "unresolved-method": {
                "member_resolution_status": "ambiguous",
                "member_resolution_identity": "r-unresolved-method",
            },
            "dynamic-first": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "dynamic-first-target",
                "member_resolution_identity": "r-dynamic-first",
            },
            "dynamic-second": {
                "member_resolution_status": "resolved",
                "resolved_member_identity": "dynamic-second-target",
                "member_resolution_identity": "r-dynamic-second",
            },
            "unresolved": {
                "member_resolution_status": "no_class_definition",
                "member_resolution_identity": "r-unresolved",
            },
            "unresolved-no-identities": {
                "member_resolution_status": "ambiguous",
                "initiating_loader_realm_identity": "loader",
            },
        }
        base_edge = {
            "caller_member_identity": "caller",
            "symbolic_owner": "demo/Target",
            "symbolic_name": "run",
            "symbolic_descriptor": "()V",
        }
        engine.edges = {
            "no-status": dict(base_edge, edge_kind="method"),
            "unsupported": dict(base_edge, edge_kind="resource"),
            "resolved": dict(base_edge, edge_kind="method"),
            "resolved-no-identities": dict(base_edge, edge_kind="method"),
            "possible": dict(base_edge, edge_kind="invokedynamic_bootstrap"),
            "unresolved": dict(base_edge, edge_kind="field"),
            "unresolved-no-identities": dict(base_edge, edge_kind="method"),
            "resolved-empty": dict(base_edge, edge_kind="method"),
            "missing-kind": dict(base_edge, edge_kind=None),
            "unresolved-method": dict(base_edge, edge_kind="method"),
            "dynamic-first": dict(base_edge, edge_kind="invokedynamic_handle_0"),
            "dynamic-second": dict(base_edge, edge_kind="ldc_bootstrap_handle_0"),
            "type-none": dict(base_edge, edge_kind="type", direct_edge_identity="type-none"),
            "type-bad": dict(base_edge, edge_kind="type", direct_edge_identity="type-bad"),
            "type-good": dict(base_edge, edge_kind="type", direct_edge_identity="type-good"),
            "init-empty": dict(base_edge, edge_kind="method", direct_edge_identity="init-empty"),
            "init-no-identity": dict(
                base_edge, edge_kind="method", direct_edge_identity="init-no-identity"
            ),
            "other": dict(base_edge, edge_kind="method", direct_edge_identity="other"),
        }
        engine.dispatch = {
            "possible": {
                "dispatch_status": "possible",
                "implementation_target_identities": ("target-possible",),
                "dispatch_resolution_identity": "dispatch",
            },
        }
        engine.linkage_resolutions = {
            "resolved": {"linkage_status": "resolved"},
            "possible": {"linkage_status": "loader_constraint_violation"},
            "unresolved-no-identities": {"linkage_status": "unresolved"},
        }
        alias = BinaryTraceEngine._symbolic_target(
            "alias/Owner", "run", "()V", "method"
        )
        engine.unresolved_edge_alias_targets = {"unresolved": (alias,)}
        engine.paired_artifact_missing_targets = {alias}
        engine.type_resolutions = {
            "type-bad": {"type_resolution_status": "missing"},
            "type-good": {
                "direct_edge_identity": "type-good",
                "type_resolution_status": "resolved",
            },
        }
        engine.class_initializations = {
            "missing-edge": {
                "class_initialization_status": "resolved",
                "initializer_target_identities": ("init-missing",),
            },
            "other": {"class_initialization_status": "not_required"},
            "resolved": {
                "class_initialization_status": "resolved",
                "initializer_target_identities": ("initializer",),
                "class_initialization_resolution_identity": "init-resolution",
            },
            "init-empty": {
                "class_initialization_status": "resolved",
                "initializer_target_identities": (),
            },
            "init-no-identity": {
                "class_initialization_status": "resolved",
                "initializer_target_identities": ("initializer-no-identity",),
            },
        }
        engine.inline_overlay = SimpleNamespace(rows=(
            {"consumption_state": "unchanged"},
            {"consumption_state": "changed_with_source", "binding_certainty": "unknown"},
            {"consumption_state": "changed_with_source", "binding_certainty": "proven",
             "consumer_member_identity": "", "changed_field_member_identity": "target"},
            {"consumption_state": "changed_with_source", "binding_certainty": "possible",
             "consumer_member_identity": "inline-caller", "changed_field_member_identity": "",
             "inline_overlay_identity": "inline-missing"},
            {"consumption_state": "changed_with_source", "binding_certainty": "proven",
             "consumer_member_identity": "inline-caller", "changed_field_member_identity": "inline-target",
             "inline_overlay_identity": "inline-proven"},
            {"consumption_state": "changed_with_source", "binding_certainty": "possible",
             "consumer_member_identity": "inline-caller", "changed_field_member_identity": "inline-possible",
             "inline_overlay_identity": "inline-possible"},
        ))
        engine.semantic_edges = {
            "missing-caller": {"semantic_edge_identity": "missing-caller",
                               "caller_member_identity": "", "target_member_identity": "target"},
            "missing-target": {"semantic_edge_identity": "missing-target",
                               "caller_member_identity": "caller", "target_member_identity": ""},
            "semantic-exact": {"semantic_edge_identity": "semantic-exact",
                               "caller_member_identity": "semantic-caller",
                               "target_member_identity": "semantic-target",
                               "path_certainty": "exact"},
            "semantic-possible": {"semantic_edge_identity": "semantic-possible",
                                  "caller_member_identity": "semantic-caller",
                                  "target_member_identity": "semantic-possible-target",
                                  "path_certainty": "possible"},
        }
        engine.reverse["preseeded"].append({
            "caller_member_identity": "caller",
            "certainty": "exact",
            "direct_edge_identity": "preseeded-edge",
        })

        engine._build_reverse_graph()

        self.assertEqual(engine.reverse["target-resolved"][0]["certainty"], "exact")
        self.assertEqual(engine.reverse["target-possible"][0]["certainty"], "possible")
        self.assertEqual(engine.reverse[alias][0]["certainty"], "exact")
        self.assertIn("initializer", engine.reverse)
        self.assertIn("initializer-no-identity", engine.reverse)
        self.assertIn("inline-target", engine.reverse)
        self.assertIn("semantic-target", engine.reverse)
        self.assertNotIn("init-missing", engine.reverse)

    def test_reverse_graph_streams_and_filters_auxiliary_resolution_rows(self):
        engine = self.graph_engine()
        engine.store = SimpleNamespace()
        engine._node_identity_pool = {}
        engine._release_resolution_indexes_after_build = True
        engine._stream_auxiliary_resolutions = True
        engine._trace_reconciliation = SimpleNamespace(
            type_resolutions=(
                {"direct_edge_identity": "type-bad", "type_resolution_status": "missing"},
                {
                    "direct_edge_identity": "type-good",
                    "type_resolution_status": "primitive_or_array_type",
                    "symbolic_owner": "demo/Type",
                },
            ),
            class_initialization_resolutions=(
                {
                    "direct_edge_identity": "init-empty",
                    "class_initialization_status": "resolved",
                    "initializer_target_identities": (),
                },
                {
                    "direct_edge_identity": "init-good",
                    "class_initialization_status": "resolved",
                    "initializer_target_identities": ("initializer",),
                },
            ),
        )
        engine.edges = {
            "type-good": {
                "caller_member_identity": "caller",
                "symbolic_owner": "fallback/Type",
                "symbolic_descriptor": "Ldemo/Type;",
            },
            "init-good": {"caller_member_identity": "caller"},
        }

        engine._build_reverse_graph()

        self.assertIn("initializer", engine.reverse)
        self.assertEqual(engine.member_resolutions, {})
        self.assertEqual(engine.dispatch, {})
        self.assertIsNone(engine._trace_reconciliation)

    def test_reachability_scc_and_batch_graph_cover_cycles_duplicates_and_possible_paths(self):
        self.assertEqual(
            BinaryTraceEngine._reachable(("a",), {"a": {"b"}, "b": {"a", "c"}}),
            {"a", "b", "c"},
        )
        self.assertEqual(BinaryTraceEngine._scc_count(set(), {}), (0, 0))
        self.assertEqual(
            BinaryTraceEngine._scc_count(
                {"a", "b", "c", "d"},
                {"a": {"b", "c"}, "b": {"a", "d"}, "c": {"d"}},
            ),
            (3, 2),
        )

        engine = object.__new__(BinaryTraceEngine)
        engine.exact_entrypoints = {"root"}
        engine.possible_entrypoints = {"possible-root"}
        engine.entrypoints = engine.exact_entrypoints | engine.possible_entrypoints
        engine.reverse = defaultdict(list, {
            "middle": [
                {"caller_member_identity": "root", "certainty": "exact"},
                {"caller_member_identity": "possible-root", "certainty": "possible"},
            ],
            "target": [
                {"caller_member_identity": "middle", "certainty": "exact"},
                {"caller_member_identity": "root", "certainty": "exact"},
                {"caller_member_identity": "middle", "certainty": "possible"},
                {"caller_member_identity": "root", "certainty": "possible"},
            ],
        })
        engine.semantic_edges = {}
        engine.semantic_overlay = SimpleNamespace(identity="semantic")
        engine.entrypoint_discovery = self.discovery(
            exact=("root",), possible=("possible-root",)
        )
        engine._prepare_batch_graph()
        self.assertIn("target", engine.possible_path_nodes)
        self.assertIn("middle", engine.exact_reachable_nodes)
        self.assertGreaterEqual(engine.graph_stats["possible_scc_count"], 1)

    def test_target_selection_covers_resolution_provider_and_symbolic_fallbacks(self):
        class Store:
            result = []

            def rows(self, *_args, **_kwargs):
                return list(self.result)

        engine = object.__new__(BinaryTraceEngine)
        engine.providers = {}
        engine.store = Store()
        resolved = {
            "fact_kind": "member_resolution",
            "evidence": {"current_resolution": {
                "resolved_member_identity": "resolved-member",
            }},
        }
        self.assertEqual(engine._target_nodes(resolved), ("resolved-member",))
        for decision in (
            {},
            {"fact_kind": "member_resolution", "evidence": None},
            {"fact_kind": "member_resolution", "evidence": {
                "current_resolution": None,
            }},
        ):
            with self.subTest(decision=decision):
                self.assertEqual(len(engine._target_nodes(decision)), 1)

        decision = {
            "fact_kind": "method",
            "fact_scope": {
                "initiating_loader_realm_identity": "loader",
                "class_name": "demo.Type",
                "member_kind": "method",
                "member_name": "run",
                "descriptor": "()V",
            },
        }
        symbolic = engine._target_nodes(decision)
        engine.providers[("loader", "demo/Type")] = {
            "class_provider_status": "ambiguous",
        }
        self.assertEqual(engine._target_nodes(decision), symbolic)
        engine.providers[("loader", "demo/Type")] = {
            "class_provider_status": "resolved",
            "selected_class_variant_identity": "variant",
        }
        engine.store.result = []
        self.assertEqual(engine._target_nodes(decision), symbolic)
        engine.store.result = [
            {"member_identity": "one"}, {"member_identity": "two"},
        ]
        self.assertEqual(engine._target_nodes(decision), symbolic)
        engine.store.result = [{"member_identity": "physical"}]
        self.assertEqual(engine._target_nodes(decision), ("physical",))

        class_decision = {"fact_kind": "class", "fact_scope": {
            "class_name": None,
            "member_kind": None,
            "member_name": None,
            "descriptor": None,
        }}
        self.assertEqual(len(engine._target_nodes(class_decision)), 1)

    @staticmethod
    def trace_engine(*, exact=(), possible=(), max_paths=20, max_nodes=100):
        engine = object.__new__(BinaryTraceEngine)
        engine.entrypoints = set(exact) | set(possible)
        engine.exact_entrypoints = set(exact)
        engine.possible_entrypoints = set(possible)
        engine.exact_reachable_nodes = set()
        engine.possible_reachable_nodes = set(engine.entrypoints)
        engine.possible_path_nodes = set(possible)
        engine.reverse = defaultdict(list)
        engine._trace_cache = {}
        engine.max_paths_per_target = max_paths
        engine.max_visited_nodes = max_nodes
        engine.entrypoint_records_by_member = defaultdict(list)
        engine.members = {}
        engine.edges = {}
        engine.semantic_edges = {}
        return engine

    def test_trace_enumeration_covers_cache_limits_metadata_and_possible_overflow(self):
        engine = self.trace_engine(exact=("root",))
        self.assertEqual(engine._trace(("unreachable",)), ([], []))
        self.assertEqual(engine._trace(("unreachable",)), ([], []))

        engine = self.trace_engine(exact=("root",))
        engine.exact_reachable_nodes = {"root", "target"}
        engine.possible_reachable_nodes = {"root", "target"}
        engine.reverse["target"].append({
            "caller_member_identity": "root",
            "direct_edge_identity": "missing-edge",
            "certainty": "exact",
        })
        engine.entrypoint_records_by_member["root"].append({
            "entrypoint_record_identity": "entry-record",
            "member_identity": "root",
            "path_certainty": "exact",
        })
        paths, gaps = engine._trace(("target", "target"))
        self.assertEqual(gaps, [])
        self.assertEqual(paths[0]["path_certainty"], "exact")
        self.assertEqual(paths[0]["edges"][0]["caller_class_name"], "")
        self.assertEqual(paths[0]["edges"][0]["edge_kind"], "")

        limited = self.trace_engine(exact=("root",), max_paths=0)
        limited.exact_reachable_nodes = {"root", "target"}
        limited.possible_reachable_nodes = {"root", "target"}
        limited.reverse["target"].append({
            "caller_member_identity": "root",
            "direct_edge_identity": "edge",
            "certainty": "exact",
        })
        self.assertEqual(limited._trace(("target",)), ([], []))

        node_limited = self.trace_engine(exact=("root",), max_nodes=0)
        node_limited.exact_reachable_nodes = {"root", "target"}
        node_limited.possible_reachable_nodes = {"root", "target"}
        node_limited.reverse["target"].append({
            "caller_member_identity": "root",
            "direct_edge_identity": "edge",
            "certainty": "exact",
        })
        self.assertIn("trace_node_limit_exceeded", node_limited._trace(("target",))[1])

        possible = self.trace_engine(
            possible=("possible-a", "possible-b"), max_paths=1
        )
        possible.possible_reachable_nodes.update({"target"})
        possible.possible_path_nodes.add("target")
        possible.reverse["target"].extend((
            {"caller_member_identity": "possible-a",
             "direct_edge_identity": "edge-a", "certainty": "possible"},
            {"caller_member_identity": "possible-b",
             "direct_edge_identity": "edge-b", "certainty": "possible"},
        ))
        paths, gaps = possible._trace(("target",))
        self.assertEqual(len(paths), 1)
        self.assertIn("trace_path_enumeration_limit_exceeded", gaps)

        exact_overflow = self.trace_engine(exact=("root-a", "root-b"), max_paths=1)
        exact_overflow.exact_reachable_nodes.update({"target"})
        exact_overflow.possible_reachable_nodes.update({"target"})
        exact_overflow.reverse["target"].extend((
            {"caller_member_identity": "root-a", "direct_edge_identity": "a",
             "certainty": "exact"},
            {"caller_member_identity": "root-b", "direct_edge_identity": "b",
             "certainty": "exact"},
        ))
        self.assertIn(
            "trace_path_enumeration_limit_exceeded",
            exact_overflow._trace(("target",))[1],
        )

        mixed = self.trace_engine(
            exact=("exact-root",), possible=("possible-root",)
        )
        mixed.exact_reachable_nodes.update({"target", "possible-root"})
        mixed.possible_reachable_nodes.update({"target"})
        mixed.possible_path_nodes.add("target")
        mixed.reverse["target"].extend((
            {"caller_member_identity": "exact-root", "direct_edge_identity": "exact",
             "certainty": "exact"},
            {"caller_member_identity": "possible-root", "direct_edge_identity": "possible",
             "certainty": "exact"},
        ))
        mixed.reverse["exact-root"].append({
            "caller_member_identity": "exact-root",
            "direct_edge_identity": "cycle",
            "certainty": "possible",
        })
        mixed.entrypoint_records_by_member["exact-root"].append({
            "entrypoint_record_identity": "nonmatching",
            "path_certainty": "possible",
        })
        mixed.semantic_edges["exact"] = {
            "semantic_edge_identity": "exact",
            "semantic_edge_kind": "reflection",
            "evidence": {"source": "semantic"},
            "target_dependency_coord": "demo:target",
        }
        paths, gaps = mixed._trace(("target",))
        self.assertEqual(gaps, [])
        self.assertTrue(any(path["path_certainty"] == "exact" for path in paths))
        self.assertTrue(any(path["path_certainty"] == "possible" for path in paths))
        exact_path = next(path for path in paths if path["path_certainty"] == "exact")
        self.assertEqual(exact_path["entrypoint_records"], [])
        self.assertEqual(exact_path["edges"][0]["semantic_evidence"], {
            "source": "semantic",
        })
        self.assertEqual(
            exact_path["edges"][0]["target_dependency_coord"], "demo:target"
        )

    @staticmethod
    def result_engine(paths, trace_gaps=(), runtime_gaps=()):
        engine = object.__new__(BinaryTraceEngine)
        engine._target_nodes = lambda _decision: ("target",)
        engine._trace = lambda _targets: (list(paths), list(trace_gaps))
        engine.entrypoint_gaps = ()
        engine.runtime = SimpleNamespace(coverage_gaps=tuple(runtime_gaps))
        engine.member_resolutions = {}
        engine.linkage_resolutions = {}
        engine.members = {}
        engine.class_definition_statuses = {}
        engine.decisions = SimpleNamespace(analysis_context_identity="context")
        engine.profile = SimpleNamespace(identity="profile")
        engine.batch_graph_identity = "batch"
        return engine

    def test_result_truth_and_static_linkage_matrix(self):
        base = {
            "decision_identity": "decision",
            "fact_kind": "method",
            "fact_scope": None,
            "coverage_gaps": None,
        }
        result = self.result_engine([])._result_for(
            projection_identity="projection",
            decision=base,
            assessment_identity="assessment",
            diagnostic=False,
        )
        self.assertEqual(result["reachability_status"], "not_found_in_static_analysis")
        self.assertEqual(result["static_linkage_status"], "compatible_or_not_applicable")

        incomplete = self.result_engine([], runtime_gaps=("runtime-gap",))._result_for(
            projection_identity="projection",
            decision=base,
            assessment_identity="assessment",
            diagnostic=True,
        )
        self.assertEqual(incomplete["reachability_status"], "not_analyzed")
        self.assertEqual(incomplete["candidate_fact_status"], "candidate")

        path = {
            "path_certainty": "exact",
            "edges": [{
                "direct_edge_identity": "edge",
                "caller_member_identity": "caller",
            }],
        }
        engine = self.result_engine([path])
        engine.member_resolutions["edge"] = {
            "member_resolution_status": "resolved",
            "initiating_loader_realm_identity": None,
        }
        engine.linkage_resolutions["edge"] = {"linkage_status": "resolved"}
        rebound = dict(base, fact_scope={"member_change_kind": "removed"})
        result = engine._result_for(
            projection_identity="projection", decision=rebound,
            assessment_identity="assessment", diagnostic=False,
        )
        self.assertEqual(result["reachability_status"], "reachable")
        self.assertEqual(result["static_linkage_status"], "compatible_or_not_applicable")

        engine.member_resolutions["edge"]["member_resolution_status"] = "illegal_access"
        result = engine._result_for(
            projection_identity="projection", decision=base,
            assessment_identity="assessment", diagnostic=False,
        )
        self.assertEqual(result["static_linkage_status"], "incompatible_if_executed")

        possible_path = dict(path, path_certainty="possible")
        engine = self.result_engine([possible_path])
        engine.member_resolutions["edge"] = {
            "member_resolution_status": "ambiguous",
        }
        result = engine._result_for(
            projection_identity="projection", decision=base,
            assessment_identity="assessment", diagnostic=False,
        )
        self.assertEqual(result["reachability_status"], "uncertain")
        self.assertEqual(result["static_linkage_status"], "undetermined")

        unknown_edge = dict(path)
        unknown_edge["edges"] = [{
            "direct_edge_identity": "unknown-edge",
            "caller_member_identity": "known-caller",
        }]
        engine = self.result_engine([unknown_edge])
        engine.members["known-caller"] = {"class_name": "demo/Caller"}
        neutral = engine._result_for(
            projection_identity="projection",
            decision=dict(base, coverage_gaps=("decision-gap",)),
            assessment_identity="assessment",
            diagnostic=False,
        )
        self.assertIn("decision-gap", neutral["trace_coverage_gaps"])

        removed_without_path = self.result_engine([])._result_for(
            projection_identity="projection",
            decision=dict(base, fact_scope={"member_change_kind": "removed"}),
            assessment_identity="assessment",
            diagnostic=False,
        )
        self.assertEqual(
            removed_without_path["static_linkage_status"],
            "incompatible_if_executed",
        )

        contract_change = {
            **base,
            "fact_scope": {"member_change_kind": "contract_changed",
                           "member_kind": "method"},
            "evidence": {
                "base_contract": {"access": binary_trace_engine.ACC_PUBLIC},
                "current_contract": {
                    "access": binary_trace_engine.ACC_PUBLIC
                    | binary_trace_engine.ACC_ABSTRACT,
                },
            },
        }
        self.assertEqual(
            self.result_engine([])._result_for(
                projection_identity="projection", decision=contract_change,
                assessment_identity="assessment", diagnostic=False,
            )["static_linkage_status"],
            "incompatible_if_executed",
        )

        legal_access_engine = self.result_engine([path])
        legal_access_engine.member_resolutions["edge"] = {
            "member_resolution_status": "resolved",
            "initiating_loader_realm_identity": "loader",
        }
        legal_access_engine.linkage_resolutions["edge"] = {
            "linkage_status": "resolved",
        }
        legal_access_engine.members["caller"] = {"class_name": "demo/Caller"}
        legal_access_engine.class_definition_statuses[(
            "loader", "demo/Caller"
        )] = "definition_ready"
        legal_access = dict(contract_change)
        legal_access["evidence"] = {
            "base_contract": {"access": binary_trace_engine.ACC_PUBLIC},
            "current_contract": {"access": binary_trace_engine.ACC_PROTECTED},
        }
        self.assertEqual(
            legal_access_engine._result_for(
                projection_identity="projection", decision=legal_access,
                assessment_identity="assessment", diagnostic=False,
            )["static_linkage_status"],
            "compatible_or_not_applicable",
        )

        provider = self.result_engine([])._result_for(
            projection_identity="projection",
            decision=dict(base, fact_kind="provider_topology"),
            assessment_identity="assessment", diagnostic=False,
        )
        self.assertEqual(provider["static_linkage_status"], "undetermined")

    @staticmethod
    def service_engine(*, certainty=None, gaps=(), include_load=True, near=True,
                       dependency_artifacts=None, include_member=True,
                       mechanism=None):
        engine = object.__new__(BinaryTraceEngine)
        caller = "caller"
        literal = {
            "direct_edge_identity": "literal",
            "caller_member_identity": caller,
            "instruction_index": 10,
            "edge_kind": "type",
            "symbolic_owner": "demo/Api",
            "edge_json": '{"type_use_kind":"class_literal"}',
        }
        rows = [literal, {
            "direct_edge_identity": "non-literal",
            "caller_member_identity": caller,
            "instruction_index": None,
            "edge_kind": "type",
            "symbolic_owner": "demo/Api",
            "edge_json": None,
        }, {
            "direct_edge_identity": "sort-missing-kind",
            "caller_member_identity": "other-caller",
            "instruction_index": None,
            "edge_kind": None,
            "symbolic_owner": "other/Type",
        }]
        if include_load:
            rows.extend(({
                "direct_edge_identity": "load-missing-descriptor",
                "caller_member_identity": caller,
                "instruction_index": 8,
                "edge_kind": "method",
                "symbolic_owner": "java/util/ServiceLoader",
                "symbolic_name": "load",
                "symbolic_descriptor": None,
            }, {
                "direct_edge_identity": "load-before-literal",
                "caller_member_identity": caller,
                "instruction_index": 8,
                "edge_kind": "method",
                "symbolic_owner": "java/util/ServiceLoader",
                "symbolic_name": "load",
                "symbolic_descriptor": "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
            }, {
                "direct_edge_identity": "load",
                "caller_member_identity": caller,
                "instruction_index": 12 if near else 20,
                "edge_kind": "method",
                "symbolic_owner": "java/util/ServiceLoader",
                "symbolic_name": "load",
                "symbolic_descriptor": "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
            }))
        engine.edges = {
            item["direct_edge_identity"]: item for item in rows
        }
        engine.exact_reachable_nodes = {caller} if certainty == "exact" else set()
        engine.possible_reachable_nodes = (
            {caller} if certainty == "possible" else set()
        )
        engine.members = ({
            caller: {
                "class_name": "demo/Caller",
                "member_name": "run",
                "descriptor": "()V",
            },
        } if include_member else {})
        engine._trace = lambda _targets: ([{"path_identity": "path"}], list(gaps))
        engine.entrypoint_gaps = ()
        engine.runtime = SimpleNamespace(coverage_gaps=())
        engine.decisions = BinaryTraceBoundaryTest.decisions(
            authoritative_decisions=(
                {"fact_kind": "class", "decision_identity": "class"},
                {"fact_kind": "resource", "fact_scope": None,
                 "decision_identity": "empty-scope"},
                {"fact_kind": "resource", "fact_scope": {
                    "resource_name": "META-INF/other",
                }, "decision_identity": "other-resource"},
                {"fact_kind": "resource", "fact_scope": {
                    "resource_name": "META-INF/services/demo.Api",
                    "resource_mechanism": mechanism,
                }, "decision_identity": "service",
                 "dependency_artifacts": dependency_artifacts},
            ),
        )
        return engine

    def test_service_activation_covers_all_four_statuses_and_call_pair_boundaries(self):
        expected = {
            "exact": "reachable",
            "possible": "uncertain",
            None: "not_found_in_static_analysis",
        }
        for certainty, status in expected.items():
            engine = self.service_engine(
                certainty=certainty,
                dependency_artifacts=({"coord": "demo:api"},)
                if certainty == "exact" else None,
                include_member=certainty != "possible",
                mechanism="service_loader" if certainty == "exact" else None,
            )
            with self.subTest(certainty=certainty):
                results = engine._service_activation_results()
                self.assertEqual(len(results), 1)
                self.assertEqual(results[0]["activation_status"], status)
                self.assertEqual(results[0]["path_set_complete"], True)
                if certainty == "possible":
                    self.assertEqual(
                        results[0]["activation_callers"][0]["caller_class_name"],
                        "",
                    )

        analyzed_gap = self.service_engine(
            certainty=None, gaps=("trace-gap",)
        )._service_activation_results()[0]
        self.assertEqual(analyzed_gap["activation_status"], "not_analyzed")
        self.assertFalse(analyzed_gap["path_set_complete"])

        no_near_load = self.service_engine(
            certainty="exact", near=False
        )._service_activation_results()[0]
        self.assertEqual(
            no_near_load["activation_status"],
            "not_found_in_static_analysis",
        )

        zero_index = self.service_engine(certainty="exact")
        zero_index.edges["literal"]["instruction_index"] = None
        zero_index.edges["load"]["instruction_index"] = None
        self.assertEqual(
            zero_index._service_activation_results()[0]["activation_status"],
            "reachable",
        )

        class FilteredEdges(dict):
            def iter_service_activation_rows(self, service_owners):
                self.service_owners = service_owners
                return self.values()

        filtered = self.service_engine(certainty="exact")
        filtered.edges = FilteredEdges(filtered.edges)
        self.assertEqual(
            filtered._service_activation_results()[0]["activation_status"],
            "reachable",
        )
        self.assertEqual(filtered.edges.service_owners, ("demo/Api",))

    def test_service_activation_without_service_decisions_does_not_scan_edges(self):
        class Edges:
            def values(self):
                raise AssertionError("unrelated direct edges must not be scanned")

        engine = object.__new__(BinaryTraceEngine)
        engine.edges = Edges()
        engine.decisions = self.decisions(authoritative_decisions=({
            "fact_kind": "method",
            "decision_identity": "method",
        },))

        self.assertEqual(engine._service_activation_results(), [])

    def test_build_skips_non_targetable_candidate_and_binds_partial_coverage(self):
        engine = object.__new__(BinaryTraceEngine)
        engine.decisions = self.decisions(
            candidate_projection_plans=({
                "planning_status": "unsupported",
                "decision_identity": "ignored",
            },),
        )
        engine.assessment_by_identity = {}
        engine.decision_by_identity = {}
        engine._service_activation_results = lambda: []
        engine.entrypoint_discovery = self.discovery(gaps=("entry-gap",))
        engine.entrypoint_gaps = ("entry-gap",)
        engine.semantic_overlay = SimpleNamespace(
            identity="semantic", coverage_gaps=("semantic-gap",)
        )
        engine.runtime = SimpleNamespace(coverage_gaps=("runtime-gap",))
        engine.batch_graph_identity = "batch"
        engine.graph_stats = {"node_count": 0}
        bundle = engine.build()
        self.assertEqual(bundle.formal_results, ())
        self.assertEqual(bundle.candidate_results, ())
        self.assertEqual(bundle.coverage_status, "partial")
        self.assertEqual(
            set(bundle.coverage_gaps),
            {"entry-gap", "semantic-gap", "runtime-gap"},
        )

    def test_build_materializes_formal_targetable_candidates_and_resource_digests(self):
        engine = object.__new__(BinaryTraceEngine)
        engine.decisions = self.decisions(
            formal_projections=({
                "projection_identity": "formal-projection",
                "projection_assessment_identity": "assessment",
            },),
            candidate_projection_plans=(
                {"planning_status": "targetable", "decision_identity": "candidate",
                 "candidate_projection_plan_identity": "empty-plan",
                 "projection_obligation_keys": ()},
                {"planning_status": "targetable", "decision_identity": "candidate",
                 "candidate_projection_plan_identity": "plan",
                 "projection_obligation_keys": ("one", "two")},
            ),
        )
        engine.assessment_by_identity = {
            "assessment": {
                "projection_assessment_identity": "assessment",
                "decision_identity": "formal",
            },
        }
        engine.decision_by_identity = {
            "formal": {"decision_identity": "formal"},
            "candidate": {"decision_identity": "candidate"},
        }

        def result_for(**arguments):
            return {
                "trace_result_identity": "trace-" + arguments["projection_identity"],
                "trace_coverage_gaps": (
                    ["result-gap"] if arguments["diagnostic"] else []
                ),
            }

        engine._result_for = result_for
        engine._service_activation_results = lambda: [{
            "resource_activation_result_identity": "resource-result",
        }]
        engine.entrypoint_discovery = self.discovery(records=(
            {"member_identity": "entry"},
        ))
        engine.entrypoint_gaps = ()
        engine.semantic_overlay = None
        engine.runtime = SimpleNamespace(coverage_gaps=())
        engine.batch_graph_identity = "batch"
        engine.graph_stats = {"node_count": 1}
        bundle = engine.build()
        self.assertEqual(len(bundle.formal_results), 1)
        self.assertEqual(len(bundle.candidate_results), 2)
        self.assertEqual(len(bundle.resource_activation_results), 1)
        self.assertEqual(bundle.coverage_gaps, ("result-gap",))
        self.assertEqual(bundle.entrypoint_coverage_status, "complete")

    def test_no_target_fast_path_preserves_partial_gaps_and_semantic_identity(self):
        discovery = self.discovery(gaps=("entry-gap",))
        decisions = self.decisions(authoritative_decisions=(
            {"fact_kind": "resource", "fact_scope": None},
            {"fact_kind": "resource", "fact_scope": {}},
            {"fact_kind": "method"},
        ))
        semantic = SimpleNamespace(
            rows=(object(),), identity="semantic", coverage_gaps=("semantic-gap",)
        )
        with patch.object(
            binary_trace_engine, "discover_binary_entrypoints", return_value=discovery
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            bundle = build_binary_traces(
                object(), object(), self.runtime(coverage_gaps=("runtime-gap",)),
                decisions, semantic_overlay=semantic,
            )
        engine.assert_not_called()
        self.assertEqual(bundle.coverage_status, "partial")
        self.assertEqual(
            set(bundle.coverage_gaps),
            {"entry-gap", "runtime-gap", "semantic-gap"},
        )
        self.assertEqual(bundle.graph_stats["runtime_semantic_edge_count"], 1)
        self.assertEqual(bundle.entrypoint_coverage_status, "partial")

    def test_trace_builder_routes_possible_roots_and_service_short_circuit_inputs(self):
        runtime = self.runtime()
        cases = (
            (
                self.decisions(formal_projections=({"projection": "p"},)),
                self.discovery(possible=("possible-entry",)),
            ),
            (
                self.decisions(
                    formal_projections=({"projection": "p"},),
                    authoritative_decisions=({
                        "fact_kind": "resource",
                        "fact_scope": {
                            "resource_name": "META-INF/services/demo.Api",
                        },
                    },),
                ),
                self.discovery(),
            ),
            (
                self.decisions(candidate_projection_plans=({
                    "planning_status": "unsupported",
                },)),
                self.discovery(),
            ),
        )
        for decisions, discovery in cases:
            with self.subTest(decisions=decisions), patch.object(
                binary_trace_engine,
                "discover_binary_entrypoints",
                return_value=discovery,
            ), patch.object(
                binary_trace_engine, "BinaryTraceEngine"
            ) as engine, patch.object(
                binary_trace_engine,
                "hydrate_runtime_reconciliation",
                return_value=runtime,
            ):
                engine.return_value.build.return_value = "built"
                result = build_binary_traces(
                    object(), object(), runtime, decisions
                )
            if decisions.formal_projections:
                self.assertEqual(result, "built")


class BinaryTraceEngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        home = current_jdk_home()
        if not shutil.which("javac") or not home or not (home / "jmods").is_dir():
            raise unittest.SkipTest("full JDK required")
        cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        cls.platform = JdkPlatformImage(home, asm_jar=cls.asm_jar)

    @classmethod
    def tearDownClass(cls):
        # JdkPlatformImage deliberately shares the exact, digest-checked ASM
        # transport across hierarchy frontiers.  The production pipeline owns
        # and closes that phase-scoped pool in its ``finally`` block; this
        # standalone integration fixture must provide the matching boundary so
        # later process-lifecycle contract tests do not inherit its JVM.
        binary_asm_helper.close_persistent_asm_sessions()
        cls.platform = None

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def compile_side(self, side, value):
        vendor_source = self.root / side / "vendor-src" / "vendor" / "Api.java"
        vendor_source.parent.mkdir(parents=True)
        vendor_source.write_text(
            f"package vendor; public final class Api {{ public static int work(){{ return {value}; }} }}",
            encoding="utf-8",
        )
        vendor_classes = self.root / side / "vendor-classes"
        vendor_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(vendor_classes), str(vendor_source)],
            check=True,
            capture_output=True,
        )
        vendor_jar = self.root / side / "vendor.jar"
        with zipfile.ZipFile(vendor_jar, "w") as archive:
            archive.write(vendor_classes / "vendor" / "Api.class", "vendor/Api.class")

        business_source = self.root / side / "business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; public class Main { public int entry(){ return vendor.Api.work(); } }",
            encoding="utf-8",
        )
        business_classes = self.root / side / "business-classes"
        business_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-cp", str(vendor_jar), "-d", str(business_classes), str(business_source)],
            check=True,
            capture_output=True,
        )
        business_jar = self.root / side / "business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")
        return business_jar, vendor_jar

    def profile(self, business_sha, vendor_sha):
        required = RuntimeProfile.REQUIRED_FIELDS
        return RuntimeProfile({
            "target_jvm": {
                "vendor": self.platform.release.get("IMPLEMENTOR"),
                "major": self.platform.java_major,
                "version": self.platform.release.get("JAVA_VERSION"),
            },
            "runtime_platform_image_identity": self.platform.identity,
            "target_os": "test-os",
            "target_arch": self.platform.release.get("OS_ARCH", "unknown"),
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [
                {
                    "logical_location": "app/business.jar", "content_sha256": business_sha,
                    "path_kind": "business_classes", "slot": 0, "loader_realm": "application-loader",
                },
                {
                    "logical_location": "lib/vendor.jar", "content_sha256": vendor_sha,
                    "path_kind": "classpath", "slot": 1, "loader_realm": "application-loader",
                },
            ],
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["application-loader"],
                "realms": [
                    {"identity": "platform-loader", "kind": "platform", "module_mode": "named-platform"},
                    {
                        "identity": "application-loader", "kind": "application",
                        "parent": "platform-loader", "delegation": "parent_first", "module_mode": "unnamed",
                    },
                ],
            },
            "runtime_code_source_origin_mapping_identity": "origins-1",
            "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Main",
                    "member_name": "entry",
                    "descriptor": "()I",
                }],
            },
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def instance(self, artifact, profile, slot, kind, origin, coord):
        sha = binary_artifact_diff._sha256_file(artifact)
        return ArtifactInstance(
            outer_artifact_sha256=sha,
            container_entry="<artifact>",
            content_sha256=sha,
            runtime_profile_identity=profile.identity,
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind=kind,
            runtime_classpath_index=slot,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity=origin,
            coord=coord,
        )

    def build_store(self, artifacts, profile):
        store = BinaryFactStore()
        snapshots = {}
        for artifact, instance in artifacts:
            snapshot = binary_artifact_diff.snapshot_archive(
                artifact,
                artifact_instance_identity=instance.identity,
                expected_sha256=instance.content_sha256,
                asm_jar=self.asm_jar,
            )
            store.add_artifact_snapshot(instance, snapshot)
            snapshots[instance.coord] = snapshot
        return store, snapshots

    def test_exact_business_entry_path_reaches_changed_dependency_method(self):
        base_business, base_vendor = self.compile_side("base", 1)
        current_business, current_vendor = self.compile_side("current", 2)
        base_profile = self.profile(
            binary_artifact_diff._sha256_file(base_business),
            binary_artifact_diff._sha256_file(base_vendor),
        )
        current_profile = self.profile(
            binary_artifact_diff._sha256_file(current_business),
            binary_artifact_diff._sha256_file(current_vendor),
        )
        comparison = RuntimeComparison(
            base_profile, current_profile, "same_deployment_profile", "v1",
            ("target_jvm", "loader_topology"), ("dependency-artifacts",), (),
        )
        scope_required = AnalysisScope.REQUIRED_FIELDS
        scope = AnalysisScope({
            "analysis_observability_scope": "binary-static-v1",
            "artifact_diff_support_manifest_identity": "artifact-v1",
            "runtime_loader_support_manifest_identity": "loader-v1",
            "class_definition_support_manifest_identity": "definition-v1",
            "runtime_fact_semantic_capability_identity": "semantic-v1",
            "runtime_fact_dynamic_capability_identity": "dynamic-v1",
            "runtime_fact_transformer_capability_identity": "transformer-none",
            "environment_equivalence_capability_identity": "equivalence-v1",
            "field_coverage": {key: "known" for key in scope_required},
        })
        context = AnalysisContext(comparison, scope)
        base_business_instance = self.instance(
            base_business, base_profile, 0, "business_classes", "origin-business", "business",
        )
        base_vendor_instance = self.instance(
            base_vendor, base_profile, 1, "classpath", "origin-vendor", "vendor",
        )
        current_business_instance = self.instance(
            current_business, current_profile, 0, "business_classes", "origin-business", "business",
        )
        current_vendor_instance = self.instance(
            current_vendor, current_profile, 1, "classpath", "origin-vendor", "vendor",
        )
        base_store, base_snapshots = self.build_store(
            ((base_business, base_business_instance), (base_vendor, base_vendor_instance)), base_profile
        )
        current_store, current_snapshots = self.build_store(
            ((current_business, current_business_instance), (current_vendor, current_vendor_instance)), current_profile
        )
        try:
            artifact_diff = binary_artifact_diff.compare_artifact_snapshots(
                base_snapshots["vendor"], current_snapshots["vendor"],
                comparison_or_runtime_scope={"runtime_comparison_identity": comparison.identity},
            )
            base_runtime = RuntimeReconciler(
                base_store, base_profile, self.platform,
                analysis_context_identity=context.identity,
            ).reconcile(retain_record_kinds=(
                binary_runtime_reconciler._RECONCILIATION_RECORD_FIELDS
            ))
            current_runtime = RuntimeReconciler(
                current_store, current_profile, self.platform,
                analysis_context_identity=context.identity,
            ).reconcile(retain_record_kinds=(
                binary_runtime_reconciler._RECONCILIATION_RECORD_FIELDS
            ))
            decisions = BinaryDecisionEngine(
                analysis_context_identity=context.identity,
                runtime_comparison_identity=comparison.identity,
                base_store=base_store,
                current_store=current_store,
                base_reconciliation=base_runtime,
                current_reconciliation=current_runtime,
                artifact_local_diffs=(artifact_diff,),
            ).build()
            traces = BinaryTraceEngine(
                current_store, current_profile, current_runtime, decisions
            ).build()
        finally:
            base_store.close()
            current_store.close()

        work_decision = next(
            item for item in decisions.authoritative_decisions
            if item["fact_kind"] == "method" and item["fact_scope"]["member_name"] == "work"
        )
        work_assessment = next(
            item for item in decisions.projection_assessments
            if item["decision_identity"] == work_decision["decision_identity"]
        )
        result = next(
            item for item in traces.formal_results
            if item["projection_assessment_identity"] == work_assessment["projection_assessment_identity"]
        )
        self.assertEqual(traces.coverage_status, "complete")
        self.assertEqual(result["reachability_status"], "reachable")
        self.assertTrue(result["is_reachable"])
        self.assertTrue(result["exact_path_exists"])
        self.assertEqual(result["impact_conclusion"], "probable_impact")
        self.assertEqual(
            result["static_linkage_status"], "compatible_or_not_applicable"
        )
        self.assertEqual(result["runtime_verification_status"], "required_not_executed")
        self.assertFalse(result["runtime_verification_executed_by_system"])
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(
            result["batch_graph_identity"],
            traces.formal_results[0]["batch_graph_identity"],
        )
        self.assertEqual(
            traces.graph_stats["batch_transition_build"],
            "shared_target_independent_v1",
        )
        self.assertGreater(traces.graph_stats["exact_scc_count"], 0)
        self.assertGreater(traces.graph_stats["possible_scc_count"], 0)


if __name__ == "__main__":
    unittest.main()
