from __future__ import annotations

import io
import json
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s5_query_call_chain as s5  # noqa: E402


class S5QueryCallChainBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def method(symbol_id="id", qualified="demo.Owner.run", **overrides):
        values = {
            "symbol_id": symbol_id,
            "qualified_key": qualified,
            "simple_key": "method:run",
            "class_fqcn": "demo.Owner",
            "method_name": "run",
            "declared_signature": "()",
            "declared_qualified_key": f"{qualified}()",
            "owner_type": "dependency",
            "owner_coord": "g:a",
            "module": "module",
            "file": "/repo/Owner.java",
            "line": 1,
            "is_test": False,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def edge(caller="id", callee="demo.Target.changed()", **overrides):
        values = {
            "caller_symbol_id": caller,
            "caller_qualified_key": "demo.Owner.run()",
            "callee_key": callee,
            "callee_simple_key": "method:changed()",
            "evidence_type": "ast",
            "confidence": "high",
            "file": "/repo/Owner.java",
            "line": 1,
            "owner_type": "dependency",
            "owner_coord": "g:a",
            "module": "module",
            "is_test": False,
            "callee_fqcn_complete": True,
            "callee_signature_complete": True,
            "callee_resolution_note": "",
        }
        values.update(overrides)
        return values

    @staticmethod
    def index(methods=None, reverse=None, lookups=None, targets=None):
        result = {
            "schema": s5.SCHEMA,
            "methods": dict(methods or {}),
            "lookup_keys_by_symbol": dict(lookups or {}),
            "reverse_edges": dict(reverse or {}),
        }
        if targets is not None:
            result["target_apis"] = list(targets)
        return result

    def write_index(self, data=None, *, name="index.json"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data or self.index()), encoding="utf-8")
        return path

    def test_record_conversion_target_normalization_and_index_filter_matrix(self):
        empty_method = SimpleNamespace(line=None)
        method_record = s5._method_to_record(empty_method)
        self.assertEqual(method_record["line"], 0)
        self.assertEqual(method_record["symbol_id"], "")
        self.assertFalse(method_record["is_test"])

        empty_edge = SimpleNamespace(line=None)
        edge_record = s5._edge_to_record(empty_edge)
        self.assertEqual(edge_record["line"], 0)
        self.assertFalse(edge_record["callee_fqcn_complete"])

        self.assertEqual(
            s5._target_api_record(None),
            {"coord": "", "api_name": "", "api_signature": "", "symbol_kind": ""},
        )
        embedded = s5._target_api_record({
            "target_coord": " g:a ",
            "changed_symbol": " demo.Api.run(java.lang.String) ",
            "symbol_kind": " METHOD ",
        })
        self.assertEqual(embedded, {
            "coord": "g:a",
            "api_name": "demo.Api.run",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
        })
        invalid_signature = {
            "coord": "g:a",
            "api_name": "demo.Api.run",
            "api_signature": "(broken<",
            "symbol_kind": "method",
        }
        self.assertEqual(
            s5._target_api_identity(invalid_signature)[2], "(broken<"
        )

        valid_method = self.method()
        empty_id_method = self.method(symbol_id=" ")
        minimal_method = self.method(
            symbol_id="minimal",
            qualified="demo.Minimal.run",
            declared_signature="",
            declared_qualified_key="",
            simple_key="",
            class_fqcn="",
        )
        graph = SimpleNamespace(
            methods_by_id={
                " ": empty_id_method,
                "id": valid_method,
                "minimal": minimal_method,
            },
            lookup_keys_by_symbol={
                "id": ["", "demo.Owner.run()", "demo.Owner.run()", "method:run"],
            },
            reverse_edges={
                "": [SimpleNamespace()],
                "demo.Target.changed()": [SimpleNamespace(**self.edge())],
                "empty": None,
            },
        )
        result = s5.build_query_index(
            graph,
            graph_stats={"custom": 1},
            target_apis=[
                None,
                "not-a-dict",
                {},
                {"coord": "g:a", "api_name": "demo.Api.run", "api_signature": "()"},
            ],
        )
        self.assertEqual(list(result["methods"]), ["id", "minimal"])
        self.assertNotIn("", result["reverse_edges"])
        self.assertEqual(result["reverse_edges"]["empty"], [])
        self.assertEqual(result["stats"]["custom"], 1)
        self.assertEqual(result["stats"]["target_apis_indexed"], 1)

        bare = s5.build_query_index(SimpleNamespace())
        self.assertEqual(bare["methods"], {})
        self.assertEqual(bare["stats"]["target_apis_indexed"], 0)

    def test_load_inputs_path_inference_schema_alert_and_receipt_matrix(self):
        bad = self.write_index({"schema": "bad"}, name="bad.json")
        with self.assertRaisesRegex(ValueError, "不支持"):
            s5.load_query_inputs(bad)

        receipt = self.write_index(
            dict(self.index(), step4_publication_receipt_identity="receipt"),
            name="receipt.json",
        )
        with self.assertRaisesRegex(ValueError, "缺少可验证"):
            s5.load_query_inputs(receipt)

        standalone = self.write_index(name="standalone.json")
        data, alerts, loaded = s5.load_query_inputs(standalone)
        self.assertEqual(data["schema"], s5.SCHEMA)
        self.assertEqual(alerts, ())
        self.assertEqual(loaded, standalone)

        canonical_wrong_parent = self.write_index(
            name=f"wrong/{s5.STEP5_QUERY_INDEX_FILE}"
        )
        self.assertEqual(s5.load_query_inputs(canonical_wrong_parent)[2], canonical_wrong_parent)
        canonical_wrong_runtime = self.write_index(
            name=f"wrong/{s5.RUNTIME_INDEXES_DIRNAME}/{s5.STEP5_QUERY_INDEX_FILE}"
        )
        self.assertEqual(s5.load_query_inputs(canonical_wrong_runtime)[2], canonical_wrong_runtime)

        report = self.root / "report"
        report.mkdir()
        index_path = (
            report / s5.RUNTIME_DIRNAME / s5.RUNTIME_INDEXES_DIRNAME /
            s5.STEP5_QUERY_INDEX_FILE
        )
        bundle = {
            "index": dict(self.index(), step4_publication_receipt_identity="receipt"),
            "alerts": [{"path_text": "A → B"}],
            "index_path": str(index_path),
        }
        with mock.patch(
            "binary_report.load_consistent_step5_query_inputs",
            return_value=bundle,
        ) as load:
            loaded_data, loaded_alerts, loaded_path = s5.load_query_inputs(report)
        load.assert_called_once_with(report)
        self.assertEqual(loaded_data["step4_publication_receipt_identity"], "receipt")
        self.assertEqual(loaded_alerts, ({"path_text": "A → B"},))
        self.assertEqual(loaded_path, index_path)

        with mock.patch(
            "binary_report.load_consistent_step5_query_inputs",
            return_value=bundle,
        ):
            inferred = s5.load_query_inputs(index_path)
        self.assertEqual(inferred[2], index_path)

    def test_target_key_prefix_and_exact_path_matching_matrix(self):
        self.assertEqual(s5.build_target_keys(""), [])
        signed = s5.build_target_keys(" demo.Api.run( String , int ) ")
        self.assertIn("demo.Api.run(String , int )", signed)
        self.assertFalse(any(key == "demo.Api.run" for key in signed))
        unsigned = s5.build_target_keys("demo.Api.run")
        self.assertEqual(unsigned, ["demo.Api.run", "class:demo.Api.run"])
        simple = s5.build_target_keys("run")
        self.assertEqual(simple, ["run"])
        fuzzy_signed = s5.build_target_keys("demo.Api.run(String)", fuzzy=True)
        self.assertIn("method:run(String)", fuzzy_signed)
        self.assertIn("method:run", fuzzy_signed)
        fuzzy_class = s5.build_target_keys("demo.Api", fuzzy=True)
        self.assertIn("class:Api", fuzzy_class)
        malformed = s5.build_target_keys("demo.Api.run(broken<)", fuzzy=True)
        self.assertTrue(malformed)
        self.assertEqual(
            s5.build_target_keys("method:run", fuzzy=True).count("method:run"),
            1,
        )
        self.assertEqual(
            s5.build_target_keys("class:Api", fuzzy=True).count("class:Api"),
            1,
        )

        prefixes = s5._target_match_prefixes("demo.Api.run")
        self.assertIn("demo.Api.run(", prefixes)
        self.assertEqual(
            s5._target_match_prefixes("demo.Api.run()"),
            tuple(s5.build_target_keys("demo.Api.run()")),
        )
        self.assertEqual(s5._target_match_prefixes(""), ())

        self.assertFalse(s5._path_ends_with_target("", "demo.Api.run"))
        self.assertFalse(s5._path_ends_with_target("A → Other.run()", "demo.Api.run"))
        self.assertTrue(s5._path_ends_with_target("A -> g:a:demo.Api.run()", "demo.Api.run"))
        self.assertTrue(s5._path_ends_with_target("A → demo.Api.run", "demo.Api.run", "()"))
        self.assertTrue(s5._path_ends_with_target("A → demo.Api.run(String)", "demo.Api.run(String)"))
        self.assertFalse(s5._path_ends_with_target(
            "A → demo.Api.run(int)", "demo.Api.run", "(String)"
        ))

    def test_resolve_target_keys_edge_precision_and_next_lookup_matrix(self):
        index = self.index(reverse={
            "demo.Api.run": [self.edge()],
            "demo.Api.run()": [self.edge()],
            "demo.Api.run(String)": [self.edge()],
            "method:run": [self.edge()],
            "method:empty": [],
        })
        exact, matched = s5._resolve_target_keys(index, "demo.Api.run")
        self.assertEqual(exact[0:2], ["demo.Api.run()", "demo.Api.run(String)"])
        self.assertEqual(matched, exact)

        class_index = self.index(reverse={
            "demo.Api.run": [self.edge()],
            "class:demo.Api.run": [self.edge()],
        })
        class_exact, _ = s5._resolve_target_keys(class_index, "demo.Api.run")
        self.assertEqual(class_exact, ["demo.Api.run", "class:demo.Api.run"])
        self.assertEqual(s5._resolve_target_keys(self.index(), ""), ([], []))

        overload_boundaries = self.index(reverse={
            "other": [self.edge()],
            "demo.Api.run(int)": [],
            "demo.Api.run(String)": [self.edge()],
        })
        self.assertEqual(
            s5._resolve_target_keys(overload_boundaries, "demo.Api.run")[0],
            ["demo.Api.run(String)"],
        )

        signed_exact, signed_matched = s5._resolve_target_keys(
            index, "demo.Api.run()", fuzzy=True
        )
        self.assertTrue(signed_exact)
        self.assertEqual(signed_matched, signed_exact)

        fuzzy_index = self.index(reverse={"method:run": [self.edge()]})
        no_exact, fuzzy = s5._resolve_target_keys(
            fuzzy_index, "demo.Api.run()", fuzzy=True
        )
        self.assertEqual(no_exact, [])
        self.assertEqual(fuzzy, ["method:run()", "method:run"][-1:])
        fuzzy_empty_candidate = self.index(reverse={
            "method:run()": [],
            "method:run": [self.edge()],
        })
        self.assertEqual(
            s5._resolve_target_keys(
                fuzzy_empty_candidate, "demo.Api.run()", fuzzy=True
            )[1],
            ["method:run"],
        )

        edge = self.edge()
        self.assertTrue(s5._edge_contains_exact_target(edge, set(), (), fuzzy=True))
        self.assertFalse(s5._edge_contains_exact_target({"callee_key": ""}, set(), ()))
        self.assertTrue(s5._edge_contains_exact_target(edge, {edge["callee_key"]}, ()))
        self.assertTrue(s5._edge_contains_exact_target(
            edge, set(), ("demo.Target.changed(",)
        ))
        self.assertFalse(s5._edge_contains_exact_target(
            edge, set(), ("other(", "demo.Target.changed")
        ))

        for key, expected in (
            ("", False),
            ("method:run", False),
            ("class:Owner", False),
            ("class:demo.Owner", True),
            ("demo.Owner.run", True),
            ("run", False),
        ):
            self.assertEqual(s5._is_precise_lookup_key(key), expected)
        self.assertEqual(
            list(s5._iter_next_lookup_keys(
                [None, "", "method:run", "demo.Owner.run"], fuzzy=False
            )),
            ["demo.Owner.run"],
        )
        self.assertEqual(
            list(s5._iter_next_lookup_keys(["method:run"], fuzzy=True)),
            ["method:run"],
        )
        self.assertEqual(list(s5._iter_next_lookup_keys(None)), [])

    def test_format_sort_path_dedupe_and_chain_equivalence_matrix(self):
        self.assertEqual(s5._edge_sort_key({})[-3], 0)
        self.assertLess(
            s5._edge_sort_key({"confidence": "high", "owner_type": "business"}),
            s5._edge_sort_key({"confidence": "unknown", "owner_type": "dependency"}),
        )
        self.assertEqual(s5._format_node(None), "")
        self.assertEqual(
            s5._format_node({"qualified_key": "A.run", "owner_coord": "g:a", "owner_type": "dependency"}),
            "g:a:A.run",
        )
        self.assertEqual(
            s5._format_node({"qualified_key": "A.run", "owner_coord": "BUSINESS", "owner_type": "business"}),
            "A.run",
        )
        self.assertEqual(
            s5._format_node({"qualified_key": "A.run", "owner_coord": "g:a", "owner_type": "business"}),
            "A.run",
        )
        self.assertEqual(s5._format_node({"present": True}), "")
        self.assertEqual(s5._format_path([], {}, " target "), "target")
        fallback_edges = [
            {"caller_symbol_id": "missing", "caller_qualified_key": "Fallback.run", "callee_key": ""},
            {"caller_symbol_id": "", "caller_qualified_key": "", "callee_key": "ignored"},
        ]
        self.assertEqual(
            s5._format_path(fallback_edges, {}, "Target.run"),
            "? → Fallback.run → Target.run",
        )
        self.assertEqual(s5._path_parts([], {}, "  "), ())

        short = [{"caller_symbol_id": "a", "callee_key": "Target"}]
        long = [
            {"caller_symbol_id": "a", "callee_key": "Target"},
            {"caller_symbol_id": "b", "callee_key": "A"},
        ]
        methods = {
            "a": {"qualified_key": "A", "owner_coord": "", "owner_type": "business"},
            "b": {"qualified_key": "B", "owner_coord": "", "owner_type": "business"},
        }
        preferred = s5._dedupe_and_prefer_longest(
            [short, long, list(long)], methods, "Target", 5
        )
        self.assertEqual(preferred, [long])
        self.assertEqual(
            s5._dedupe_and_prefer_longest([], methods, "Target", 0), []
        )

        self.assertTrue(s5._chains_equivalent("A() -> B(String)", "A → B(String)"))
        self.assertTrue(s5._chains_equivalent("", ""))
        self.assertTrue(s5._chains_equivalent("A → B", "A() → B(String)"))
        self.assertFalse(s5._chains_equivalent("A", "A → B"))
        self.assertFalse(s5._chains_equivalent("A → B", "A → C"))
        self.assertFalse(s5._chains_equivalent("A()", "A(String)"))
        self.assertEqual(s5._chain_node_identity("A(broken<")[1], "(broken<")
        self.assertEqual(s5._chain_skeleton("A →  → B"), ("A", "B"))

    def test_merge_chain_group_precision_limit_and_identity_matrix(self):
        chains = []
        groups = {}
        self.assertTrue(s5._merge_chain(chains, "A → B", groups=groups))
        self.assertFalse(s5._merge_chain(chains, " A -> B ", groups=groups))
        self.assertFalse(s5._merge_chain(chains, "A() → B(String)", groups=groups))
        self.assertEqual(chains, ["A() → B(String)"])
        self.assertFalse(s5._merge_chain(chains, "A → C", limit=1, groups=groups))
        self.assertTrue(s5._merge_chain(chains, "X → Y", limit=None, groups=None))
        self.assertFalse(s5._merge_chain(chains, "X → Y", groups=None))

    def test_query_call_chains_limits_cycles_tests_depth_and_lookup_matrix(self):
        target = "vendor.Api.changed()"
        methods = {
            "business": {
                "qualified_key": "app.Main.run",
                "owner_coord": "BUSINESS",
                "owner_type": "business",
                "is_test": False,
            },
            "dep": {
                "qualified_key": "dep.Facade.call",
                "owner_coord": "g:dep",
                "owner_type": "dependency",
                "is_test": False,
            },
            "test": {"qualified_key": "app.Test.run", "owner_type": "business", "is_test": True},
        }
        index = self.index(
            methods=methods,
            reverse={
                target: [
                    self.edge("dep", target),
                    self.edge("test", target, is_test=True),
                    self.edge("test", target, is_test=False),
                    self.edge("missing", target),
                    self.edge("", target),
                ],
                "dep.Facade.call": [
                    self.edge("business", "dep.Facade.call", owner_type="business", owner_coord="BUSINESS"),
                    self.edge("dep", "dep.Facade.call"),
                ],
                "unused": [],
            },
            lookups={
                "dep": [
                    "",
                    "method:call",
                    "dep.Facade.call",
                    "dep.Facade.call",
                    "unused",
                ],
                "business": ["app.Main.run"],
            },
        )
        self.assertEqual(s5.query_call_chains(index, target, limit=0), [])
        self.assertEqual(s5.query_call_chains(index, "missing", limit=2), [])
        self.assertEqual(s5.query_call_chains(index, target, max_visits=0), [])
        self.assertEqual(s5.query_call_chains(index, target, max_depth=0), [])
        self.assertEqual(s5.query_call_chains(index, target, max_depth=1), [])
        chains = s5.query_call_chains(index, target, max_depth=5, limit=2)
        self.assertEqual(len(chains), 1)
        self.assertIn("app.Main.run", chains[0])
        self.assertIn(target, chains[0])

        direct_business = self.index(
            methods={"business": methods["business"]},
            reverse={target: [self.edge(
                "business", "wrong.Target()", owner_type="business", owner_coord="BUSINESS"
            )]},
        )
        self.assertEqual(s5.query_call_chains(direct_business, target), [])

        bounded = self.index(
            methods={
                "one": methods["business"],
                "two": dict(methods["business"], qualified_key="app.Second.run"),
                "extra": methods["dep"],
            },
            reverse={
                "vendor.Api.changed()": [self.edge(
                    "one", "vendor.Api.changed()", owner_type="business", owner_coord="BUSINESS"
                )],
                "vendor.Api.changed(String)": [self.edge(
                    "two", "vendor.Api.changed(String)", owner_type="business", owner_coord="BUSINESS"
                )],
                "extra.Key": [self.edge("extra", "extra.Key")],
            },
            lookups={"one": ["extra.Key"]},
        )
        self.assertEqual(
            len(s5.query_call_chains(bounded, "vendor.Api.changed", limit=1)),
            1,
        )

    def test_alert_path_query_and_row_validation_matrix(self):
        report = self.root / "report"
        self.assertEqual(s5._alerts_path(report), report / "evidence" / "call_chain" / "alerts.csv")
        standalone = self.write_index(name="standalone.json")
        self.assertEqual(s5._alerts_path(standalone), self.root / "evidence" / "call_chain" / "alerts.csv")
        canonical = self.write_index(
            name=f"canonical/{s5.RUNTIME_DIRNAME}/{s5.RUNTIME_INDEXES_DIRNAME}/{s5.STEP5_QUERY_INDEX_FILE}"
        )
        self.assertEqual(
            s5._alerts_path(canonical),
            self.root / "canonical" / "evidence" / "call_chain" / "alerts.csv",
        )
        self.assertEqual(s5.query_alert_chains(report, "A.run"), [])

        rows = [
            {"path_status": "blocked", "changed_symbol": "A.run", "path_text": "X → A.run"},
            {"path_status": "", "changed_symbol": "Other.run", "path_text": "X → Other.run"},
            {"path_status": "reachable", "changed_symbol": "A.run(int)", "api_signature": "(int)", "path_text": "X → A.run(int)"},
            {"path_status": "reachable", "changed_symbol": "A.run", "path_text": ""},
            {"path_status": "reachable", "changed_symbol": "A.run", "path_text": "X → Other.run"},
            {"path_status": "reachable", "changed_symbol": "A.run", "path_text": "X -> A.run(String)"},
            {"path_status": "reachable", "changed_symbol": "A.run", "path_text": "X → A.run(String)"},
            {"path_status": "reachable", "changed_symbol": "A.run", "path_text": "Y → A.run(String)"},
        ]
        chains = s5.query_alert_chains(
            report, "A.run(String)", limit=1, alert_rows=rows
        )
        self.assertEqual(chains, ["X → A.run(String)"])
        self.assertEqual(s5.query_alert_chains(
            report, "A.run(boolean)", alert_rows=rows
        ), [])
        self.assertEqual(
            s5.query_alert_chains(
                report, "A.run(String)", limit=10, alert_rows=rows
            ),
            ["X → A.run(String)", "Y → A.run(String)"],
        )

        self.assertEqual(s5._alert_scope_rows(report, alert_rows=[]), [])
        self.assertEqual(s5._alert_scope_rows(report), [])
        scope_rows = s5._alert_scope_rows(report, alert_rows=[
            {"path_status": "blocked", "path_text": "X → A.run", "changed_symbol": "A.run"},
            {"path_status": "reachable", "path_text": "", "changed_symbol": "A.run"},
            {"path_status": "reachable", "path_text": "X → Other", "changed_symbol": "A.run"},
            {"path_status": "", "path_text": "X -> A.run()", "target_coord": "g:a (1)", "changed_symbol": "A.run()"},
            {"path_status": "reachable", "path_text": "Z → A.run()", "target_coord": "", "changed_symbol": "A.run()"},
            {"path_status": "reachable", "path_text": "X → A.run", "target_coord": "g:a（2）", "changed_symbol": ""},
        ])
        self.assertEqual(len(scope_rows), 2)
        self.assertEqual(scope_rows[0]["coord"], "g:a")

    def test_coordinate_package_and_scope_target_resolution_matrix(self):
        coords = ["g:a:linux", "g:a:windows", "x:a", "g:b (2)", "g:c（3）", ""]
        self.assertEqual(s5._coord_ga("invalid"), "")
        self.assertEqual(s5._coord_ga("g:"), "")
        self.assertEqual(s5._resolve_coord_query("", coords)[1], "coord_not_found")
        self.assertEqual(s5._resolve_coord_query("g:b", coords)[1], "coord_exact")
        self.assertEqual(s5._resolve_coord_query("g:c", coords)[1], "coord_exact")
        self.assertEqual(s5._resolve_coord_query("g:a", coords)[1], "coord_ambiguous")
        self.assertEqual(s5._resolve_coord_query("a", coords)[1], "coord_ambiguous")
        self.assertEqual(s5._resolve_coord_query("missing", coords)[1], "coord_not_found")
        self.assertEqual(s5._resolve_coord_query("g:a:linux", coords)[1], "coord_exact")
        self.assertEqual(s5._resolve_coord_query("g:a:mac", coords)[1], "coord_not_found")

        self.assertTrue(s5._api_in_package("a.b.Api.run()", "a.b.*"))
        self.assertTrue(s5._api_in_package("a.b", "a.b"))
        self.assertFalse(s5._api_in_package("a.bc.Api.run", "a.b"))
        self.assertFalse(s5._api_in_package("a.b.Api.run", ""))

        targets = [
            {"coord": "g:a", "api_name": "a.b.Api.run", "api_signature": "()", "symbol_kind": "method"},
            {"coord": "g:b", "api_name": "a.bc.Other.run", "api_signature": "", "symbol_kind": "class"},
            {"coord": "", "api_name": "a.b.EmptyCoord.run", "api_signature": "()", "symbol_kind": "method"},
            "not-a-dict",
        ]
        index = self.index(targets=targets)
        matched, coords, mode, warnings = s5._resolve_scope_targets(index, "g:a", "coord")
        self.assertEqual((len(matched), coords, mode, warnings), (1, ["g:a"], "coord_exact", []))
        matched, coords, mode, warnings = s5._resolve_scope_targets(index, "a.b", "package")
        self.assertEqual((len(matched), coords, mode), (2, ["g:a"], "package_prefix"))
        self.assertEqual(s5._resolve_scope_targets(index, "", "package")[2], "package_not_found")
        self.assertTrue(s5._resolve_scope_targets(index, "missing", "package")[3])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            s5._resolve_scope_targets(index, "x", "other")

    def test_target_api_query_chain_helpers_and_alert_scope_matrix(self):
        self.assertEqual(s5._target_api_query({
            "api_name": "A.run", "api_signature": "()", "symbol_kind": "method"
        }), "A.run()")
        self.assertEqual(s5._target_api_query({
            "api_name": "A", "api_signature": "", "symbol_kind": "constructor"
        }), "")
        self.assertEqual(s5._target_api_query({
            "api_name": "A.run", "api_signature": "()", "symbol_kind": ""
        }), "A.run()")
        self.assertEqual(s5._target_api_query({
            "api_name": "A", "api_signature": "", "symbol_kind": "class"
        }), "A")
        self.assertEqual(s5._target_api_query({
            "api_name": "A", "api_signature": "()", "symbol_kind": "class"
        }), "A")
        self.assertEqual(s5._target_api_query({}), "")

        rows = [
            {"path_status": "reachable", "path_text": "X → a.b.Api.run()", "target_coord": "g:a", "changed_symbol": "a.b.Api.run()"},
            {"path_status": "reachable", "path_text": "Y → a.b.Api.run()", "target_coord": "g:a", "changed_symbol": "a.b.Api.run()"},
            {"path_status": "reachable", "path_text": "Z → a.b.Api.run()", "target_coord": "g:b", "changed_symbol": "a.b.Api.run()"},
            {"path_status": "reachable", "path_text": "N → a.b.Api.run()", "target_coord": "", "changed_symbol": "a.b.Api.run()"},
        ]
        coord = s5.query_alert_chains_by_scope(
            self.root, "g:a", "coord", limit=1, alert_rows=rows
        )
        self.assertEqual(coord["match_mode"], "coord_exact")
        self.assertEqual(len(coord["chains"]), 1)
        self.assertEqual(len(coord["_all_chains"]), 2)
        package = s5.query_alert_chains_by_scope(
            self.root, "a.b", "package", alert_rows=rows
        )
        self.assertEqual(package["match_mode"], "package_prefix")
        self.assertTrue(s5.query_alert_chains_by_scope(
            self.root, "", "package", alert_rows=rows
        )["warnings"])
        self.assertTrue(s5.query_alert_chains_by_scope(
            self.root, "missing", "package", alert_rows=rows
        )["warnings"])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            s5.query_alert_chains_by_scope(
                self.root, "x", "other", alert_rows=rows
            )

    def test_scope_result_ambiguous_unqueryable_merge_limit_and_old_index_matrix(self):
        index_path = self.root / "index.json"
        base_index = self.index(targets=[])

        with mock.patch.object(
            s5, "load_query_inputs", return_value=(base_index, (), index_path)
        ), mock.patch.object(
            s5,
            "_resolve_scope_targets",
            return_value=([], [], "coord_ambiguous", ["ambiguous"]),
        ):
            ambiguous = s5.query_scope_call_chain_result(
                self.root, "a", "coord"
            )
        self.assertEqual(ambiguous["match_mode"], "coord_ambiguous")

        targets = [
            {"coord": "g:a", "api_name": "A.run", "api_signature": "", "symbol_kind": "method"},
            {"coord": "g:a", "api_name": "A.work", "api_signature": "()", "symbol_kind": "method"},
            {"coord": "g:a", "api_name": "A.more", "api_signature": "()", "symbol_kind": "method"},
        ]
        scoped_index = self.index(targets=targets)
        alert_result = {
            "chains": ["Alert → A.work()"],
            "_all_chains": ["Alert → A.work()", "Extra → A.more()"],
            "matched_coords": ["g:a"],
            "matched_target_count": 3,
            "match_mode": "coord_exact",
            "warnings": [],
        }
        with mock.patch.object(
            s5, "load_query_inputs", return_value=(scoped_index, (), index_path)
        ), mock.patch.object(
            s5, "_resolve_scope_targets", return_value=(targets, ["g:a"], "coord_exact", [])
        ), mock.patch.object(
            s5, "query_call_chains", side_effect=[[], ["Graph → A.work()"], ["Graph → A.more()"]]
        ), mock.patch.object(
            s5, "query_alert_chains_by_scope", return_value=alert_result
        ):
            result = s5.query_scope_call_chain_result(
                self.root, "g:a", "coord", limit=2
            )
        self.assertEqual(result["unqueryable_target_count"], 1)
        self.assertTrue(result["limit_reached"])
        self.assertEqual(len(result["chains"]), 2)
        self.assertTrue(result["warnings"])

        old_index = self.index()
        with mock.patch.object(
            s5, "load_query_inputs", return_value=(old_index, (), index_path)
        ), mock.patch.object(
            s5, "_resolve_scope_targets", return_value=([], [], "coord_not_found", ["index warning"])
        ), mock.patch.object(
            s5,
            "query_alert_chains_by_scope",
            return_value=dict(alert_result, matched_target_count=1),
        ):
            old = s5.query_scope_call_chain_result(
                self.root, "g:a", "coord", limit=0
            )
        self.assertEqual(old["match_mode"], "alerts_coord_exact")
        self.assertEqual(old["matched_target_count"], 1)

        with mock.patch.object(
            s5, "load_query_inputs", return_value=(base_index, (), index_path)
        ), mock.patch.object(
            s5,
            "_resolve_scope_targets",
            return_value=([], [], "coord_not_found", ["not found"]),
        ), mock.patch.object(
            s5, "query_alert_chains_by_scope", return_value=alert_result
        ):
            no_targets = s5.query_scope_call_chain_result(
                self.root, "missing", "coord"
            )
        self.assertEqual(no_targets["chains"], [])

    def test_scope_result_no_chains_warning_precedence_matrix(self):
        index_path = self.root / "index.json"
        target = {"coord": "g:a", "api_name": "A.run", "api_signature": "()", "symbol_kind": "method"}
        base = self.index(targets=[target])
        empty_alert = {
            "chains": [], "_all_chains": [], "matched_coords": [],
            "matched_target_count": 0, "match_mode": "coord_not_found", "warnings": [],
        }

        def run(targets, warnings, *, unqueryable=False):
            chosen = [
                {"coord": "g:a", "api_name": "A", "api_signature": "", "symbol_kind": "method"}
            ] if unqueryable else targets
            with mock.patch.object(
                s5, "load_query_inputs", return_value=(base, (), index_path)
            ), mock.patch.object(
                s5, "_resolve_scope_targets", return_value=(chosen, ["g:a"], "coord_exact", warnings)
            ), mock.patch.object(s5, "query_call_chains", return_value=[]), mock.patch.object(
                s5, "query_alert_chains_by_scope", return_value=empty_alert
            ):
                return s5.query_scope_call_chain_result(
                    self.root, "g:a", "coord"
                )

        no_chain = run([target], [])
        self.assertIn("没有找到", no_chain["warnings"][0])
        preserved = run([target], ["existing"])
        self.assertEqual(preserved["warnings"], ["existing"])
        unqueryable = run([], [], unqueryable=True)
        self.assertEqual(unqueryable["unqueryable_target_count"], 1)
        self.assertTrue(unqueryable["warnings"])
        unqueryable_with_existing = run([], ["existing"], unqueryable=True)
        self.assertEqual(unqueryable_with_existing["warnings"], ["existing"])
        no_targets = run([], [])
        self.assertEqual(no_targets["warnings"], [])

    def test_query_result_warning_and_fuzzy_match_matrix(self):
        index_path = self.root / "index.json"
        index = self.index()

        def run(exact, matched, graph_chains, alert_chains, fuzzy=False):
            with mock.patch.object(
                s5, "load_query_inputs", return_value=(index, (), index_path)
            ), mock.patch.object(
                s5, "_resolve_target_keys", return_value=(exact, matched)
            ), mock.patch.object(
                s5, "query_call_chains", return_value=graph_chains
            ), mock.patch.object(
                s5, "query_alert_chains", return_value=alert_chains
            ):
                return s5.query_call_chain_result(
                    self.root, "A.run", fuzzy=fuzzy
                )

        exact = run(["A.run"], ["A.run"], ["X → A.run"], [])
        self.assertEqual(exact["match_mode"], "exact")
        alert = run([], [], [], ["X → A.run"])
        self.assertEqual(alert["match_mode"], "alerts_exact")
        blocked_fuzzy = run([], ["method:run"], [], [], fuzzy=False)
        self.assertIn("未使用简单名", blocked_fuzzy["warnings"][0])
        fuzzy_empty = run([], ["method:run"], [], [], fuzzy=True)
        self.assertIn("fuzzy", fuzzy_empty["warnings"][0])
        missing = run([], [], [], [])
        self.assertIn("未找到精确", missing["warnings"][0])
        fuzzy_missing = run([], [], [], [], fuzzy=True)
        self.assertIn("未找到精确", fuzzy_missing["warnings"][0])
        fuzzy = run([], ["method:run"], ["X → A.run"], [], fuzzy=True)
        self.assertEqual(fuzzy["match_mode"], "fuzzy")
        self.assertFalse(fuzzy["exact_match"])
        exact_but_empty = run(["A.run"], ["A.run"], [], [])
        self.assertIn("未找到精确", exact_but_empty["warnings"][0])
        fuzzy_exact = run(
            ["A.run"], ["A.run"], ["X → A.run"], [], fuzzy=True
        )
        self.assertEqual(fuzzy_exact["match_mode"], "exact")

    def test_render_and_cli_method_scope_json_human_and_fuzzy_error(self):
        self.assertEqual(s5.render_call_chains([]), "未找到调用链。")
        self.assertIn("2. B", s5.render_call_chains(["A", "B"]))
        self.assertEqual(
            s5.render_query_result({"chains": [], "warnings": ["warning"]}),
            "warning",
        )
        self.assertEqual(
            s5.render_query_result({"chains": [], "warnings": []}),
            "未找到精确匹配的调用链。",
        )
        self.assertIn("warning", s5.render_query_result({
            "chains": ["A → B"], "warnings": ["warning"]
        }))

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            s5.main(["--report-dir", "x", "--coord", "g:a", "--fuzzy"])

        with mock.patch.object(
            s5,
            "query_call_chain_result",
            return_value={"chains": [], "warnings": []},
        ) as method_query, redirect_stdout(io.StringIO()):
            self.assertEqual(s5.main([
                "--report-dir", "x", "--method", "A.run", "--fuzzy"
            ]), 0)
        self.assertTrue(method_query.call_args.kwargs["fuzzy"])

        scope_result = {"chains": [], "warnings": [], "query": "x"}
        for args in (
            ["--report-dir", "x", "--coord", "g:a", "--json"],
            ["--report-dir", "x", "--package", "a.b"],
        ):
            with self.subTest(args=args), mock.patch.object(
                s5, "query_scope_call_chain_result", return_value=scope_result
            ) as query, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(s5.main(args), 0)
                self.assertTrue(output.getvalue())
                expected_type = "coord" if "--coord" in args else "package"
                self.assertEqual(query.call_args.args[2], expected_type)


if __name__ == "__main__":
    unittest.main()
