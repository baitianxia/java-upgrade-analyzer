from __future__ import annotations

import copy
from contextlib import contextmanager
import dis
from functools import lru_cache
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import whitebox_call_coverage
import whitebox_coverage_gate
from test_suite_runner import discover_tests


def _profile_probe():
    return "observed"


def _comprehension_profile_probe(values):
    return tuple(_profile_probe() for _value in values)


@contextmanager
def _decorated_profile_probe():
    yield "decorated-observed"


@lru_cache(maxsize=2)
def _cached_profile_probe(value):
    return "left" if value else "right"


class WhiteboxCallCoverageTest(unittest.TestCase):
    def test_internal_scope_classifies_every_implementation_file_and_owner(self):
        contract = json.loads((
            ROOT / "tests" / "fixtures" / "internal_test_scope.json"
        ).read_text(encoding="utf-8"))
        result = whitebox_call_coverage.audit_internal_test_scope(
            ROOT,
            contract,
            discovered_test_ids=[test.id() for test in discover_tests(ROOT)],
        )

        self.assertEqual(result["issues"], [])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["structural_profile_exclusion_count"], 2)
        self.assertEqual(
            result["python_module_inventory_count"],
            result["analysis_module_count"] + result["support_module_count"],
        )
        graph = whitebox_call_coverage.build_static_call_graph(
            SCRIPTS, contract["analysis_entry_modules"],
        )
        dynamic_edges, evidence = (
            whitebox_coverage_gate._dynamic_edge_contract(
                ROOT,
                contract,
                source_identity=graph.source_identity,
                callable_ids={row.callable_id for row in graph.callables},
            )
        )
        self.assertEqual(len(dynamic_edges), evidence["edge_count"])
        self.assertTrue(dynamic_edges)
        self.assertTrue(dynamic_edges.isdisjoint(graph.resolved_edges))

    def test_internal_scope_rejects_unclassified_code_and_missing_test_owner(self):
        contract = json.loads((
            ROOT / "tests" / "fixtures" / "internal_test_scope.json"
        ).read_text(encoding="utf-8"))
        weakened = copy.deepcopy(contract)
        weakened["analysis_modules"].remove("streaming_json")
        weakened["governed_support_modules"][0]["test_selectors"] = [
            "tests.does_not_exist",
        ]

        result = whitebox_call_coverage.audit_internal_test_scope(
            ROOT,
            weakened,
            discovered_test_ids=[test.id() for test in discover_tests(ROOT)],
        )
        codes = {row["code"] for row in result["issues"]}

        self.assertIn("ANALYSIS_MODULE_CLOSURE_MISMATCH", codes)
        self.assertIn("INTERNAL_PYTHON_MODULE_INVENTORY_MISMATCH", codes)
        self.assertIn("INTERNAL_SCOPE_TEST_SELECTOR_UNRESOLVED", codes)

    def test_internal_scope_rejects_unowned_structural_profile_exclusion(self):
        contract = json.loads((
            ROOT / "tests" / "fixtures" / "internal_test_scope.json"
        ).read_text(encoding="utf-8"))
        weakened = copy.deepcopy(contract)
        weakened["structural_profile_exclusions"][0][
            "replacement_test_ids"
        ] = ["tests.missing.Replacement.test_case"]

        result = whitebox_call_coverage.audit_internal_test_scope(
            ROOT,
            weakened,
            discovered_test_ids=[test.id() for test in discover_tests(ROOT)],
        )

        self.assertEqual(result["status"], "failed")
        self.assertIn(
            "STRUCTURAL_PROFILE_EXCLUSION_TEST_UNRESOLVED",
            {row["code"] for row in result["issues"]},
        )

    def test_static_graph_is_reachable_from_production_entries_and_resolves_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            (scripts / "entry.py").write_text(textwrap.dedent("""
                import worker
                from helper import normalize
                from worker import Engine as WorkerEngine

                def main(value):
                    if value:
                        return worker.run(normalize(value))
                    return normalize(value)

                def unreachable_in_reachable_module():
                    return normalize("still governed")

                def local_import(value):
                    import worker as scoped_worker
                    return scoped_worker.run(value)

                def local_import_does_not_leak(value):
                    return scoped_worker.run(value)

                def ambiguous_conditional_import(value, flag):
                    if flag:
                        import worker as selected
                    else:
                        import helper as selected
                    return selected.run(value)

                def local_instance(value):
                    engine = worker.Engine()
                    return engine.execute(value)

                def imported_local_instance(value):
                    engine = WorkerEngine()
                    return engine.execute(value)

                def shadowed_module_name(value):
                    worker = object()
                    return worker.run(value)

                def imported_over_instance(value):
                    engine = worker.Engine()
                    import helper as engine
                    return engine.execute(value)

                def deleted_instance(value):
                    engine = worker.Engine()
                    del engine
                    return engine.execute(value)

                def exception_over_instance(value):
                    engine = worker.Engine()
                    try:
                        return value
                    except Exception as engine:
                        return engine.execute(value)
            """), encoding="utf-8-sig")
            (scripts / "worker.py").write_text(textwrap.dedent("""
                class Engine:
                    def execute(self, value):
                        return finish(value)

                def finish(value):
                    return value

                def run(value):
                    return Engine().execute(value)
            """), encoding="utf-8")
            (scripts / "helper.py").write_text(textwrap.dedent("""
                def normalize(value):
                    return value.strip()

                def run(value):
                    return value
            """), encoding="utf-8")
            (scripts / "test_tool.py").write_text(
                "def unrelated():\n    return 1\n", encoding="utf-8",
            )

            graph = whitebox_call_coverage.build_static_call_graph(
                scripts, ("entry",),
            )

        self.assertEqual(
            graph.reachable_modules, ("entry", "helper", "worker")
        )
        callable_ids = {row.callable_id for row in graph.callables}
        self.assertIn("entry::unreachable_in_reachable_module", callable_ids)
        self.assertNotIn("test_tool::unrelated", callable_ids)
        self.assertIn(
            ("entry::main", "helper::normalize"), graph.resolved_edges,
        )
        self.assertIn(
            ("entry::main", "worker::run"), graph.resolved_edges,
        )
        self.assertIn(
            ("worker::Engine.execute", "worker::finish"),
            graph.resolved_edges,
        )
        self.assertIn(
            ("worker::run", "worker::Engine.execute"),
            graph.resolved_edges,
        )
        self.assertIn(
            ("entry::local_import", "worker::run"), graph.resolved_edges,
        )
        self.assertIn(
            ("entry::local_instance", "worker::Engine.execute"),
            graph.resolved_edges,
        )
        self.assertIn(
            ("entry::imported_local_instance", "worker::Engine.execute"),
            graph.resolved_edges,
        )
        call_site_edges = {
            (row.caller, row.callee) for row in graph.call_sites
        }
        self.assertIn(("entry::main", "helper::normalize"), call_site_edges)
        self.assertIn(("entry::main", "worker::run"), call_site_edges)
        self.assertTrue(all(row.offset >= 0 for row in graph.call_sites))
        self.assertFalse(any(
            caller == "entry::local_import_does_not_leak"
            for caller, _callee in graph.resolved_edges
        ))
        self.assertFalse(any(
            caller == "entry::ambiguous_conditional_import"
            and callee in {"worker::run", "helper::run"}
            for caller, callee in graph.resolved_edges
        ))
        self.assertFalse(any(
            caller == "entry::shadowed_module_name"
            and callee == "worker::run"
            for caller, callee in graph.resolved_edges
        ))
        for caller in (
            "entry::imported_over_instance",
            "entry::deleted_instance",
            "entry::exception_over_instance",
        ):
            self.assertNotIn(
                (caller, "worker::Engine.execute"), graph.resolved_edges,
            )
        entry_branches = [
            row for row in graph.branch_alternatives
            if row.callable_id == "entry::main"
        ]
        self.assertEqual({row.side for row in entry_branches}, {
            "left", "right",
        })
        self.assertTrue(all("IF" in row.opname for row in entry_branches))
        self.assertEqual(len({row.offset for row in entry_branches}), 1)

    def test_static_graph_identity_changes_with_any_reachable_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            entry = scripts / "entry.py"
            dependency = scripts / "dependency.py"
            entry.write_text(
                "import dependency\ndef main():\n    return dependency.run()\n",
                encoding="utf-8",
            )
            dependency.write_text(
                "def run():\n    return 'first'\n", encoding="utf-8",
            )
            first = whitebox_call_coverage.build_static_call_graph(
                scripts, ("entry",),
            )
            dependency.write_text(
                "def run():\n    return 'second'\n", encoding="utf-8",
            )
            second = whitebox_call_coverage.build_static_call_graph(
                scripts, ("entry",),
            )

        self.assertRegex(first.source_identity, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first.source_identity, second.source_identity)
        self.assertEqual(
            first.index_payload()["source_identity"], first.source_identity,
        )

    def test_static_branch_denominator_excludes_cpython_builtin_fast_path_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            source = scripts / "entry.py"
            source.write_text(textwrap.dedent("""
                def main(values, marker, sentinel):
                    converted = tuple(value for value in values)
                    if marker is sentinel:
                        return any(converted)
                    return converted
            """), encoding="utf-8")
            graph = whitebox_call_coverage.build_static_call_graph(
                scripts, ("entry",),
            )
            module_code = compile(
                source.read_text(encoding="utf-8"), str(source), "exec",
                dont_inherit=True,
            )
            guard_offsets = set()
            for code in whitebox_call_coverage._iter_code_objects(module_code):
                instructions = list(dis.get_instructions(code))
                guard_offsets.update(
                    (code.co_qualname, instruction.offset)
                    for index, instruction in enumerate(instructions)
                    if whitebox_call_coverage._is_conditional_branch_instruction(
                        instruction
                    )
                    and whitebox_call_coverage._is_compiler_builtin_identity_guard(
                        instructions, index,
                    )
                )

        governed = {
            (row.code_qualname, row.offset)
            for row in graph.branch_alternatives
            if row.callable_id == "entry::main"
        }
        self.assertTrue(governed)
        self.assertTrue(guard_offsets.isdisjoint(governed))
        business_branches = [
            row for row in graph.branch_alternatives
            if row.callable_id == "entry::main" and row.line == 4
        ]
        self.assertEqual(
            {(row.side, row.opname) for row in business_branches},
            {("left", "POP_JUMP_IF_FALSE"), ("right", "POP_JUMP_IF_FALSE")},
        )

    def test_static_branch_denominator_excludes_exception_and_generator_protocol_jumps(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            source = scripts / "entry.py"
            source.write_text(textwrap.dedent("""
                class Scope:
                    def __enter__(self):
                        return self
                    def __exit__(self, *_args):
                        return False

                def main(flag):
                    try:
                        with Scope() as scope:
                            if flag:
                                return scope
                    except RuntimeError:
                        return None
                    return False

                def delegate(values):
                    yield from values
            """), encoding="utf-8")
            graph = whitebox_call_coverage.build_static_call_graph(
                scripts, ("entry",),
            )
            module_code = compile(
                source.read_text(encoding="utf-8"), str(source), "exec",
                dont_inherit=True,
            )
            protocol_offsets = set()
            for code in whitebox_call_coverage._iter_code_objects(module_code):
                instructions = list(dis.get_instructions(code))
                protocol_offsets.update(
                    (code.co_qualname, instruction.offset)
                    for index, instruction in enumerate(instructions)
                    if whitebox_call_coverage._is_conditional_branch_instruction(
                        instruction
                    )
                    and whitebox_call_coverage._is_compiler_protocol_branch(
                        instructions, index,
                    )
                )

        governed = {
            (row.code_qualname, row.offset)
            for row in graph.branch_alternatives
        }
        self.assertTrue(protocol_offsets)
        self.assertTrue(protocol_offsets.isdisjoint(governed))
        main_branches = [
            row for row in graph.branch_alternatives
            if row.callable_id == "entry::main"
        ]
        self.assertTrue(main_branches)
        self.assertEqual({row.side for row in main_branches}, {"left", "right"})
        self.assertFalse(any(
            row.callable_id == "entry::delegate"
            for row in graph.branch_alternatives
        ))

    def test_source_branch_identity_merges_finally_copies_but_not_short_circuits(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary)
            source = scripts / "entry.py"
            source.write_text(textwrap.dedent("""
                def duplicated(flag):
                    acquired = False
                    try:
                        if flag:
                            acquired = True
                            return 1
                        raise RuntimeError("failed")
                    finally:
                        if acquired:
                            acquired = False

                def distinct(first, second):
                    if first and second:
                        return True
                    return False
            """), encoding="utf-8")
            graph = whitebox_call_coverage.build_static_call_graph(
                scripts,
                ("entry",),
            )

        copied = [
            row for row in graph.branch_alternatives
            if row.callable_id == "entry::duplicated" and row.line == 10
        ]
        copied_offsets = {row.offset for row in copied}
        copied_source_keys = {
            whitebox_coverage_gate._source_branch_key(row) for row in copied
        }
        self.assertGreater(len(copied_offsets), 1)
        self.assertEqual(len(copied_source_keys), 2)

        short_circuits = [
            row for row in graph.branch_alternatives
            if row.callable_id == "entry::distinct" and row.line == 14
        ]
        short_circuit_source_keys = {
            whitebox_coverage_gate._source_branch_key(row)
            for row in short_circuits
        }
        self.assertGreaterEqual(len({row.column for row in short_circuits}), 2)
        self.assertEqual(len(short_circuit_source_keys), 4)

    def test_all_tests_structural_suite_combines_every_orthogonal_partition(self):
        partitions = {
            "blackbox": ["blackbox"],
            "whitebox": ["whitebox"],
            "performance": ["performance"],
        }

        self.assertEqual(
            whitebox_coverage_gate._select_tests("all-tests", partitions),
            ["blackbox", "whitebox", "performance"],
        )
        self.assertEqual(
            whitebox_coverage_gate._select_tests("all-internal", partitions),
            ["whitebox", "performance"],
        )

    def test_windows_structural_suite_requires_native_windows_evidence(self):
        self.assertIn("windows", whitebox_coverage_gate.SUITES)
        if os.name == "nt":
            return
        with self.assertRaisesRegex(
            ValueError, "WINDOWS_STRUCTURAL_EVIDENCE_REQUIRES_NATIVE_WINDOWS",
        ):
            whitebox_coverage_gate.run_gate(
                ROOT,
                suite_name="windows",
                policy_path=(
                    ROOT / "tests" / "fixtures" / "test_suite_policy.json"
                ),
                verbosity=0,
            )

    def test_structural_gate_rejects_selector_that_matches_no_test(self):
        exit_code, payload = whitebox_coverage_gate.run_gate(
            ROOT,
            suite_name="all-internal",
            policy_path=(
                ROOT / "tests" / "fixtures" / "test_suite_policy.json"
            ),
            selectors=("tests.does_not_exist",),
            verbosity=0,
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["reason_code"], "WHITEBOX_EXECUTION_FAILED")
        self.assertTrue(payload["execution"]["selection_empty"])
        self.assertEqual(payload["execution"]["selected"], 0)
        self.assertEqual(payload["execution"]["run"], 0)

    def test_evidence_identity_changes_with_test_truth_and_profiler_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tests" / "fixtures").mkdir(parents=True)
            (root / "scripts").mkdir()
            test_path = root / "tests" / "test_contract.py"
            truth_path = root / "tests" / "fixtures" / "truth.json"
            profiler_path = root / "scripts" / "whitebox_call_coverage.py"
            gate_path = root / "scripts" / "whitebox_coverage_gate.py"
            test_path.write_text("assert True\n", encoding="utf-8")
            truth_path.write_text('{"expected": 1}\n', encoding="utf-8")
            profiler_path.write_text("PROFILER = 1\n", encoding="utf-8")
            gate_path.write_text("GATE = 1\n", encoding="utf-8")
            first = whitebox_coverage_gate._evidence_input_identity(
                root, "a" * 64,
            )
            truth_path.write_text('{"expected": 2}\n', encoding="utf-8")
            second = whitebox_coverage_gate._evidence_input_identity(
                root, "a" * 64,
            )
            third = whitebox_coverage_gate._evidence_input_identity(
                root, "b" * 64,
            )

        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        self.assertNotEqual(second, third)

    def test_dynamic_edge_contract_is_source_bound_unique_and_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "tests" / "fixtures" / "dynamic.json"
            fixture.parent.mkdir(parents=True)
            payload = {
                "schema": (
                    "java-upgrade-analyzer.internal-dynamic-call-edges.v1"
                ),
                "source_identity": "a" * 64,
                "edges": [{"caller": "a::one", "callee": "b::two"}],
            }
            fixture.write_text(
                json.dumps(payload, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            scope = {"dynamic_call_edges": "tests/fixtures/dynamic.json"}

            edges, evidence = whitebox_coverage_gate._dynamic_edge_contract(
                root,
                scope,
                source_identity="a" * 64,
                callable_ids={"a::one", "b::two"},
            )
            self.assertEqual(edges, {("a::one", "b::two")})
            self.assertEqual(evidence["edge_count"], 1)

            payload["source_identity"] = "b" * 64
            fixture.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source is stale"):
                whitebox_coverage_gate._dynamic_edge_contract(
                    root,
                    scope,
                    source_identity="a" * 64,
                    callable_ids={"a::one", "b::two"},
                )

    def test_merged_coverage_rejects_stale_failed_or_unowned_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test_source = root / "tests" / "test_probe.py"
            test_source.parent.mkdir(parents=True)
            test_source.write_text("def test_probe(): pass\n", encoding="utf-8")
            report_path = root / "coverage.json"
            branch = ("a::one", "one", 3, 8, "left")
            report = {
                "schema": whitebox_coverage_gate.REPORT_SCHEMA,
                "suite": "whitebox",
                "scope": {
                    "source_identity": "a" * 64,
                    "evidence_input_identity": "b" * 64,
                    "audit": {"status": "passed"},
                },
                "execution": {
                    "status": "passed", "selected": 1,
                    "unique_selected": 1, "run": 1,
                    "duplicate_test_ids": [], "failures": [], "errors": [],
                    "unexpected_skips": [], "expected_failures": [],
                    "unexpected_successes": [], "loader_failures": [],
                    "child_profile_errors": [],
                },
                "coverage": {
                    "call_evidence_schema": whitebox_call_coverage.SCHEMA,
                    "branch_supported": True,
                    "call_site_supported": True,
                    "called": [{
                        "callable": "a::one",
                        "tests": ["<unattributed>", "tests.test_probe.test_probe"],
                    }],
                    "edges": [{
                        "caller": "a::one", "callee": "b::two",
                        "tests": ["tests.test_probe.test_probe"],
                    }],
                    "call_sites": [{
                        "caller": "a::one", "callee": "b::two",
                        "tests": ["tests.test_probe.test_probe"],
                    }],
                    "branches": [{
                        "callable": branch[0], "code_qualname": branch[1],
                        "code_first_line": branch[2], "offset": branch[3],
                        "side": branch[4], "destinations": [12],
                        "tests": ["tests.test_probe.test_probe"],
                    }],
                },
            }

            def write(value):
                report_path.write_text(
                    json.dumps(value, ensure_ascii=False), encoding="utf-8",
                )

            write(report)
            normalized, provenance = (
                whitebox_coverage_gate._coverage_payload_from_report(
                    root,
                    report_path,
                    source_identity="a" * 64,
                    evidence_input_identity="b" * 64,
                    callable_ids={"a::one", "b::two"},
                    static_edges={("a::one", "b::two")},
                    static_branches={branch},
                )
            )
            self.assertEqual(
                normalized["called"][0]["tests"],
                ["tests.test_probe.test_probe"],
            )
            self.assertRegex(provenance["sha256"], r"^[0-9a-f]{64}$")

            stale = copy.deepcopy(report)
            stale["scope"]["evidence_input_identity"] = "c" * 64
            write(stale)
            with self.assertRaisesRegex(ValueError, "truth are stale"):
                whitebox_coverage_gate._coverage_payload_from_report(
                    root, report_path, source_identity="a" * 64,
                    evidence_input_identity="b" * 64,
                    callable_ids={"a::one", "b::two"},
                    static_edges={("a::one", "b::two")},
                    static_branches={branch},
                )

            failed = copy.deepcopy(report)
            failed["execution"]["status"] = "failed"
            write(failed)
            with self.assertRaisesRegex(ValueError, "execution failed"):
                whitebox_coverage_gate._coverage_payload_from_report(
                    root, report_path, source_identity="a" * 64,
                    evidence_input_identity="b" * 64,
                    callable_ids={"a::one", "b::two"},
                    static_edges={("a::one", "b::two")},
                    static_branches={branch},
                )

            unowned = copy.deepcopy(report)
            unowned["coverage"]["called"][0]["tests"] = [
                "tests.missing.Owner.test_case"
            ]
            write(unowned)
            with self.assertRaisesRegex(ValueError, "owner is unresolved"):
                whitebox_coverage_gate._coverage_payload_from_report(
                    root, report_path, source_identity="a" * 64,
                    evidence_input_identity="b" * 64,
                    callable_ids={"a::one", "b::two"},
                    static_edges={("a::one", "b::two")},
                    static_branches={branch},
                )

    def test_runtime_profiler_is_safe_while_platform_tests_patch_os_name(self):
        callable_id = "probe::_profile_probe"
        profiler = whitebox_call_coverage.RuntimeCallProfiler(
            {(str(Path(__file__).resolve()), "_profile_probe"): callable_id},
            active_test_getter=lambda: self.id(),
        )
        previous = sys.getprofile()
        try:
            sys.setprofile(profiler)
            threading.setprofile(profiler)
            with patch.object(whitebox_call_coverage.os, "name", "nt"):
                self.assertEqual(_profile_probe(), "observed")
        finally:
            sys.setprofile(previous)
            threading.setprofile(None)

        payload = profiler.payload()
        self.assertEqual(
            payload["called"],
            [{"callable": callable_id, "tests": [self.id()]}],
        )

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_monitoring_profiler_records_call_and_edge_without_setprofile(self):
        callable_index = {
            (str(Path(__file__).resolve()), "_profile_probe"):
                "probe::_profile_probe",
            (str(Path(__file__).resolve()),
             "WhiteboxCallCoverageTest._call_profile_probe"):
                "probe::caller",
        }
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            callable_index, active_test_getter=lambda: self.id(),
        )
        profiler.start()
        try:
            self.assertEqual(self._call_profile_probe(), "observed")
        finally:
            profiler.stop()

        self.assertEqual(profiler.payload()["edges"], [{
            "caller": "probe::caller",
            "callee": "probe::_profile_probe",
            "tests": [self.id()],
        }])

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_anonymous_code_is_attributed_without_creating_parent_self_edge(self):
        path = str(Path(__file__).resolve())
        parent = "probe::_comprehension_profile_probe"
        callee = "probe::_profile_probe"
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            {
                (path, "_comprehension_profile_probe"): parent,
                (path, "_profile_probe"): callee,
            },
            active_test_getter=lambda: self.id(),
        )
        profiler.start()
        try:
            self.assertEqual(
                _comprehension_profile_probe((1, 2)),
                ("observed", "observed"),
            )
        finally:
            profiler.stop()

        self.assertEqual(profiler.payload()["edges"], [{
            "caller": parent,
            "callee": callee,
            "tests": [self.id()],
        }])

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_monitoring_profiler_records_static_call_site_when_target_is_mocked(self):
        code = self._call_profile_probe.__code__
        call_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(code)
            if instruction.opname.startswith("CALL")
        )
        edge = ("probe::caller", "probe::_profile_probe")
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            {
                (str(Path(__file__).resolve()), code.co_qualname): edge[0],
            },
            call_site_index={
                (
                    str(Path(__file__).resolve()),
                    code.co_qualname,
                    code.co_firstlineno,
                    call_offset,
                ): edge,
            },
            active_test_getter=lambda: self.id(),
        )
        profiler.start()
        try:
            with patch(
                f"{__name__}._profile_probe", return_value="mocked",
            ):
                self.assertEqual(self._call_profile_probe(), "mocked")
        finally:
            profiler.stop()

        self.assertEqual(profiler.payload()["edges"], [])
        self.assertEqual(profiler.payload()["call_sites"], [{
            "caller": edge[0], "callee": edge[1], "tests": [self.id()],
        }])

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_local_monitoring_includes_decorator_wrapped_production_code(self):
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            {
                (str(Path(__file__).resolve()), "_decorated_profile_probe"):
                    "probe::_decorated_profile_probe",
            },
            active_test_getter=lambda: self.id(),
        )
        profiler.start()
        try:
            with _decorated_profile_probe() as value:
                self.assertEqual(value, "decorated-observed")
        finally:
            profiler.stop()

        self.assertEqual(profiler.payload()["called"], [{
            "callable": "probe::_decorated_profile_probe",
            "tests": [self.id()],
        }])

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_local_monitoring_follows_c_implemented_lru_cache_wrapper(self):
        callable_id = "probe::_cached_profile_probe"
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            {
                (str(Path(__file__).resolve()), "_cached_profile_probe"):
                    callable_id,
            },
            active_test_getter=lambda: self.id(),
        )
        _cached_profile_probe.cache_clear()
        profiler.start()
        try:
            self.assertEqual(_cached_profile_probe(True), "left")
            self.assertEqual(_cached_profile_probe(False), "right")
        finally:
            profiler.stop()
            _cached_profile_probe.cache_clear()

        self.assertEqual(profiler.payload()["called"], [{
            "callable": callable_id,
            "tests": [self.id()],
        }])
        self.assertEqual(
            {row["side"] for row in profiler.payload()["branches"]},
            {"left", "right"},
        )

    def _call_profile_probe(self):
        return _profile_probe()

    @unittest.skipUnless(
        hasattr(sys, "monitoring"), "requires Python 3.12 sys.monitoring",
    )
    def test_global_monitoring_captures_code_loaded_after_profiler_start(self):
        profiler = whitebox_call_coverage.MonitoringCallProfiler(
            {("/virtual/dynamic_probe.py", "dynamic_probe"):
             "probe::dynamic_probe"},
            active_test_getter=lambda: self.id(),
            local_only=False,
        )
        profiler.start()
        try:
            namespace = {}
            exec(compile(
                "def dynamic_probe(value):\n"
                "    return 'left' if value else 'right'\n",
                "/virtual/dynamic_probe.py",
                "exec",
            ), namespace)
            self.assertEqual(namespace["dynamic_probe"](True), "left")
            self.assertEqual(namespace["dynamic_probe"](False), "right")
        finally:
            profiler.stop()

        self.assertEqual(profiler.payload()["called"], [{
            "callable": "probe::dynamic_probe",
            "tests": [self.id()],
        }])
        self.assertEqual(
            {row["side"] for row in profiler.payload()["branches"]},
            {"left", "right"},
        )

    def test_child_profiler_only_attaches_to_governed_python_entrypoints(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            governed = root / "repository" / "scripts" / "run_step.py"
            governed.parent.mkdir(parents=True)
            governed.write_text("def main(): return 0\n", encoding="utf-8")
            fake_java = root / "jdk-timeout" / "bin" / "java"
            fake_java.parent.mkdir(parents=True)
            fake_java.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            payload = {
                "schema": whitebox_call_coverage.INDEX_SCHEMA,
                "callables": [{
                    "id": "run_step::main",
                    "path": str(governed),
                    "qualname": "main",
                }],
            }

            self.assertTrue(
                whitebox_call_coverage.process_target_is_governed(
                    payload,
                    argv=(str(governed), "--step", "step0"),
                    orig_argv=(
                        sys.executable, str(governed), "--step", "step0",
                    ),
                )
            )
            self.assertFalse(
                whitebox_call_coverage.process_target_is_governed(
                    payload,
                    argv=(str(fake_java), "RuntimeOutcomeOracle"),
                    orig_argv=(
                        sys.executable, str(fake_java), "RuntimeOutcomeOracle",
                    ),
                )
            )
            self.assertFalse(
                whitebox_call_coverage.process_target_is_governed(
                    payload,
                    argv=("-c",),
                    orig_argv=(
                        sys.executable, "-c", "print('fixture')",
                    ),
                )
            )

    def test_coverage_gate_module_is_safe_when_spawn_imports_main_script(self):
        namespace = runpy.run_path(
            str(SCRIPTS / "whitebox_coverage_gate.py"),
            run_name="__mp_main__",
        )

        self.assertIn("main", namespace)

    def test_process_payloads_merge_callers_callees_and_test_owners(self):
        merged = whitebox_call_coverage.merge_process_payloads((
            {
                "schema": whitebox_call_coverage.SCHEMA,
                "process_id": 10,
                "branch_supported": True,
                "call_site_supported": True,
                "called": [{"callable": "a::one", "tests": ["test.one"]}],
                "edges": [{
                    "caller": "a::one", "callee": "b::two",
                    "tests": ["test.one"],
                }],
                "call_sites": [{
                    "caller": "a::one", "callee": "b::two",
                    "tests": ["test.one"],
                }],
                "branches": [{
                    "callable": "a::one", "code_qualname": "one",
                    "code_first_line": 4, "offset": 8, "side": "left",
                    "destinations": [12], "tests": ["test.one"],
                }],
            },
            {
                "schema": whitebox_call_coverage.SCHEMA,
                "process_id": 11,
                "branch_supported": True,
                "call_site_supported": True,
                "called": [{"callable": "a::one", "tests": ["test.two"]}],
                "edges": [{
                    "caller": "a::one", "callee": "b::two",
                    "tests": ["test.two"],
                }],
                "call_sites": [{
                    "caller": "a::one", "callee": "b::two",
                    "tests": ["test.two"],
                }],
                "branches": [{
                    "callable": "a::one", "code_qualname": "one",
                    "code_first_line": 4, "offset": 8, "side": "left",
                    "destinations": [14], "tests": ["test.two"],
                }],
            },
        ))

        self.assertEqual(merged["process_ids"], [10, 11])
        self.assertEqual(merged["called"], [{
            "callable": "a::one", "tests": ["test.one", "test.two"],
        }])
        self.assertEqual(merged["edges"], [{
            "caller": "a::one", "callee": "b::two",
            "tests": ["test.one", "test.two"],
        }])
        self.assertTrue(merged["call_site_supported"])
        self.assertEqual(merged["call_sites"], [{
            "caller": "a::one", "callee": "b::two",
            "tests": ["test.one", "test.two"],
        }])
        self.assertTrue(merged["branch_supported"])
        self.assertEqual(merged["branches"], [{
            "callable": "a::one",
            "code_qualname": "one",
            "code_first_line": 4,
            "offset": 8,
            "side": "left",
            "destinations": [12, 14],
            "tests": ["test.one", "test.two"],
        }])

    def test_call_index_rejects_duplicate_runtime_identity(self):
        payload = {
            "schema": whitebox_call_coverage.INDEX_SCHEMA,
            "callables": [
                {"id": "a::one", "path": __file__, "qualname": "one"},
                {"id": "a::two", "path": __file__, "qualname": "one"},
            ],
        }

        with self.assertRaisesRegex(ValueError, "duplicated"):
            whitebox_call_coverage.callable_index_from_payload(payload)


if __name__ == "__main__":
    unittest.main()
