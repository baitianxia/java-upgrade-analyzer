from __future__ import annotations

import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import enhanced_source_analyzer as analyzer


def method_def(**overrides):
    values = {
        "symbol_id": "com.acme.Sample#work@Sample.java:1",
        "qualified_key": "com.acme.Sample.work",
        "simple_key": "method:work",
        "class_fqcn": "com.acme.Sample",
        "class_name": "Sample",
        "method_name": "work",
        "return_type": "void",
        "file": "Sample.java",
        "line": 1,
        "end_line": 2,
        "package_name": "com.acme",
        "owner_type": "business",
        "owner_coord": "BUSINESS",
        "module": "root",
        "source_root": "src/main/java",
        "language": "java",
        "is_test": False,
    }
    field_names = set(analyzer.MethodDef.__dataclass_fields__)
    values.update({key: value for key, value in overrides.items() if key in field_names})
    result = analyzer.MethodDef(**values)
    for key, value in overrides.items():
        if key not in field_names:
            setattr(result, key, value)
    return result


class FakeNode:
    def __init__(
        self,
        node_type,
        text="",
        *,
        fields=None,
        children=None,
        parent=None,
        start_byte=0,
        end_byte=None,
        start_row=0,
        end_row=None,
    ):
        self.type = node_type
        self.text = text
        self._fields = dict(fields or {})
        self.children = list(children or [])
        self.parent = parent
        self.start_byte = start_byte
        self.end_byte = (
            start_byte + len(text.encode("utf-8"))
            if end_byte is None else end_byte
        )
        self.start_point = SimpleNamespace(row=start_row, column=0)
        self.end_point = SimpleNamespace(
            row=start_row if end_row is None else end_row,
            column=0,
        )
        for child in self.children:
            child.parent = self
        for child in self._fields.values():
            if child is not None:
                child.parent = self

    def child_by_field_name(self, name):
        return self._fields.get(name)


def tree_analyzer_without_parser():
    instance = object.__new__(analyzer.TreeSitterAnalyzer)
    instance.file_path = "Sample.java"
    instance.source_root = {"root": "src/main/java", "module": "root"}
    instance.language = "java"
    instance.helper = analyzer.EnhancedRegexAnalyzer(
        "Sample.java",
        {"root": "src/main/java", "module": "root"},
    )
    instance.helper.package_name = "com.acme"
    instance.helper.imports = {"Order": "com.acme.model.Order"}
    instance._node_text = lambda node, _source: getattr(node, "text", "")
    return instance


class EnvironmentAndDiagnosticContractTest(unittest.TestCase):
    def test_environment_flags_status_and_preflight_are_side_effect_free(self):
        with patch.dict(
            os.environ,
            {
                "FEATURE_ON": " yes ",
                "FEATURE_OFF": "OFF",
                "JUA_STEP5_DEBUG": "true",
                "JUA_STEP5_DEBUG_BREAK": "1",
            },
            clear=False,
        ):
            self.assertTrue(analyzer._env_flag_enabled("FEATURE_ON"))
            self.assertTrue(analyzer._env_flag_disabled("FEATURE_OFF"))
            self.assertFalse(analyzer._env_flag_enabled("FEATURE_OFF"))
            self.assertTrue(analyzer._step5_debug_enabled())
            self.assertTrue(analyzer._step5_debug_break_enabled())

            stderr = io.StringIO()
            with patch.object(analyzer.sys, "stderr", stderr):
                analyzer._step5_debug("resolution", "observed", kept=1, omitted=None)
            payload = stderr.getvalue()
            self.assertIn('"topic": "resolution"', payload)
            self.assertIn('"kept": 1', payload)
            self.assertNotIn("omitted", payload)

            with patch("builtins.breakpoint") as breakpoint_call, patch.object(
                analyzer, "_step5_debug",
            ) as debug:
                analyzer._step5_debug_break("resolution", candidate="one")
            breakpoint_call.assert_called_once_with()
            debug.assert_called_once()

        with patch.dict(os.environ, {"JUA_STEP5_DEBUG": "0"}, clear=False):
            stderr = io.StringIO()
            with patch.object(analyzer.sys, "stderr", stderr):
                analyzer._step5_debug("disabled", "must not print")
            self.assertEqual(stderr.getvalue(), "")

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", False):
            self.assertFalse(analyzer._ensure_tree_sitter_available())
            self.assertFalse(analyzer.ensure_tree_sitter_available())
            status = analyzer.tree_sitter_status()
        self.assertFalse(status["available"])
        self.assertFalse(status["auto_install_enabled"])
        self.assertEqual(status["isolated_install_dir"], "")
        self.assertIn("bootstrap_runtime.py", status["install_command"])
        self.assertTrue(status["requirements_file"].endswith("requirements-runtime.txt"))
        self.assertIn(str(analyzer.sys.executable or "python"), analyzer._current_python_pip_install_cmd())

    def test_debug_break_is_a_noop_unless_explicitly_enabled(self):
        with patch.dict(os.environ, {"JUA_STEP5_DEBUG_BREAK": "false"}, clear=False), patch(
            "builtins.breakpoint",
        ) as breakpoint_call:
            analyzer._step5_debug_break("disabled")
        breakpoint_call.assert_not_called()

    def test_path_encoding_and_source_budget_boundaries_are_deterministic(self):
        role_cases = {
            None: "unknown",
            "": "unknown",
            "Sample.java": "unknown",
            "/project/java/Sample.java": "unknown",
            "/project/src/test/java/Sample.java": "test",
            "/project/src/tests/Sample.java": "test",
            "/project/src/testFixtures/java/Sample.java": "test",
            "/project/src/integrationTest/java/Sample.java": "test",
            r"C:\project\src\main\java\Sample.java": "production",
            "/project/src/commonMain/kotlin/Sample.kt": "production",
            "/project/src/custom/java/Sample.java": "unknown",
        }
        for value, expected in role_cases.items():
            with self.subTest(path=value):
                self.assertEqual(analyzer.source_set_role(value), expected)

        with patch.dict(
            os.environ, {"JUA_TREE_SITTER_TOOL_DIR": "~/jua-parser"},
            clear=False,
        ):
            self.assertEqual(
                analyzer._tree_sitter_tool_dir(),
                Path("~/jua-parser").expanduser(),
            )
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(
                str(analyzer._tree_sitter_tool_dir()).endswith(
                    f"java-upgrade-analyzer/python/py{sys.version_info.major}{sys.version_info.minor}",
                ),
            )

        decode_cases = {
            b"": "",
            b"class Sample {}": "class Sample {}",
            "class 样例 {}".encode("utf-8-sig"): "class 样例 {}",
            "class 样例 {}".encode("utf-16"): "class 样例 {}",
            "class 样例 {}".encode("gb18030"): "class 样例 {}",
            b"\x81": "\ufffd",
        }
        for value, expected in decode_cases.items():
            with self.subTest(encoded=value[:8]):
                self.assertEqual(analyzer.decode_java_source_bytes(value), expected)

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_bytes(b"")
            with patch.object(analyzer, "MAX_TREE_SITTER_SOURCE_BYTES", 1), patch.object(
                analyzer, "MAX_TREE_SITTER_SOURCE_LINES", 1,
            ):
                self.assertEqual(analyzer.tree_sitter_source_limit_reason(source), "")
                source.write_bytes(b"ab")
                self.assertEqual(
                    analyzer.tree_sitter_source_limit_reason(source),
                    "source_file_byte_limit_exceeded",
                )
            source.write_bytes(b"a\nb\n")
            with patch.object(analyzer, "MAX_TREE_SITTER_SOURCE_BYTES", 100), patch.object(
                analyzer, "MAX_TREE_SITTER_SOURCE_LINES", 1,
            ):
                self.assertEqual(
                    analyzer.tree_sitter_source_limit_reason(source),
                    "source_file_line_limit_exceeded",
                )
            source.write_bytes(b"a\n")
            with patch.object(analyzer, "MAX_TREE_SITTER_SOURCE_BYTES", 100), patch.object(
                analyzer, "MAX_TREE_SITTER_SOURCE_LINES", 1,
            ):
                self.assertEqual(analyzer.tree_sitter_source_limit_reason(source), "")
            self.assertEqual(
                analyzer.tree_sitter_source_limit_reason(Path(temporary) / "missing.java"),
                "source_file_unreadable",
            )

    def test_environment_helpers_cover_empty_values_without_fabricating_state(self):
        with patch.dict(
            os.environ,
            {
                "FLAG_ZERO": " 0 ",
                "FLAG_FALSE": "false",
                "FLAG_NO": "NO",
                "FLAG_OFF": "off",
                "FLAG_EMPTY": "",
                "JUA_STEP5_DEBUG": "yes",
            },
            clear=False,
        ):
            for name in ("FLAG_ZERO", "FLAG_FALSE", "FLAG_NO", "FLAG_OFF"):
                self.assertTrue(analyzer._env_flag_disabled(name))
            self.assertFalse(analyzer._env_flag_disabled("FLAG_EMPTY"))
            stderr = io.StringIO()
            with patch.object(analyzer.sys, "stderr", stderr):
                analyzer._step5_debug(None, None)
                analyzer._step5_debug("topic", "message", false_value=False, none_value=None)
            payload = stderr.getvalue()
            self.assertIn('"topic": ""', payload)
            self.assertIn('"message": ""', payload)
            self.assertIn('"false_value": false', payload)
            self.assertNotIn("none_value", payload)

        with patch.object(analyzer.sys, "executable", ""):
            self.assertTrue(analyzer._current_python_pip_install_cmd().startswith('"python"'))
            self.assertEqual(analyzer.tree_sitter_status()["python_executable"], "python")

    def test_java_analysis_attempts_mandatory_tree_sitter_before_reporting_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_text(
                "package com.acme; class Sample { void work() {} }\n",
                encoding="utf-8",
            )
            with patch.object(analyzer, "TREE_SITTER_AVAILABLE", False), patch.object(
                analyzer, "_ensure_tree_sitter_available", return_value=False,
            ) as ensure:
                methods, diagnostics = analyzer.analyze_file(
                    str(source),
                    {"root": temporary, "module": "root"},
                    prefer_tree_sitter=True,
                    return_diagnostics=True,
                )

        ensure.assert_called_once_with()
        self.assertEqual(methods, [])
        self.assertEqual(diagnostics["actual_parser"], "skipped")
        self.assertEqual(
            diagnostics["fallback_reason"], "tree_sitter_unavailable",
        )

    def test_analysis_entrypoint_covers_limits_languages_parser_results_and_failures(self):
        root = {"root": "src", "module": "root"}
        with patch.object(
            analyzer, "tree_sitter_source_limit_reason",
            return_value="source_file_byte_limit_exceeded",
        ):
            self.assertEqual(analyzer.analyze_file("Large.java", root), [])
            methods, info = analyzer.analyze_file(
                "Large.java", root, return_diagnostics=True,
            )
        self.assertEqual(methods, [])
        self.assertEqual(info["actual_parser"], "skipped")
        self.assertEqual(info["fallback_reason"], "source_file_byte_limit_exceeded")

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", False), patch.object(
            analyzer, "tree_sitter_source_limit_reason", return_value="",
        ), patch.object(
            analyzer, "_ensure_tree_sitter_available", return_value=False,
        ) as ensure:
            self.assertEqual(analyzer.analyze_file("Missing.java", root), [])
        ensure.assert_called_once_with()

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", True), patch.object(
            analyzer, "tree_sitter_source_limit_reason", return_value="",
        ), patch.object(analyzer, "TreeSitterAnalyzer") as tree_class:
            parsed = method_def(method_name="parsed")
            tree = tree_class.return_value
            tree.analyze.return_value = [parsed]
            tree.non_empty_source = True
            tree.has_type_declarations = True
            tree.error_nodes = 2
            methods, info = analyzer.analyze_file(
                "Sample.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [parsed])
            self.assertEqual(info["actual_parser"], "tree_sitter")
            self.assertEqual(info["error_nodes"], 2)

            tree.analyze.return_value = []
            tree.non_empty_source = False
            tree.has_type_declarations = False
            del tree.error_nodes
            methods, info = analyzer.analyze_file(
                "Empty.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [])
            self.assertEqual(info["error_nodes"], 0)

            tree.non_empty_source = True
            methods, info = analyzer.analyze_file(
                "package-info.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [])
            self.assertEqual(info["actual_parser"], "tree_sitter")

            tree.has_type_declarations = True
            methods, info = analyzer.analyze_file(
                "Marker.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [])
            self.assertEqual(info["actual_parser"], "tree_sitter")

            tree.has_type_declarations = False
            methods, info = analyzer.analyze_file(
                "Broken.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [])
            self.assertEqual(info["actual_parser"], "skipped")
            self.assertEqual(
                info["fallback_reason"],
                "tree_sitter_runtime_error:RuntimeError",
            )

            tree.analyze.side_effect = ValueError("broken parser")
            methods, info = analyzer.analyze_file(
                "Failure.java", root, return_diagnostics=True,
            )
            self.assertEqual(methods, [])
            self.assertEqual(
                info["fallback_reason"], "tree_sitter_runtime_error:ValueError",
            )

        for suffix in ("kt", "kts"):
            with patch.object(analyzer, "EnhancedRegexAnalyzer") as regex_class:
                regex_class.return_value.analyze.return_value = [method_def()]
                methods, info = analyzer.analyze_file(
                    f"Sample.{suffix}", root, return_diagnostics=True,
                )
            self.assertEqual(len(methods), 1)
            self.assertEqual(info["language"], "kotlin")
            self.assertEqual(info["preferred_parser"], "regex")
            self.assertEqual(
                info["fallback_reason"], "unsupported_language_kotlin",
            )

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", True):
            methods, info = analyzer.analyze_file(
                "Sample.java", root, prefer_tree_sitter=False,
                return_diagnostics=True,
            )
        self.assertEqual(methods, [])
        self.assertEqual(info["actual_parser"], "skipped")
        self.assertEqual(info["fallback_reason"], "prefer_tree_sitter_disabled")

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", False):
            methods, info = analyzer.analyze_file(
                "Sample.java", root, prefer_tree_sitter=False,
                return_diagnostics=True,
            )
        self.assertEqual(methods, [])
        self.assertEqual(info["fallback_reason"], "prefer_tree_sitter_disabled")

        with patch.object(analyzer, "TREE_SITTER_AVAILABLE", True), patch.object(
            analyzer, "tree_sitter_source_limit_reason", return_value="",
        ), patch.object(analyzer, "TreeSitterAnalyzer") as tree_class:
            tree_class.return_value.analyze.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                analyzer.analyze_file("Interrupted.java", root)


class InvocationParsingContractTest(unittest.TestCase):
    def test_string_comment_stripping_removes_every_literal_and_comment_form(self):
        strip = analyzer._strip_strings_and_comments
        cases = {
            "": "",
            "plain.call();": "plain.call();",
            'before(); "hidden.call()" after();': "before();  after();",
            'before(); "escaped \\\" hidden.call()" after();': "before();  after();",
            'before(); "unterminated hidden.call()': "before(); ",
            "before(); 'x' after();": "before();  after();",
            "before(); '\\'' after();": "before();  after();",
            "before(); 'unterminated hidden.call()": "before(); ",
            "before(); /* hidden.call() */ after();": "before();  after();",
            "before(); /* unterminated hidden.call()": "before(); ",
            "before(); // hidden.call()\nafter();": "before(); \nafter();",
            "before(); // hidden.call()": "before(); ",
            "before(); / after();": "before(); / after();",
            "before(); /": "before(); /",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(strip(value), expected)

    def test_regex_call_extractors_cover_resolved_unresolved_and_filtered_edges(self):
        definition = method_def(
            package_name="com.acme",
            imports={"Order": "com.acme.Order"},
            field_types={
                "orders": "java.util.List<com.acme.Order>",
                "fieldWorker": "com.acme.FieldWorker",
                "emptyWorker": "",
            },
            param_types={"paramWorker": "com.acme.ParamWorker"},
            known_type_metadata={
                "com.acme.Sample": {"extends": ["com.acme.Base"]},
            },
        )

        lambda_text = " ".join((
            "orders.stream().map(order -> order.run());",
            "values.stream().map(value -> value.run());",
            "items.stream().map(fieldWorker -> fieldWorker.run());",
            "items.stream().map(paramWorker -> paramWorker.run());",
            "items.stream().map(missing -> missing.run());",
            "items.stream().map(noCall -> noCall + 1);",
            "Stream<Order> stream; stream.filter(item -> item.run());",
            "Stream<Order> unused;",
            "paramOrders.stream().map(paramItem -> paramItem.run());",
        ))
        definition.param_types["paramOrders"] = "java.util.List<com.acme.Order>"
        lambda_edges = analyzer.extract_lambda_calls(lambda_text, definition)
        lambda_projection = {
            (edge.callee_key, edge.confidence) for edge in lambda_edges
        }
        self.assertIn(("com.acme.Order.run", "high"), lambda_projection)
        self.assertIn(("com.acme.FieldWorker.run", "high"), lambda_projection)
        self.assertIn(("com.acme.ParamWorker.run", "high"), lambda_projection)
        self.assertIn(("method:run", "medium"), lambda_projection)
        self.assertEqual(analyzer.extract_lambda_calls("x -> x + 1", definition), [])

        refs = analyzer.extract_method_refs(
            "Order::new fieldWorker::run paramWorker::run "
            "emptyWorker::run Missing::staticCall lower::call",
            definition,
        )
        ref_projection = {
            (edge.callee_key, edge.confidence) for edge in refs
        }
        self.assertIn(("com.acme.Order.new", "high"), ref_projection)
        self.assertIn(("com.acme.FieldWorker.run", "high"), ref_projection)
        self.assertIn(("com.acme.ParamWorker.run", "high"), ref_projection)
        self.assertIn(("com.acme.emptyWorker.run", "high"), ref_projection)
        self.assertIn(("com.acme.Missing.staticCall", "high"), ref_projection)
        self.assertIn(("com.acme.lower.call", "high"), ref_projection)
        self.assertEqual(analyzer.extract_method_refs("no reference", definition), [])
        unresolved_refs = analyzer.extract_method_refs(
            "lower::call Order::run", method_def(package_name=""),
        )
        self.assertEqual(unresolved_refs[0].callee_key, "lower.call")
        self.assertEqual(unresolved_refs[0].confidence, "medium")
        self.assertEqual(unresolved_refs[1].callee_key, "Order.run")
        self.assertEqual(unresolved_refs[1].confidence, "high")

        normal_text = " ".join((
            "Order.staticCall();",
            "super.parent();",
            "fieldWorker.work();",
            "paramWorker.work(\"value\");",
            "missing.work();",
            "missing.work(unknown);",
            "missing.work(,);",
            "missing.invalid(,);",
        ))
        high_only = analyzer.extract_normal_calls_enhanced(
            normal_text, definition, include_low_confidence=False,
        )
        all_edges = analyzer.extract_normal_calls_enhanced(
            normal_text, definition, include_low_confidence=True,
        )
        self.assertTrue(all(edge.confidence == "high" for edge in high_only))
        self.assertGreater(len(all_edges), len(high_only))
        self.assertTrue(any(edge.confidence == "low" for edge in all_edges))
        invalid_edge = next(
            edge for edge in all_edges if "invalid" in edge.callee_key
        )
        self.assertEqual(invalid_edge.callee_key, "method:invalid")
        self.assertEqual(
            analyzer.extract_normal_calls_enhanced(
                "no calls", definition, include_low_confidence=True,
            ),
            [],
        )

        no_parent = method_def(field_types={}, param_types={})
        super_edges = analyzer.extract_normal_calls_enhanced(
            "super.parent();", no_parent, include_low_confidence=True,
        )
        self.assertEqual(super_edges[0].confidence, "low")
        self.assertEqual(super_edges[0].callee_key, "method:parent()")

    def test_call_edge_dispatch_uses_ast_or_cleaned_regex_without_leaking_noise(self):
        empty = method_def(body_text="")
        self.assertEqual(analyzer.extract_call_edges_enhanced(empty), [])
        self.assertEqual(
            analyzer.extract_call_edges_enhanced(method_def(body_text="plain text")),
            [],
        )
        kotlin_ast_metadata = method_def(
            language="kotlin",
            body_text="known.run()",
            ast_call_sites=[{"kind": "method_invocation"}],
            local_var_types={"known": "com.acme.Known"},
        )
        self.assertEqual(
            [edge.callee_key for edge in analyzer.extract_call_edges_enhanced(
                kotlin_ast_metadata,
            )],
            ["com.acme.Known.run()"],
        )

        regex_definition = method_def(
            body_text=(
                '"hidden.call()"; /* ignored.call(); */ '
                "known.run(); missing.run(); Order::new; x -> x.work();"
            ),
            imports={"Order": "com.acme.Order"},
            field_types={"known": "com.acme.Known"},
        )
        high_edges = analyzer.extract_call_edges_enhanced(regex_definition)
        all_edges = analyzer.extract_call_edges_enhanced(
            regex_definition, include_low_confidence=True,
        )
        self.assertTrue(all(edge.confidence != "low" for edge in high_edges))
        self.assertTrue(any(edge.confidence == "low" for edge in all_edges))
        self.assertFalse(any("hidden" in edge.callee_key for edge in all_edges))
        self.assertFalse(any("ignored" in edge.callee_key for edge in all_edges))

        ast_definition = method_def(
            language="java",
            ast_call_sites=[{
                "kind": "method_invocation",
                "method_name": "run",
                "receiver_expr": "known",
                "arg_exprs": [],
                "line": 9,
            }],
            local_var_types={"known": "com.acme.Known"},
        )
        ast_edges = analyzer.extract_call_edges_enhanced(ast_definition)
        self.assertEqual(
            [edge.callee_key for edge in ast_edges],
            ["com.acme.Known.run()"],
        )

    def test_ast_call_edge_matrix_preserves_scope_identity_and_failure_certainty(self):
        definition = method_def(
            class_fqcn="com.acme.Child",
            qualified_key="com.acme.Child.work",
            imports={
                "Order": "com.acme.Order",
                "Outer": "com.acme.Outer",
            },
            static_imports={
                "requireNonNull": "java.util.Objects.requireNonNull",
                "broken": "java.util.Objects.other",
            },
            field_types={"fieldWorker": "com.acme.FieldWorker"},
            param_types={"parameter": "com.acme.Parameter"},
            local_var_types={
                "worker": "com.acme.Worker",
                "Order": "com.acme.LocalOrder",
            },
            known_type_metadata={
                "com.acme.Child": {"extends": ["com.acme.Base"]},
            },
            known_method_return_types_by_signature={
                "com.acme.Worker": {
                    "convert": {"(String, int)": "com.acme.Result"},
                },
            },
            ast_call_sites=[
                {
                    "kind": "constructor_invocation",
                    "method_name": "Order",
                    "receiver_type": "com.acme.Order",
                    "arg_exprs": [],
                    "line": 1,
                },
                {
                    "kind": "constructor_invocation",
                    "method_name": "Recovered",
                    "receiver_type": "",
                    "arg_exprs": ["unknown"],
                    "line": 2,
                },
                {
                    "kind": "constructor_invocation",
                    "method_name": "",
                    "receiver_type": "com.acme.Recovered",
                    "arg_exprs": [],
                    "line": 2,
                },
                {
                    "kind": "constructor_invocation",
                    "method_name": "",
                    "receiver_type": ".",
                    "arg_exprs": [],
                    "line": 2,
                },
                {
                    "kind": "constructor_delegation",
                    "method_name": "this",
                    "receiver_expr": "this",
                    "arg_exprs": [],
                    "line": 3,
                },
                {
                    "kind": "constructor_delegation",
                    "method_name": "super",
                    "receiver_expr": "super",
                    "arg_exprs": [],
                    "line": 4,
                },
                {
                    "kind": "method_reference",
                    "method_name": "run",
                    "receiver_expr": "this",
                    "line": 5,
                },
                {
                    "kind": "method_reference",
                    "method_name": "run",
                    "receiver_expr": "super",
                    "line": 6,
                },
                {
                    "kind": "method_reference",
                    "method_name": "new",
                    "receiver_expr": "Order",
                    "scope_local_var_types": {"Order": "com.acme.LocalOrder"},
                    "line": 7,
                },
                {
                    "kind": "method_reference",
                    "method_name": "staticCall",
                    "receiver_expr": "com.acme.Order",
                    "line": 8,
                },
                {
                    "kind": "method_reference",
                    "method_name": "run",
                    "receiver_expr": "worker",
                    "line": 9,
                },
                {
                    "kind": "method_reference",
                    "method_name": "run",
                    "receiver_expr": "missing",
                    "line": 10,
                },
                {
                    "kind": "method_reference",
                    "method_name": "new",
                    "receiver_expr": "missing",
                    "line": 10,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "requireNonNull",
                    "receiver_expr": "",
                    "arg_exprs": ['"value"'],
                    "line": 11,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "broken",
                    "receiver_expr": "",
                    "arg_exprs": [],
                    "line": 12,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "localCall",
                    "receiver_expr": "",
                    "arg_exprs": [],
                    "line": 13,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "parent",
                    "receiver_expr": "super",
                    "arg_exprs": [],
                    "line": 14,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "outerCall",
                    "receiver_expr": "Outer.this",
                    "arg_exprs": [],
                    "line": 15,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "outerCall",
                    "receiver_expr": ".this",
                    "arg_exprs": [],
                    "line": 15,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "staticCall",
                    "receiver_expr": "Order",
                    "arg_exprs": [],
                    "scope_local_var_types": {},
                    "line": 16,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "work",
                    "receiver_expr": "fieldWorker",
                    "arg_exprs": [],
                    "line": 17,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "convert",
                    "receiver_expr": "worker",
                    "arg_exprs": ['"text"', "unknown"],
                    "line": 18,
                    "content": "x" * 150,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "missing",
                    "receiver_expr": "unknown",
                    "arg_exprs": ["unknown"],
                    "line": None,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "missing",
                    "receiver_expr": "unknown",
                    "arg_exprs": ["unknown"],
                    "line": None,
                },
            ],
        )

        all_edges = analyzer.extract_ast_call_edges(
            definition, include_low_confidence=True,
        )
        high_edges = analyzer.extract_ast_call_edges(
            definition, include_low_confidence=False,
        )
        keys = {edge.callee_key for edge in all_edges}
        self.assertIn("com.acme.Order.Order()", keys)
        self.assertIn("com.acme.Recovered.Recovered()", keys)
        self.assertIn("constructor:unknown()", keys)
        self.assertIn("com.acme.Child.Child()", keys)
        self.assertIn("com.acme.Base.Base()", keys)
        self.assertIn("com.acme.Child.run", keys)
        self.assertIn("com.acme.Base.run", keys)
        self.assertIn("com.acme.LocalOrder.LocalOrder", keys)
        self.assertIn("com.acme.Order.staticCall", keys)
        self.assertIn("com.acme.Worker.run", keys)
        self.assertIn("java.util.Objects.requireNonNull(String)", keys)
        self.assertIn("com.acme.Child.broken()", keys)
        self.assertIn("com.acme.Child.localCall()", keys)
        self.assertIn("com.acme.Base.parent()", keys)
        self.assertIn("com.acme.Outer.outerCall()", keys)
        self.assertIn("com.acme.FieldWorker.work()", keys)
        self.assertIn("com.acme.Worker.convert(String, int)", keys)
        self.assertIn("method:missing", keys)
        self.assertEqual(
            sum(edge.callee_key == "method:missing" for edge in all_edges), 1,
        )
        self.assertTrue(any(edge.confidence == "low" for edge in all_edges))
        self.assertTrue(all(edge.confidence != "low" for edge in high_edges))
        convert = next(edge for edge in all_edges if ".convert" in edge.callee_key)
        self.assertEqual(len(convert.content), 100)
        missing = next(edge for edge in all_edges if edge.callee_key == "method:missing")
        self.assertEqual(missing.line, definition.line)

        no_parent = method_def(
            class_fqcn="com.acme.Orphan",
            ast_call_sites=[
                {
                    "kind": "constructor_delegation",
                    "receiver_expr": "super",
                    "line": 1,
                },
                {
                    "kind": "method_reference",
                    "method_name": "run",
                    "receiver_expr": "super",
                    "line": 2,
                },
                {
                    "kind": "method_invocation",
                    "method_name": "run",
                    "receiver_expr": "super",
                    "arg_exprs": [],
                    "line": 3,
                },
            ],
        )
        orphan_edges = analyzer.extract_ast_call_edges(
            no_parent, include_low_confidence=True,
        )
        self.assertEqual(
            {edge.confidence for edge in orphan_edges}, {"medium"},
        )

    def test_java_argument_splitter_preserves_nested_lexical_structures(self):
        split = analyzer.split_java_argument_expressions
        cases = {
            "": [],
            '"last, first"': ['"last, first"'],
            "nested(1, 2), value": ["nested(1, 2)", "value"],
            "values[index, other], value": ["values[index, other]", "value"],
            "new Pair<String, Order>(), value": [
                "new Pair<String, Order>()", "value",
            ],
            "factory.<String, Order>create(), value": [
                "factory.<String, Order>create()", "value",
            ],
            "'\\'', value": ["'\\''", "value"],
            '"""a,b""", value': ['"""a,b"""', "value"],
            "first /* comma, ignored */, second": [
                "first /* comma, ignored */", "second",
            ],
            "first // comma, ignored\n, second": [
                "first // comma, ignored", "second",
            ],
            "a < b, c > d": ["a < b", "c > d"],
            "1 < 2, 3": ["1 < 2", "3"],
            "first /* closed */, second": ["first /* closed */", "second"],
            "first /* * still-comment */, second": [
                "first /* * still-comment */", "second",
            ],
            "first // closed\r, second": ["first // closed", "second"],
            "left / right, second": ["left / right", "second"],
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(split(value), expected)

        for malformed in (
            ",value", "value,", "value,,other", "nested(value",
            "values[index", '"unterminated', "/* unterminated",
            "new Pair<String, Order()",
            ")", "([)]", "first, /* unterminated", "first, Type<Value",
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(split(malformed))

    def test_low_confidence_calls_are_opt_in_for_ast_and_regex_paths(self):
        regex_definition = method_def(
            body_text="missing.invoke(unknown);",
        )
        self.assertEqual(
            analyzer.extract_call_edges_enhanced(
                regex_definition, include_low_confidence=False,
            ),
            [],
        )
        regex_edges = analyzer.extract_call_edges_enhanced(
            regex_definition, include_low_confidence=True,
        )
        self.assertEqual(len(regex_edges), 1)
        self.assertEqual(regex_edges[0].confidence, "low")

        ast_definition = method_def(
            body_text="Order.invoke();",
            imports={"Order": "com.acme.model.Order"},
            ast_call_sites=[{
                "kind": "method_invocation",
                "method_name": "invoke",
                "receiver_expr": "missing",
                "arg_exprs": ["unknown"],
                "line": 7,
                "content": "missing.invoke(unknown)",
            }],
        )
        self.assertEqual(
            analyzer.extract_call_edges_enhanced(
                ast_definition, include_low_confidence=False,
            ),
            [],
        )
        ast_edges = analyzer.extract_call_edges_enhanced(
            ast_definition, include_low_confidence=True,
        )
        self.assertEqual(len(ast_edges), 1)
        self.assertEqual(ast_edges[0].confidence, "low")

    def test_trailing_call_parser_handles_nested_receivers_and_rejects_non_calls(self):
        self.assertEqual(
            analyzer.split_trailing_method_call(" service.client().send(one, nested(two)) "),
            {"receiver": "service.client()", "method": "send", "args": "one, nested(two)"},
        )
        self.assertEqual(
            analyzer.split_trailing_method_call("((service)).send()"),
            {"receiver": "((service))", "method": "send", "args": ""},
        )
        self.assertEqual(
            analyzer.split_trailing_method_call("receiver . method_name ()"),
            {"receiver": "receiver", "method": "method_name", "args": ""},
        )
        strip_cases = {
            None: "",
            "plain": "plain",
            "(plain)": "plain",
            "((plain))": "plain",
            "(left)(right)": "(left)(right)",
            "((incomplete)": "((incomplete)",
        }
        for expression, expected in strip_cases.items():
            with self.subTest(parenthesized=expression):
                self.assertEqual(
                    analyzer._strip_balanced_outer_parens(expression), expected,
                )
        for value in (
            "", "service", "send()", ".send()", "service.send(", ")", "()", ".()",
            "   ()",
        ):
            self.assertIsNone(analyzer.split_trailing_method_call(value))

    def test_partial_signature_resolution_requires_one_compatible_overload(self):
        definition = method_def(
            local_method_return_types={
                "convert": {
                    "(String, int)": "A",
                    "(String, long)": "B",
                    "malformed": "ignored",
                    "": "ignored",
                    None: "ignored",
                    7: "ignored",
                },
            },
            known_method_return_types_by_signature={
                "com.acme.Other": {
                    "convert": {
                        "(String)": "C",
                        "(String[])": "D",
                    },
                },
            },
        )
        self.assertEqual(analyzer._normalize_type_hint("java.lang.String..."), "String[]")
        self.assertEqual(analyzer._normalize_type_hint("List<Order>"), "List")
        self.assertEqual(
            analyzer._collect_candidate_signatures_for_receiver(
                "com.acme.Sample", "convert", definition,
            ),
            {"(String, int)", "(String, long)", "malformed"},
        )
        self.assertEqual(
            analyzer.resolve_invocation_signature_from_partial_hints(
                "com.acme.Sample", "convert", ["String", "int"], definition,
            ),
            "(String, int)",
        )
        self.assertEqual(
            analyzer.resolve_invocation_signature_from_partial_hints(
                "com.acme.Other", "convert", ["java.lang.String"], definition,
            ),
            "(String)",
        )
        self.assertEqual(
            analyzer.resolve_invocation_signature_from_partial_hints(
                "com.acme.Other", "convert", ["java.lang.String..."], definition,
            ),
            "(String[])",
        )
        self.assertEqual(
            analyzer.resolve_invocation_signature_from_partial_hints(
                "com.acme.Sample", "convert", ["String", ""], definition,
            ),
            "",
        )
        for receiver, method, hints in (
            ("", "convert", ["String"]),
            ("com.acme.Sample", "", ["String"]),
            ("com.acme.Sample", "convert", None),
            ("com.acme.Sample", "convert", []),
            ("com.acme.Sample", "convert", [""]),
            ("com.acme.Missing", "convert", ["String"]),
            ("com.acme.Sample", "convert", ["int"]),
            ("com.acme.Sample", "convert", ["String", "boolean"]),
        ):
            with self.subTest(receiver=receiver, method=method, hints=hints):
                self.assertEqual(
                    analyzer.resolve_invocation_signature_from_partial_hints(
                        receiver, method, hints, definition,
                    ),
                    "",
                )

    def test_partial_signature_resolution_ignores_malformed_metadata(self):
        malformed_definitions = (
            method_def(local_method_return_types={"convert": None}),
            method_def(local_method_return_types={"convert": []}),
            method_def(local_method_return_types=[]),
            method_def(known_method_return_types_by_signature={"Owner": []}),
            method_def(
                known_method_return_types_by_signature={
                    "Owner": {"convert": None},
                },
            ),
            method_def(known_method_return_types_by_signature=[]),
        )
        for definition in malformed_definitions:
            with self.subTest(definition=definition):
                self.assertEqual(
                    analyzer._collect_candidate_signatures_for_receiver(
                        definition.class_fqcn, "convert", definition,
                    ),
                    set(),
                )
                self.assertEqual(
                    analyzer._collect_candidate_signatures_for_receiver(
                        "Owner", "convert", definition,
                    ),
                    set(),
                )
                self.assertEqual(
                    analyzer.resolve_invocation_signature_from_partial_hints(
                        "Owner", "convert", ["String"], definition,
                    ),
                    "",
                )
        self.assertEqual(
            analyzer.resolve_invocation_signature_from_partial_hints(
                "", "convert", ["String"], definition,
            ),
            "",
        )

    def test_regex_calls_method_references_and_lambda_context_keep_resolved_owners(self):
        definition = method_def(
            imports={"Order": "com.acme.model.Order"},
            field_types={
                "orders": "java.util.List<com.acme.model.Order>",
                "worker": "com.acme.Worker",
            },
            known_type_metadata={
                "com.acme.Sample": {"extends": ["com.acme.Base"]},
            },
        )

        normal = analyzer.extract_normal_calls_enhanced(
            "super.parent(); Order.staticCall();",
            definition,
            include_low_confidence=False,
        )
        self.assertEqual(
            {edge.callee_key for edge in normal},
            {"com.acme.Base.parent()", "com.acme.model.Order.staticCall()"},
        )
        references = analyzer.extract_method_refs(
            "Order::new worker::run", definition,
        )
        self.assertEqual(
            {edge.callee_key for edge in references},
            {"com.acme.model.Order.new", "com.acme.Worker.run"},
        )
        self.assertEqual(
            analyzer.infer_lambda_parameter_type_from_context(
                "orders.stream().map(order -> order.toString())",
                definition,
            ),
            {"order": "com.acme.model.Order"},
        )
        self.assertEqual(
            analyzer.infer_lambda_parameter_type_from_context(
                "Stream<Order> stream; stream.filter(item -> item.run())",
                definition,
            ),
            {"item": "com.acme.model.Order"},
        )
        no_generic = method_def(field_types={"items": "java.util.List"})
        self.assertEqual(
            analyzer.infer_lambda_parameter_type_from_context(
                "items.stream().map(item -> item.run())",
                no_generic,
            ),
            {},
        )

        spread = FakeNode(
            "spread_parameter",
            "@Marker String... values",
            children=[
                FakeNode("modifiers", "@Marker"),
                FakeNode("type_identifier", "String"),
                FakeNode("...", "..."),
                FakeNode("variable_declarator", fields={
                    "name": FakeNode("identifier", "values"),
                }),
            ],
        )
        params = FakeNode("formal_parameters", children=[spread])
        tree = tree_analyzer_without_parser()
        self.assertEqual(
            tree._parse_params(params, b""),
            (
                {"values": "java.lang.String[]"},
                {"values": "String..."},
            ),
        )


class RegexFallbackContractTest(unittest.TestCase):
    SOURCE_ROOT = {
        "root": "src/main/java",
        "owner_type": "business",
        "owner_coord": "BUSINESS",
        "module": "sample",
    }

    def test_java_regex_analyzer_preserves_structure_and_ignores_comments(self):
        source = """package com.acme;
import java.util.List;
import static java.util.Objects.requireNonNull;
/* class Phantom { void hidden() {} } */
@Deprecated
public class Sample {
  private List<String> names;
  // void commented() {}
  @Override
  public static String greet(final String name, int... counts) throws java.io.IOException {
    return requireNonNull(name);
  }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "src" / "main" / "java" / "Sample.java"
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            regex = analyzer.EnhancedRegexAnalyzer(str(path), self.SOURCE_ROOT)
            methods = regex.analyze()

        self.assertEqual([item.method_name for item in methods], ["greet"])
        method = methods[0]
        self.assertEqual(method.class_fqcn, "com.acme.Sample")
        self.assertEqual(method.return_type, "java.lang.String")
        self.assertEqual(method.param_types, {
            "name": "java.lang.String",
            "counts": "int[]",
        })
        self.assertEqual(method.field_types["names"], "java.util.List")
        self.assertEqual(method.static_imports["requireNonNull"], "java.util.Objects.requireNonNull")
        self.assertEqual(method.annotations, ["Override"])
        self.assertIn("static", method.modifiers)
        self.assertEqual(method.class_annotations, ["Deprecated"])
        self.assertIn("requireNonNull(name)", method.get_body_text())

        self.assertEqual(regex._extract_annotations("@a.b.Valid @Nullable String x"), ["Valid", "Nullable"])
        self.assertEqual(regex._extract_annotations_multiline(["@One\n", "@Two\n", "void x() {}\n"], 2), ["One", "Two"])
        self.assertEqual(regex._extract_modifiers("public static final void x()"), ["public", "static", "final"])

    def test_kotlin_regex_analyzer_handles_aliases_nullable_and_expression_body(self):
        source = """package com.acme
import com.example.Customer as Buyer
import com.example.shared.*
class Checkout {
  fun total(customer: Buyer?, vararg counts: Int): String = customer.toString()
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "src" / "integrationTest" / "kotlin" / "Checkout.kt"
            path.parent.mkdir(parents=True)
            path.write_text(source, encoding="utf-8")
            regex = analyzer.EnhancedRegexAnalyzer(str(path), self.SOURCE_ROOT)
            methods = regex.analyze()

        self.assertEqual(len(methods), 1)
        method = methods[0]
        self.assertEqual(method.language, "kotlin")
        self.assertTrue(method.is_test)
        self.assertEqual(method.imports["Buyer"], "com.example.Customer")
        self.assertEqual(method.wildcard_imports, ["com.example.shared"])
        self.assertEqual(method.param_types["customer"], "com.example.Customer")
        self.assertEqual(method.param_types["counts"], "int")

    def test_regex_analyzer_read_failure_is_an_explicit_empty_result(self):
        missing = analyzer.EnhancedRegexAnalyzer("does-not-exist.java", self.SOURCE_ROOT)
        self.assertEqual(missing.analyze(), [])

    def test_regex_lexical_import_and_type_helpers_cover_boundary_grammar(self):
        regex = analyzer.EnhancedRegexAnalyzer("Sample.java", self.SOURCE_ROOT)
        sanitized = regex._sanitize_structure_lines([
            "code /* open\n",
            "still * not-close */ tail\n",
            'String text = "escaped \\" // literal"; // actual\n',
            "char quote = '\\''; /* removed */\n",
            "char plain = 'x'; value / divisor;\n",
            "// comment without newline",
            '"unfinished\\',
            "'unfinished\\",
            "\n",
        ])
        self.assertEqual(len(sanitized), 9)
        self.assertNotIn("open", sanitized[0])
        self.assertIn("tail", sanitized[1])
        self.assertIn('// literal"', sanitized[2])
        self.assertNotIn("actual", sanitized[2])
        self.assertIn("'\\''", sanitized[3])
        self.assertNotIn("removed", sanitized[3])
        self.assertIn("value / divisor", sanitized[4])
        self.assertEqual(sanitized[5].strip(), "")

        self.assertEqual(regex._detect_package([]), "")
        self.assertEqual(regex._detect_package(["noise\n"]), "")
        self.assertEqual(
            regex._detect_package(["noise\n", "package com.acme;\n"]),
            "com.acme",
        )
        imports, static_imports, wildcards = regex._detect_imports([
            "noise\n",
            "import java.util.List;\n",
            "import java.util.*;\n",
            "import static java.util.Objects.requireNonNull;\n",
        ])
        self.assertEqual(imports, {"List": "java.util.List"})
        self.assertEqual(
            static_imports,
            {"requireNonNull": "java.util.Objects.requireNonNull"},
        )
        self.assertEqual(wildcards, ["java.util"])

        kotlin = analyzer.EnhancedRegexAnalyzer("Sample.kt", self.SOURCE_ROOT)
        self.assertEqual(
            kotlin._detect_package(["noise\n", "package com.kotlin\n"]),
            "com.kotlin",
        )
        imports, static_imports, wildcards = kotlin._detect_imports([
            "import com.example.Customer as Buyer\n",
            "import com.example.Order\n",
            "import com.example.shared.*\n",
            "not an import\n",
        ])
        self.assertEqual(imports, {
            "Buyer": "com.example.Customer",
            "Order": "com.example.Order",
        })
        self.assertEqual(static_imports, {})
        self.assertEqual(wildcards, ["com.example.shared"])

        regex.package_name = "com.acme"
        regex.imports = {"Order": "lib.Order"}
        regex.wildcard_imports = ["", "shared.types"]
        regex.class_stack = [{"name": "Outer", "fqcn": "com.acme.Outer"}]
        type_cases = {
            None: "",
            "": "",
            "final": "",
            "int": "int",
            "long[][]": "long[][]",
            "Order...": "lib.Order[]",
            "List<Order>": "shared.types.List",
            "<Order>": "",
            "Outer.Inner": "com.acme.Outer.Inner",
            "Other.Inner": "Other.Inner",
            "a.b.C": "a.b.C",
            "Order": "lib.Order",
            "Set": "shared.types.Set",
            "String": "shared.types.String",
            "Missing": "shared.types.Missing",
        }
        for value, expected in type_cases.items():
            with self.subTest(type=value):
                self.assertEqual(regex._resolve_type(value), expected)

        regex.wildcard_imports = []
        self.assertEqual(regex._resolve_simple_type("List"), "java.util.List")
        self.assertEqual(regex._resolve_simple_type("String"), "java.lang.String")
        self.assertEqual(regex._resolve_simple_type("Missing"), "com.acme.Missing")
        regex.package_name = ""
        self.assertEqual(regex._resolve_simple_type("Missing"), "Missing")
        self.assertEqual(regex._resolve_simple_type(""), "")
        self.assertEqual(kotlin._resolve_simple_type("Int"), "int")
        self.assertEqual(kotlin._resolve_simple_type("String"), "java.lang.String")

    def test_regex_parameter_return_field_and_method_matrices_are_exact(self):
        regex = analyzer.EnhancedRegexAnalyzer("Sample.java", self.SOURCE_ROOT)
        regex.package_name = "com.acme"
        regex.imports = {"Order": "lib.Order"}
        regex.wildcard_imports = []

        self.assertEqual(regex._extract_return_type("public Sample() {", "Sample"), "")
        self.assertEqual(regex._extract_return_type("public Sample() {", ""), "")
        self.assertEqual(
            regex._extract_return_type("public List<Order> values() {", "values"),
            "List<Order>",
        )
        self.assertEqual(
            regex._extract_return_type("public Order value() {", "value"),
            "lib.Order",
        )
        self.assertEqual(
            regex._extract_return_type("Order unrelated", "missing"),
            "",
        )

        java_params = {
            None: {},
            "": {},
            "   ": {},
            "broken": {},
            ",": {},
            "final Order order": {"order": "lib.Order"},
            "@Mark Order first, String... names": {
                "first": "lib.Order", "names": "java.lang.String[]",
            },
            "final value": {},
        }
        for value, expected in java_params.items():
            with self.subTest(java_params=value):
                self.assertEqual(regex._extract_param_types(value), expected)

        kotlin = analyzer.EnhancedRegexAnalyzer("Sample.kt", self.SOURCE_ROOT)
        kotlin.imports = {"Buyer": "com.example.Customer"}
        kotlin_params = {
            "invalid": {},
            ": String": {},
            "name:": {},
            "crossinline block: String = default, vararg buyer: Buyer?": {
                "block": "java.lang.String",
                "buyer": "com.example.Customer",
            },
        }
        for value, expected in kotlin_params.items():
            with self.subTest(kotlin_params=value):
                self.assertEqual(kotlin._extract_param_types(value), expected)

        field_lines = [
            "\n",
            "// ignored\n",
            "/* ignored */\n",
            "return local;\n",
            "@Inject\n",
            "\n",
            "private\n",
            "Order multiline;\n",
            "private String names[];\n",
            "private Order existing;\n",
            "public Sample() {}\n",
            "broken )\n",
            "public Sample(, lone, final value, final Order order, transient Order existing) {}\n",
        ]
        regex._scan_fields(field_lines)
        self.assertEqual(regex.field_types["multiline"], "lib.Order")
        self.assertEqual(regex.field_types["names"], "java.lang.String[]")
        self.assertEqual(regex.field_types["existing"], "lib.Order")
        self.assertEqual(regex.field_types["order"], "lib.Order")

        method_lines = [
            "void outside() {}\n",
            "\n",
            "// comment\n",
            "/* comment */\n",
            "@Marker\n",
            "public interface Contract {\n",
            "  String abstractName();\n",
            "}\n",
            "public class Outer {\n",
            "  public Outer() {}\n",
            "  public String one() { return \"one\"; }\n",
            "  public String multi() throws java.io.IOException, RuntimeException {\n",
            "    if (true) { return \"many\"; }\n",
            "  }\n",
            "  public void blanks() throws java.io.IOException, , RuntimeException {}\n",
            "  class Inner {\n",
            "    void nested() {}\n",
            "  }\n",
            "}\n",
            "class Joined {\n",
            "  class Nested {\n",
            "    void joined() {}\n",
            "}}\n",
            "class Empty {}\n",
        ]
        sanitized = regex._sanitize_structure_lines(method_lines)
        regex._scan_class_structure(sanitized)
        methods = regex._extract_methods(sanitized, original_lines=method_lines)
        by_key = {item.qualified_key: item for item in methods}
        self.assertEqual(set(by_key), {
            "com.acme.Contract.abstractName",
            "com.acme.Outer.Outer",
            "com.acme.Outer.one",
            "com.acme.Outer.multi",
            "com.acme.Outer.blanks",
            "com.acme.Outer.Inner.nested",
            "com.acme.Joined.Nested.joined",
        })
        self.assertTrue(by_key["com.acme.Contract.abstractName"].is_interface)
        self.assertEqual(
            by_key["com.acme.Outer.multi"].throws_declared_types,
            ["java.io.IOException", "RuntimeException"],
        )
        self.assertEqual(
            by_key["com.acme.Outer.blanks"].throws_declared_types,
            ["java.io.IOException", "RuntimeException"],
        )
        self.assertIn("return \"many\"", by_key["com.acme.Outer.multi"].get_body_text())
        self.assertEqual(by_key["com.acme.Outer.Outer"].return_type, "")

        regex._scan_class_structure([])
        self.assertEqual(regex._extract_methods([], original_lines=[]), [])

        raw_lines = [
            "// raw comment\n",
            "/* raw block */\n",
            "void outside() {}\n",
            "class Bare {\n",
            "  void open() {\n",
        ]
        regex.package_name = ""
        regex._scan_class_structure(raw_lines)
        unterminated = regex._extract_methods(raw_lines)
        self.assertEqual([item.qualified_key for item in unterminated], ["Bare.open"])

        annotation_lines = ["@123 invalid\n", "void method() {}\n"]
        self.assertEqual(regex._extract_leading_annotations(annotation_lines, 1), [])
        regex._scan_class_structure([
            "// comment\n", "/* comment */\n", "plain text\n",
        ])
        self.assertEqual(regex.class_at_line, {})

    def test_method_body_lazy_loading_preserves_cache_lines_files_and_errors(self):
        cached = method_def(_body_text_cached="cached")
        self.assertEqual(cached.body_text_lazy, "cached")
        self.assertEqual(cached._body_text_read_error, "")

        lines = method_def(_body_lines=("line one\n", "line two\n"))
        self.assertEqual(lines.body_text_lazy, "line one\nline two\n")
        self.assertEqual(lines._body_lines, ())
        self.assertEqual(lines.body_text_lazy, "line one\nline two\n")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_text("zero\none\ntwo\nthree\n", encoding="utf-8")
            from_file = method_def(file=str(source), line=2, end_line=3)
            self.assertEqual(from_file.body_text_lazy, "one\ntwo\n")

        missing = method_def(file="does-not-exist.java", line=1, end_line=1)
        self.assertEqual(missing.body_text_lazy, "")
        self.assertIn("FileNotFoundError", missing._body_text_read_error)
        explicit = method_def(body_text="explicit")
        self.assertEqual(explicit.get_body_text(), "explicit")

        with patch("builtins.open", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                method_def(file="interrupt.java").body_text_lazy

        interrupted = analyzer.EnhancedRegexAnalyzer("interrupt.java", self.SOURCE_ROOT)
        with patch("builtins.open", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                interrupted.analyze()


class TypeResolutionContractTest(unittest.TestCase):
    def setUp(self):
        self.definition = method_def(
            imports={"Order": "com.acme.model.Order", "val": "lombok.val"},
            wildcard_imports=["com.acme.shared"],
            field_types={"repository": "com.acme.Repository", "orders": "java.util.List<Order>"},
            field_declared_types={"orders": "List<Order>", "customer": "Customer"},
            param_types={"input": "com.acme.Input", "mapping": "java.util.Map"},
            param_declared_types={"input": "Input", "mapping": "Map<String, Order>"},
            known_class_fqcns={"com.acme.Customer", "com.acme.shared.Shared"},
            known_classes_by_simple={"Unique": ["other.Unique"]},
        )

    def test_type_resolution_uses_deterministic_precedence(self):
        resolve = lambda value: analyzer.resolve_type_fqn(value, self.definition)
        self.assertEqual(resolve("Sample"), "com.acme.Sample")
        self.assertEqual(resolve("Sample.Inner"), "com.acme.Sample.Inner")
        self.assertEqual(resolve("String"), "java.lang.String")
        self.assertEqual(resolve("List"), "java.util.List")
        self.assertEqual(resolve("Order"), "com.acme.model.Order")
        self.assertEqual(resolve("Order.Line"), "com.acme.model.Order.Line")
        self.assertEqual(resolve("Customer"), "com.acme.Customer")
        self.assertEqual(resolve("Shared"), "com.acme.shared.Shared")
        self.assertEqual(resolve("Unique"), "other.Unique")
        self.assertEqual(resolve("Repository"), "com.acme.Repository")
        self.assertEqual(resolve("Missing"), "com.acme.Missing")
        self.assertEqual(resolve(""), "")

        wildcard_without_inventory = method_def(
            package_name="",
            wildcard_imports=["", "fallback.types"],
            known_class_fqcns=set(),
        )
        self.assertEqual(
            analyzer.resolve_type_fqn("Wildcard", wildcard_without_inventory),
            "fallback.types.Wildcard",
        )
        exact_param = method_def(
            package_name="",
            field_types={"other": "Other"},
            param_types={"exact": "Exact"},
        )
        self.assertEqual(analyzer.resolve_type_fqn("Exact", exact_param), "Exact")
        later_exact_param = method_def(
            package_name="",
            field_types={},
            param_types={"other": "Other", "exact": "Exact"},
        )
        self.assertEqual(
            analyzer.resolve_type_fqn("Exact", later_exact_param),
            "Exact",
        )
        qualified_param = method_def(
            package_name="",
            field_types={},
            param_types={"qualified": "other.Exact"},
        )
        self.assertEqual(
            analyzer.resolve_type_fqn("Exact", qualified_param),
            "other.Exact",
        )

        self.assertTrue(analyzer._is_inferred_local_decl_type("var", self.definition))
        self.assertTrue(analyzer._is_inferred_local_decl_type("val", self.definition))
        self.assertFalse(analyzer._is_inferred_local_decl_type("Order", self.definition))
        self.definition.known_type_metadata = {
            "com.acme.Sample": {"extends": ["com.acme.Base"]},
        }
        self.assertEqual(analyzer._resolve_super_type(self.definition), "com.acme.Base")

    def test_signature_type_and_inheritance_helpers_cover_invalid_boundaries(self):
        signature_cases = (
            (None, None, "()"),
            ([], ["ignored"], "()"),
            (["value"], None, ""),
            (["value"], [], ""),
            (["value"], [None], ""),
            (["value"], [""], ""),
            (["left", "right"], [None, "String"], ""),
            (["left", "right"], ["String", None], ""),
            (["first", "second", "third"], ["String", "int", ""], ""),
            (["first", "second", "third"], [None, "int", "String"], ""),
            (["left", "right"], ["String", "int"], "(String, int)"),
            (["value"], [" String "], "( String )"),
        )
        for args, inferred, expected in signature_cases:
            with self.subTest(args=args, inferred=inferred):
                self.assertEqual(
                    analyzer.build_invocation_signature(args, inferred), expected,
                )

        normalized_cases = {
            None: "()",
            (): "()",
            (None, "", "  "): "()",
            ("java.lang.String",): "(String)",
            ("java.util.List<Order>", "Order..."): "(List, Order[])",
            ("Map<String, List<Order>>",): "(Map)",
            (0, "String"): "(String)",
            ("", "String"): "(String)",
            ("String", ""): "(String)",
        }
        for values, expected in normalized_cases.items():
            with self.subTest(values=values):
                self.assertEqual(
                    analyzer._build_signature_from_param_values(values), expected,
                )

        inferred_decl_cases = (
            (None, self.definition, False),
            ("", self.definition, False),
            ("var", self.definition, True),
            ("val", self.definition, True),
            ("lombok.val", self.definition, True),
            ("Order", self.definition, False),
            ("Order", method_def(), False),
            ("Missing", self.definition, False),
            ("Alias", method_def(imports={"Alias": "other.Type"}), False),
            ("Alias", method_def(imports={"Alias": "lombok.val"}), True),
        )
        for declared, definition, expected in inferred_decl_cases:
            with self.subTest(declared=declared, imports=definition.imports):
                self.assertEqual(
                    analyzer._is_inferred_local_decl_type(declared, definition),
                    expected,
                )

        super_cases = (
            (method_def(), None),
            (method_def(known_type_metadata=[]), None),
            (method_def(known_type_metadata=["invalid"]), None),
            (method_def(known_type_metadata={"com.acme.Sample": []}), None),
            (method_def(known_type_metadata={"com.acme.Sample": ["invalid"]}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": []}}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": ""}}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": "com.acme.Base"}}), "com.acme.Base"),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": ["com.acme.Base"]}}), "com.acme.Base"),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": [""]}}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": [17]}}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": ["com.acme.Base", "com.acme.Other"]}}), None),
            (method_def(known_type_metadata={"com.acme.Sample": {"extends": 17}}), None),
        )
        for definition, expected in super_cases:
            with self.subTest(metadata=getattr(definition, "known_type_metadata", None)):
                self.assertEqual(analyzer._resolve_super_type(definition), expected)

    def test_receiver_inference_respects_scope_static_fields_and_shadowed_roots(self):
        definition = method_def(
            imports={
                "Constants": "com.acme.Constants",
                "Factory": "com.acme.Factory",
                "Order": "com.acme.Order",
            },
            field_types={
                "factory": "com.acme.Factory",
                "field": "com.acme.Repository",
                "FieldOwner": "com.acme.FieldValue",
            },
            param_types={
                "parameter": "com.acme.Parameter",
                "ParamOwner": "com.acme.ParamValue",
            },
            local_var_types={"cached": "com.acme.Cached"},
            local_method_return_types={
                "create": {"()": "com.acme.Factory"},
            },
            known_method_return_types_by_signature={
                "com.acme.Factory": {
                    "create": {"()": "com.acme.Order"},
                },
            },
            known_field_types={
                "com.acme.Constants": {"ORDER": "com.acme.Order"},
            },
            known_type_metadata={
                "com.acme.Sample": {"extends": ["com.acme.Base"]},
            },
        )
        locals_ = {
            "local": "com.acme.Local",
            "LocalOwner": "com.acme.LocalValue",
        }
        infer = lambda expression, scope=locals_: (
            analyzer.infer_receiver_type_enhanced(
                expression, definition, scope,
            )
        )

        expected = {
            None: None,
            "": None,
            "this": "com.acme.Sample",
            "super": "com.acme.Base",
            "new Order()": "com.acme.Order",
            "((new Order()))": "com.acme.Order",
            "this.field": "com.acme.Repository",
            "super.field": "com.acme.Repository",
            "local": "com.acme.Local",
            "field": "com.acme.Repository",
            "parameter": "com.acme.Parameter",
            "java.util.List": "java.util.List",
            "local.value": "com.acme.Local",
            "field.value": "com.acme.Repository",
            "parameter.value": "com.acme.Parameter",
            "LocalOwner.VALUE": "com.acme.LocalValue",
            "FieldOwner.VALUE": "com.acme.FieldValue",
            "ParamOwner.VALUE": "com.acme.ParamValue",
            "missing.value": None,
            "create()": "com.acme.Factory",
            "factory.create()": "com.acme.Order",
            "Constants.ORDER": "com.acme.Order",
            "unknown()": None,
        }
        for expression, expected_type in expected.items():
            with self.subTest(expression=expression):
                self.assertEqual(infer(expression), expected_type)

        self.assertEqual(infer("cached", None), "com.acme.Cached")
        self.assertIsNone(infer("cached", {}))

        static = analyzer._looks_like_static_receiver_expr
        static_cases = {
            None: False,
            "": False,
            "this": False,
            "super": False,
            "class": False,
            "Factory()": False,
            "lowercase": False,
            "pkg.lowercase": False,
            "Order": True,
            "java.util.List": True,
            "local.Type": False,
            "field.Type": False,
            "parameter.Type": False,
        }
        for expression, expected_static in static_cases.items():
            with self.subTest(static_expression=expression):
                self.assertEqual(
                    static(expression, definition, locals_), expected_static,
                )

    def test_return_type_resolution_handles_overloads_and_inheritance(self):
        self.definition.local_method_return_types = {
            "build": {"(String)": "com.acme.TextResult", "(int)": "com.acme.NumberResult"},
            "same": {"(String)": "com.acme.Result", "(int)": "com.acme.Result"},
        }
        self.definition.known_method_return_types_by_signature = {
            "com.acme.Parent": {"load": {"(String)": "com.acme.Order"}},
        }
        self.definition.known_method_return_types = {
            "com.acme.Legacy": {"read": "java.lang.String"},
        }
        self.definition.known_type_metadata = {
            "com.acme.Sample": {"extends": ["com.acme.Middle"]},
            "com.acme.Middle": {"implements": ["com.acme.Parent"]},
        }

        infer = lambda receiver, name, signature="": analyzer.infer_invocation_return_type(
            receiver, name, self.definition, signature,
        )
        self.assertEqual(infer("com.acme.Sample", "build", "(String)"), "com.acme.TextResult")
        self.assertIsNone(infer("com.acme.Sample", "build"))
        self.assertEqual(infer("com.acme.Sample", "same"), "com.acme.Result")
        self.assertEqual(infer("com.acme.Legacy", "read"), "java.lang.String")
        self.assertEqual(infer("com.acme.Sample", "load", "(String)"), "com.acme.Order")
        self.assertIsNone(infer("com.acme.Sample", "missing"))
        self.assertIsNone(infer("com.acme.Sample", ""))
        self.assertEqual(
            analyzer.infer_receiver_type_enhanced("super", self.definition),
            "com.acme.Middle",
        )
        self.definition.local_method_return_types["factory"] = {
            "()": "com.acme.Factory",
        }
        self.assertEqual(
            analyzer.infer_receiver_type_enhanced("this.factory()", self.definition),
            "com.acme.Factory",
        )

    def test_return_type_resolution_never_falls_through_local_or_interface_ambiguity(self):
        definition = method_def(
            class_fqcn="com.acme.Child",
            local_method_return_types={
                "choose": {
                    "(String)": "com.acme.TextResult",
                    "(int)": "com.acme.NumberResult",
                },
            },
            known_method_return_types_by_signature={
                "com.acme.Parent": {
                    "choose": {"(Object)": "com.acme.ParentResult"},
                },
                "com.acme.Left": {
                    "resolve": {"(String)": "com.acme.LeftResult"},
                },
                "com.acme.Right": {
                    "resolve": {"(String)": "com.acme.RightResult"},
                },
                "com.acme.SameLeft": {
                    "resolve": {"(String)": "com.acme.SharedResult"},
                },
                "com.acme.SameRight": {
                    "resolve": {"(String)": "com.acme.SharedResult"},
                },
            },
            known_type_metadata={
                "com.acme.Child": {"extends": ["com.acme.Parent"]},
                "com.acme.Conflict": {
                    "implements": ["com.acme.Left", "com.acme.Right"],
                },
                "com.acme.ReversedConflict": {
                    "implements": ["com.acme.Right", "com.acme.Left"],
                },
                "com.acme.Same": {
                    "implements": [
                        "com.acme.SameLeft", "com.acme.SameRight",
                    ],
                },
                "com.acme.CycleA": {"extends": ["com.acme.CycleB"]},
                "com.acme.CycleB": {"extends": ["com.acme.CycleA"]},
            },
        )
        infer = lambda receiver, method, signature="": (
            analyzer.infer_invocation_return_type(
                receiver, method, definition, signature,
            )
        )

        self.assertIsNone(infer("com.acme.Child", "choose"))
        self.assertEqual(
            infer("com.acme.Child", "choose", "(String)"),
            "com.acme.TextResult",
        )
        self.assertIsNone(
            infer("com.acme.Conflict", "resolve", "(String)"),
        )
        self.assertIsNone(
            infer("com.acme.ReversedConflict", "resolve", "(String)"),
        )
        self.assertEqual(
            infer("com.acme.Same", "resolve", "(String)"),
            "com.acme.SharedResult",
        )
        self.assertIsNone(infer("com.acme.CycleA", "missing", "()"))

    def test_return_type_resolution_is_deterministic_for_metadata_boundaries(self):
        definition = method_def(
            class_fqcn="com.acme.Child",
            local_method_return_types={
                "normalized": {"(String)": "com.acme.LocalResult"},
                "empty": {"()": ""},
                "same": {
                    "(String)": "com.acme.SharedResult",
                    "(int)": "com.acme.SharedResult",
                },
                "same_with_empty": {
                    "(String)": "com.acme.SharedResult",
                    "(int)": "com.acme.SharedResult",
                    "(long)": "",
                },
                "single": {"(String)": "com.acme.OnlyResult"},
                "none": None,
                "non_string_signature": {7: "com.acme.InvalidResult"},
                "invalid_signature": {"invalid": "com.acme.InvalidResult"},
                "non_string_return": {"()": 17},
                "alias_conflict": {
                    "(String)": "com.acme.ShortResult",
                    "(java.lang.String)": "com.acme.QualifiedResult",
                },
                "empty_bucket": {},
                "conflict": {
                    "(String)": "com.acme.TextResult",
                    "(int)": "com.acme.NumberResult",
                },
                "malformed": [],
            },
            known_method_return_types_by_signature={
                "com.acme.Base": {
                    "select": {"()": "com.acme.BaseResult"},
                    "blocked": {"()": "com.acme.ParentResult"},
                    "none": {"()": "com.acme.ParentResult"},
                },
                "com.acme.Contract": {
                    "select": {"()": "com.acme.InterfaceResult"},
                },
                "com.acme.MalformedChild": {"blocked": []},
                "com.acme.EmptyChild": {"blocked": {}},
                "com.acme.BadOwner": [],
            },
            known_method_return_types={
                "com.acme.Legacy": {
                    "read": " java.lang.String ",
                    "empty": "",
                    "broken": 17,
                },
            },
            known_type_metadata={
                "com.acme.Child": {
                    "extends": "com.acme.Base",
                    "implements": ("", "com.acme.Contract"),
                },
                "com.acme.MalformedChild": {"extends": "com.acme.Base"},
                "com.acme.EmptyChild": {"extends": "com.acme.Base"},
                "com.acme.DescendantOfBroken": {
                    "extends": "com.acme.MalformedChild",
                },
                "com.acme.BadMeta": [],
                "com.acme.TupleParents": {
                    "implements": (
                        "com.acme.Contract", "com.acme.Contract",
                    ),
                },
                "com.acme.SetParents": {
                    "implements": {"com.acme.Contract"},
                },
                "com.acme.InvalidParents": {
                    "extends": 17,
                    "implements": {"", None},
                },
                "com.acme.EmptyParent": {
                    "extends": "",
                    "implements": [],
                },
                "com.acme.TruthyBadMeta": ["not-a-mapping"],
            },
        )
        infer = lambda receiver, method, signature="": (
            analyzer.infer_invocation_return_type(
                receiver, method, definition, signature,
            )
        )

        expectations = {
            ("com.acme.Child", "normalized", "(java.lang.String)"): "com.acme.LocalResult",
            ("com.acme.Child", "empty", "()"): None,
            ("com.acme.Child", "same", ""): "com.acme.SharedResult",
            ("com.acme.Child", "same_with_empty", ""): None,
            ("com.acme.Child", "single", "(int)"): None,
            ("com.acme.Child", "single", "invalid"): None,
            ("com.acme.Child", "none", "()"): None,
            ("com.acme.Child", "non_string_signature", ""): None,
            ("com.acme.Child", "non_string_signature", "()"): None,
            ("com.acme.Child", "invalid_signature", ""): None,
            ("com.acme.Child", "non_string_return", ""): None,
            ("com.acme.Child", "non_string_return", "()"): None,
            ("com.acme.Child", "alias_conflict", "(String)"): None,
            ("com.acme.Child", "alias_conflict", "(java.lang.String)"): None,
            ("com.acme.Child", "empty_bucket", ""): None,
            ("com.acme.Child", "conflict", ""): None,
            ("com.acme.Child", "malformed", "()"): None,
            ("com.acme.Child", "select", "()"): "com.acme.BaseResult",
            ("com.acme.MalformedChild", "blocked", "()"): None,
            ("com.acme.EmptyChild", "blocked", "()"): None,
            ("com.acme.DescendantOfBroken", "blocked", "()"): None,
            ("com.acme.BadOwner", "read", "()"): None,
            ("com.acme.Legacy", "read", ""): "java.lang.String",
            ("com.acme.Legacy", "empty", ""): None,
            ("com.acme.Legacy", "broken", ""): None,
            ("com.acme.BadMeta", "missing", "()"): None,
            ("com.acme.TupleParents", "select", "()"): "com.acme.InterfaceResult",
            ("com.acme.SetParents", "select", "()"): "com.acme.InterfaceResult",
            ("com.acme.InvalidParents", "select", "()"): None,
            ("com.acme.EmptyParent", "select", "()"): None,
            ("com.acme.TruthyBadMeta", "select", "()"): None,
            ("", "select", "()"): None,
            ("com.acme.Child", "", "()"): None,
        }
        for arguments, expected in expectations.items():
            with self.subTest(arguments=arguments):
                self.assertEqual(infer(*arguments), expected)

        for attribute in (
            "known_method_return_types_by_signature",
            "known_method_return_types",
            "known_type_metadata",
        ):
            malformed = method_def(class_fqcn="com.acme.Child")
            setattr(malformed, attribute, [])
            with self.subTest(top_level_metadata=attribute):
                self.assertIsNone(
                    analyzer.infer_invocation_return_type(
                        "com.acme.Child", "missing", malformed, "()",
                    ),
                )

    def test_global_type_knowledge_joins_files_and_omits_conflicts(self):
        entry = method_def(
            class_fqcn="biz.Entry",
            class_name="Entry",
            method_name="run",
            imports={"Factory": "lib.Factory"},
            local_var_types={"factory": "lib.Factory"},
            known_type_metadata={
                "biz.Entry": {"extends": ["biz.Base"], "implements": []},
            },
        )
        factory_one = method_def(
            class_fqcn="lib.Factory",
            class_name="Factory",
            method_name="key",
            return_type="java.lang.String",
            param_types={"value": "java.lang.String"},
            param_declared_types={"value": "String"},
            field_types={"DEFAULT": "java.lang.String"},
            known_type_metadata={
                "lib.Factory": {"extends": [], "implements": []},
            },
        )
        factory_two = method_def(
            class_fqcn="lib.Factory",
            class_name="Factory",
            method_name="key",
            return_type="java.lang.String",
            param_types={
                "left": "java.lang.String", "right": "java.lang.String",
            },
            param_declared_types={"left": "String", "right": "String"},
            field_types={"DEFAULT": "java.lang.String"},
            known_type_metadata={
                "lib.Factory": {"extends": [], "implements": []},
            },
        )
        conflicting = method_def(
            class_fqcn="lib.Factory",
            class_name="Factory",
            method_name="ambiguous",
            return_type="lib.First",
            param_declared_types={"value": "String"},
        )
        conflicting_duplicate = method_def(
            class_fqcn="lib.Factory",
            class_name="Factory",
            method_name="ambiguous",
            return_type="lib.Second",
            param_declared_types={"value": "String"},
        )

        rows = analyzer.install_global_type_knowledge([
            entry, factory_one, factory_two, conflicting,
            conflicting_duplicate,
        ])
        self.assertEqual(len(rows), 5)
        self.assertEqual(
            entry.known_method_return_types_by_signature["lib.Factory"]["key"],
            {
                "(String)": "java.lang.String",
                "(String, String)": "java.lang.String",
            },
        )
        self.assertNotIn(
            "ambiguous",
            entry.known_method_return_types_by_signature["lib.Factory"],
        )
        self.assertEqual(
            entry.known_field_types["lib.Factory"]["DEFAULT"],
            "java.lang.String",
        )
        self.assertEqual(
            entry.known_type_metadata["biz.Entry"]["extends"],
            ["biz.Base"],
        )
        self.assertEqual(
            entry.known_classes_by_simple["Factory"], ["lib.Factory"],
        )
        self.assertEqual(
            analyzer.infer_param_type_from_expression(
                'factory.key("last, first")', entry,
            ),
            "String",
        )

    def test_global_type_knowledge_fails_closed_for_every_incomplete_or_conflicting_declaration(self):
        self.assertEqual(analyzer.install_global_type_knowledge(None), [])

        valid = method_def(
            class_fqcn="lib.Valid",
            class_name="Valid",
            method_name="load",
            return_type="lib.Result",
            param_declared_types={},
            param_types={"value": "java.lang.String"},
            field_types={"READY": "boolean"},
            known_type_metadata={
                "lib.Valid": {
                    "extends": None,
                    "implements": ["lib.Marker"],
                },
                "lib.EmptyMetadata": None,
                "": {"extends": ["must.not.be.used"]},
            },
        )
        incomplete_rows = [
            method_def(
                class_fqcn="",
                method_name="ignored",
                return_type="lib.Result",
                field_types={"name": "lib.Value"},
                known_type_metadata={},
            ),
            method_def(
                class_fqcn="lib.NoMethod",
                method_name="",
                return_type="lib.Result",
                field_types={"": "lib.Value", "name": ""},
                known_type_metadata={},
            ),
            method_def(
                class_fqcn="lib.NoReturn",
                method_name="load",
                return_type="",
                field_types={None: None},
                known_type_metadata={None: None},
            ),
            SimpleNamespace(
                class_fqcn=None,
                method_name=None,
                return_type=None,
                field_types=None,
                known_type_metadata=None,
            ),
        ]
        conflict_rows = [
            method_def(
                class_fqcn="lib.Conflict",
                method_name="load",
                return_type="lib.First",
                param_declared_types={"value": "String"},
                field_types={"VALUE": "lib.First"},
                known_type_metadata={
                    "lib.Conflict": {"extends": ["lib.FirstParent"]},
                },
            ),
            method_def(
                class_fqcn="lib.Conflict",
                method_name="load",
                return_type="lib.Second",
                param_declared_types={"value": "String"},
                field_types={"VALUE": "lib.Second"},
                known_type_metadata={
                    "lib.Conflict": {"extends": ["lib.SecondParent"]},
                },
            ),
        ]

        rows = analyzer.install_global_type_knowledge([
            valid, *incomplete_rows, *conflict_rows,
        ])

        self.assertEqual(len(rows), 7)
        self.assertEqual(
            valid.known_method_return_types_by_signature,
            {"lib.Valid": {"load": {"(String)": "lib.Result"}}},
        )
        self.assertEqual(
            valid.known_field_types,
            {"lib.Valid": {"READY": "boolean"}},
        )
        self.assertEqual(
            valid.known_type_metadata["lib.Valid"],
            {"extends": [], "implements": ["lib.Marker"]},
        )
        self.assertEqual(
            valid.known_type_metadata["lib.EmptyMetadata"],
            {"extends": [], "implements": []},
        )
        self.assertNotIn(
            "lib.Conflict", valid.known_method_return_types_by_signature,
        )
        self.assertNotIn("lib.Conflict", valid.known_field_types)
        self.assertNotIn("lib.Conflict", valid.known_type_metadata)
        self.assertNotIn("", valid.known_classes_by_simple)
        self.assertEqual(
            valid.known_classes_by_simple["Conflict"], ["lib.Conflict"],
        )
        for row in rows:
            self.assertIs(
                row.known_method_return_types,
                valid.known_method_return_types_by_signature,
            )

    def test_expression_inference_covers_literals_calls_maps_and_arrays(self):
        self.definition.local_method_return_types = {
            "current": {"()": "com.acme.Order"},
            "echo": {
                "(String)": "com.acme.Order",
                "(int)": "com.acme.Number",
            },
        }
        self.definition.known_method_return_types_by_signature = {
            "com.acme.Repository": {"find": {"(String)": "com.acme.Order"}},
        }
        self.definition.ast_local_var_sites = [{
            "name": "values",
            "declared_type": "String[]",
            "resolved_declared_type": "java.lang.String[]",
            "initializer_expr": "",
        }]
        analyzer.resolve_ast_local_var_types(self.definition)

        infer_param = lambda expr: analyzer.infer_param_type_from_expression(
            expr, self.definition, self.definition.local_var_types,
        )
        self.assertEqual(infer_param('"text"'), "String")
        self.assertEqual(infer_param('"prefix" + input'), "String")
        self.assertEqual(infer_param("12"), "int")
        self.assertEqual(infer_param("1.5"), "double")
        self.assertEqual(infer_param("input != null"), "boolean")
        self.assertEqual(infer_param("null"), "Object")
        self.assertEqual(infer_param("Order.class"), "Class")
        self.assertEqual(infer_param("input"), "Input")
        self.assertEqual(infer_param("values[0]"), "String")
        self.assertEqual(infer_param("new Order[2][]"), "Order[][]")
        self.assertEqual(infer_param("mapping.get(\"id\")"), "Order")
        self.assertEqual(infer_param("repository.find(\"id\")"), "Order")
        self.assertEqual(infer_param("condition ? input : null"), "Input")

        infer_expr = lambda expr: analyzer.infer_expression_type_from_text(
            expr, self.definition, self.definition.local_var_types,
        )
        self.assertEqual(infer_expr('"text"'), "java.lang.String")
        self.assertEqual(infer_expr("new Order()"), "com.acme.model.Order")
        self.assertEqual(infer_expr("current()"), "com.acme.Order")
        self.assertEqual(infer_expr('echo("text")'), "com.acme.Order")
        self.assertIsNone(infer_expr("echo(unknown)"))
        self.assertEqual(infer_expr("repository.find(\"id\")"), "com.acme.Order")
        self.assertEqual(
            infer_expr("repository.find(unknown)"), "com.acme.Order",
        )
        self.assertEqual(infer_expr("Order"), "com.acme.model.Order")
        self.assertIsNone(infer_expr("unknown"))
        for malformed_expression in (
            None,
            "",
            "   ",
            '"unterminated',
            "new 1Invalid()",
            'current("unterminated)',
            'repository.find("unterminated)',
            "Order(",
        ):
            with self.subTest(malformed_expression=malformed_expression):
                self.assertIsNone(infer_expr(malformed_expression))

        unresolved = method_def(
            imports={"Order": "com.acme.model.Order"},
            local_var_types={"existing": "com.acme.Existing"},
            ast_local_var_sites=[
                {
                    "name": "declared",
                    "declared_type": "Order",
                    "resolved_declared_type": "",
                    "initializer_expr": "",
                },
                {
                    "name": "inferred",
                    "declared_type": "var",
                    "resolved_declared_type": "",
                    "initializer_expr": "new Order()",
                },
                {
                    "name": "explicit",
                    "declared_type": "",
                    "resolved_declared_type": "com.acme.Explicit",
                    "initializer_expr": "new Order()",
                },
                {
                    "name": "",
                    "declared_type": "Order",
                    "resolved_declared_type": "com.acme.model.Order",
                    "initializer_expr": "",
                },
                {
                    "name": "unresolved",
                    "declared_type": "var",
                    "resolved_declared_type": "",
                    "initializer_expr": "unknown",
                },
                {
                    "name": "empty",
                    "declared_type": "",
                    "resolved_declared_type": "",
                    "initializer_expr": "",
                },
            ],
        )
        self.assertEqual(
            analyzer.resolve_ast_local_var_types(unresolved),
            {
                "existing": "com.acme.Existing",
                "declared": "com.acme.model.Order",
                "inferred": "com.acme.model.Order",
                "explicit": "com.acme.Explicit",
            },
        )

    def test_parameter_type_inference_fails_closed_for_incomplete_expressions(self):
        infer = lambda expression: analyzer.infer_param_type_from_expression(
            expression, self.definition,
        )

        # These values model empty/error nodes that Tree-sitter can expose
        # while recovering an incomplete Java invocation.  None is the only
        # sound type result; most importantly, analysis must not abort.
        for expression in (
            None,
            "",
            "   ",
            "()",
            "( )",
            "(( ))",
            "?:",
            "condition ? : input",
            "condition ? input :",
            "? input : input",
        ):
            with self.subTest(expression=expression):
                self.assertIsNone(infer(expression))

    def test_parameter_type_inference_covers_java_expression_families(self):
        definition = method_def(
            imports={
                "Constants": "com.acme.Constants",
                "Customer": "com.acme.Customer",
                "Order": "com.acme.Order",
                "URL": "java.net.URL",
            },
            field_types={
                "fqnField": "com.acme.Order",
                "simpleField": "Order",
                "repository": "com.acme.Repository",
                "text": "java.lang.String",
                "typedFieldArray": "com.acme.Customer[]",
                "url": "java.net.URL",
            },
            field_declared_types={
                "declaredFieldArray": "Order[]",
            },
            param_types={
                "input": "com.acme.Input",
                "scalar": "com.acme.Order",
                "simple": "Simple",
                "typedParamArray": "com.acme.Customer[]",
            },
            param_declared_types={
                "declaredParamArray": "Order[]",
                "mapping": "Map<String, Order>",
                "varargs": "String...",
            },
            local_method_return_types={
                "current": {"()": "com.acme.Order"},
                "echo": {
                    "(String)": "com.acme.Order",
                    "(int)": "com.acme.Customer",
                },
            },
            known_method_return_types_by_signature={
                "com.acme.Repository": {
                    "find": {"(String)": "com.acme.Order"},
                    "lookup": {
                        "(String)": "com.acme.Order",
                        "(String, String)": "com.acme.Customer",
                    },
                    "save": {
                        "(Order)": "com.acme.Order",
                        "(Customer)": "com.acme.Customer",
                    },
                },
            },
            ast_local_var_sites=[
                {
                    "name": "localMapping",
                    "declared_type": "Map<String, Customer>",
                },
                {
                    "name": "rawMapping",
                    "declared_type": "Map",
                },
                {
                    "name": "singleTypeMapping",
                    "declared_type": "Map<Order>",
                },
                {"name": "emptyMapping", "declared_type": None},
                {"name": "listMapping", "declared_type": "List<Order>"},
                {"name": "openMapping", "declared_type": "Map<String"},
                {"name": "closeMapping", "declared_type": "Map String>"},
            ],
            body_text="for (Customer customer : customers) { use(customer); }",
            known_field_types={
                "com.acme.Constants": {
                    "ORDER": "com.acme.Order",
                    "COUNT": "int",
                },
            },
        )
        local_types = {
            "localOrder": "com.acme.Order",
            "simpleLocal": "Local",
            "localArray": "com.acme.Order[]",
            "matrix": "com.acme.Order[][]",
        }
        infer = lambda expression: analyzer.infer_param_type_from_expression(
            expression, definition, local_types,
        )

        expected_types = {
            "((\"text\"))": "String",
            "\"prefix\" + input": "String",
            "true": "boolean",
            "false": "boolean",
            "input == null": "boolean",
            "input instanceof Input": "boolean",
            "ready && valid": "boolean",
            "ready || valid": "boolean",
            "!ready": "boolean",
            "null": "Object",
            "Order.class": "Class",
            "(Order) input": "Order",
            "new Order[2][]": "Order[][]",
            "new Order()": "Order",
            "condition ? input : null": "Input",
            "condition ? null : input": "Input",
            "condition ? input : input": "Input",
            "condition ? input : \"text\"": None,
            "condition ? unknown : input": None,
            "condition ? input : unknown": None,
            "condition ? unknown : unknown": None,
            "condition ? null : unknown": None,
            "condition ? unknown : null": None,
            "condition ? (nested ? input : null) : input": "Input",
            "condition ? nested ? input : null : input": "Input",
            "condition ? localArray[index ? 1 : 0] : input": None,
            "condition ? new Order[]{new Order()} : input": None,
            "this.fqnField": "Order",
            "this.simpleField": "Order",
            "this.missing": None,
            "input": "Input",
            "simple": "Simple",
            "localOrder": "Order",
            "simpleLocal": "Local",
            "fqnField": "Order",
            "simpleField": "Order",
            "localArray[0]": "Order",
            "matrix[0]": "Order[]",
            "declaredParamArray[0]": "Order",
            "typedParamArray[0]": "Customer",
            "declaredFieldArray[0]": "Order",
            "typedFieldArray[0]": "Customer",
            "varargs[0]": "String",
            "missingArray[0]": None,
            "scalar[0]": None,
            "customer": "Customer",
            "Constants.ORDER": "Order",
            "Constants.COUNT": "int",
            "External.VALUE": "External",
            "mapping.get(\"id\")": "Order",
            "localMapping.get(\"id\")": "Customer",
            "rawMapping.get(\"id\")": None,
            "singleTypeMapping.get(\"id\")": None,
            "emptyMapping.get(\"id\")": None,
            "listMapping.get(\"id\")": None,
            "openMapping.get(\"id\")": None,
            "closeMapping.get(\"id\")": None,
            "unknownMap.get(\"id\")": None,
            "repository.find(\"id\")": "Order",
            "repository.find(\"unterminated)": None,
            "repository.lookup(\"last, first\")": "Order",
            "repository.save(new Order())": "Order",
            "repository.missing(unknown)": None,
            "text.substring(1)": "String",
            "request.getParameter(\"name\")": "String",
            "url.getParameter(\"name\", \"fallback\")": "String",
            "current()": "Order",
            "current(\"unterminated)": None,
            "echo(\"text\")": "Order",
            "echo(unknown)": None,
            "missing()": None,
            "unknown": None,
        }
        for expression, expected in expected_types.items():
            with self.subTest(expression=expression):
                self.assertEqual(infer(expression), expected)

        empty_knowledge = method_def(known_field_types={})
        self.assertEqual(
            analyzer.infer_param_type_from_expression(
                "Other.VALUE", empty_knowledge,
            ),
            "Other",
        )

    def test_parameter_type_inference_covers_java_numeric_and_character_literals(self):
        infer = lambda expression: analyzer.infer_param_type_from_expression(
            expression, self.definition,
        )
        expected_types = {
            "0": "int",
            "-12": "int",
            "+12": "int",
            "1_000": "int",
            "0xff": "int",
            "0b1010": "int",
            "077": "int",
            "12L": "long",
            "0xffL": "long",
            "1.5": "double",
            ".5": "double",
            "1.": "double",
            "1e3": "double",
            "0x1.fp3": "double",
            "1F": "float",
            "1.5f": "float",
            "'a'": "char",
            "'\\n'": "char",
            "0x": None,
            "0b2": None,
            "08": None,
            "1_": None,
            "--1": None,
            "'ab'": None,
            "'\\q'": None,
        }
        for expression, expected in expected_types.items():
            with self.subTest(expression=expression):
                self.assertEqual(infer(expression), expected)
        self.assertIsNone(analyzer._infer_java_numeric_or_character_literal_type(None))

    def test_stable_library_return_type_table_is_fail_closed(self):
        infer = analyzer.infer_known_library_method_return_type
        expected = {
            ("java.lang.String", "length"): "int",
            ("String", "substring"): "java.lang.String",
            ("java.lang.String<Order>", "indexOf"): "int",
            ("String", "unknown"): None,
            ("Class", "isRecord"): "boolean",
            ("java.lang.Class", "getName"): "java.lang.String",
            ("Class", "unknown"): None,
            ("StringUtils", "isBlank"): "boolean",
            ("StringUtils", "unknown"): None,
            ("java.net.URL", "getParameter"): "java.lang.String",
            ("Order", "getParameter"): None,
            ("java.net.URL", "unknown"): None,
            ("Order", "toString"): "java.lang.String",
            ("Order", "guess"): None,
            ("", "length"): None,
            ("String", ""): None,
            (None, "length"): None,
        }
        for arguments, return_type in expected.items():
            with self.subTest(arguments=arguments):
                self.assertEqual(infer(*arguments), return_type)
        self.assertEqual(analyzer._to_simple_type_name("java.util.List<Order>"), "List")
        self.assertIsNone(analyzer._to_simple_type_name(""))
        self.assertIsNone(analyzer._to_simple_type_name("<Order>"))
        self.assertEqual(analyzer.extract_generic_type("Map<String, Order>"), "String")
        self.assertIsNone(analyzer.extract_generic_type("String"))

    def test_text_expression_uses_stable_library_return_type_fallback(self):
        definition = method_def(
            field_types={"text": "java.lang.String"},
        )

        self.assertEqual(
            analyzer.infer_expression_type_from_text(
                "text.substring(1)", definition,
            ),
            "java.lang.String",
        )
        self.assertEqual(
            analyzer.infer_param_type_from_expression(
                "text.substring(1)", definition,
            ),
            "String",
        )
        self.assertIsNone(
            analyzer.infer_expression_type_from_text(
                "text.unregistered(1)", definition,
            )
        )


class TreeSitterInferenceContractTest(unittest.TestCase):
    def setUp(self):
        self.tree = tree_analyzer_without_parser()
        self.definition = method_def(
            imports={"Order": "com.acme.model.Order"},
            param_types={"input": "com.acme.Input"},
            param_declared_types={"input": "Input"},
            field_types={"orders": "java.util.List"},
            field_declared_types={"orders": "List<Order>"},
            local_method_return_types={"current": {"()": "com.acme.model.Order"}},
            known_type_metadata={"com.acme.Sample": {"extends": ["com.acme.Base"]}},
        )

    def test_tree_sitter_constructor_supports_both_parser_apis_and_rejects_kotlin(self):
        class LegacyParser:
            def __init__(self):
                self.assigned = None

            def set_language(self, language):
                self.assigned = language

        class ModernParser:
            pass

        with patch.object(analyzer, "Parser", LegacyParser), patch.object(
            analyzer, "Language", side_effect=lambda value: ("wrapped", value),
        ), patch.object(analyzer.tsjava, "language", return_value="java-capsule"):
            legacy = analyzer.TreeSitterAnalyzer(
                "Sample.java", {"root": "src/main/java", "module": "root"},
            )
        self.assertEqual(legacy.language, "java")
        self.assertEqual(legacy.parser.assigned, ("wrapped", "java-capsule"))

        with patch.object(analyzer, "Parser", ModernParser), patch.object(
            analyzer, "Language", return_value="java-language",
        ), patch.object(analyzer.tsjava, "language", return_value="java-capsule"):
            modern = analyzer.TreeSitterAnalyzer(
                "Sample.java", {"root": "src/main/java", "module": "root"},
            )
        self.assertEqual(modern.parser.language, "java-language")

        with patch.object(analyzer, "Parser", side_effect=AssertionError("must not initialize")):
            for suffix in (".kt", ".kts"):
                with self.subTest(suffix=suffix):
                    with self.assertRaisesRegex(ImportError, "does not support Kotlin"):
                        analyzer.TreeSitterAnalyzer(
                            "Sample" + suffix,
                            {"root": "src/main/kotlin", "module": "root"},
                        )

    @unittest.skipUnless(
        analyzer.TREE_SITTER_AVAILABLE, "requires the tree-sitter Java parser",
    )
    def test_tree_sitter_analyze_fails_closed_for_io_and_decoding_errors(self):
        missing = analyzer.TreeSitterAnalyzer(
            "/definitely/missing/Sample.java",
            {"root": "src/main/java", "module": "root"},
        )
        self.assertEqual(missing.analyze(), [])

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_bytes(b"class Sample {}")
            tree = analyzer.TreeSitterAnalyzer(
                str(source), {"root": temporary, "module": "root"},
            )
            with patch.object(
                analyzer,
                "decode_java_source_bytes",
                side_effect=TypeError("decoder contract violation"),
            ):
                self.assertEqual(tree.analyze(), [])
        self.assertFalse(tree.non_empty_source)
        self.assertFalse(tree.has_type_declarations)
        self.assertEqual(tree.error_nodes, 0)

    def test_parse_method_node_fails_closed_and_handles_missing_optional_syntax(self):
        orphan = FakeNode(
            "method_declaration",
            fields={
                "name": FakeNode("identifier", "run"),
                "type": FakeNode("void_type", "void"),
            },
        )
        with patch.object(
            self.tree,
            "_field_text",
            side_effect=lambda node, name, _source: (
                node.child_by_field_name(name).text
                if node.child_by_field_name(name) is not None else None
            ),
        ):
            self.assertIsNone(self.tree._parse_method_node(orphan, b"", []))

            nameless = FakeNode("method_declaration")
            owner = FakeNode(
                "class_declaration",
                fields={"name": FakeNode("identifier", "Owner")},
                children=[nameless],
            )
            self.assertIsNone(self.tree._parse_method_node(nameless, b"", []))

            constructor = FakeNode(
                "constructor_declaration",
                start_row=3,
                end_row=3,
            )
            owner.children.append(constructor)
            constructor.parent = owner
            parsed_constructor = self.tree._parse_method_node(constructor, b"", [])
            self.assertEqual(parsed_constructor.method_name, "Owner")
            self.assertEqual(parsed_constructor.return_type, "")
            self.assertEqual(parsed_constructor.param_declared_types, {})
            self.assertEqual(parsed_constructor.ast_call_sites, [])

            fallback_throws = FakeNode("throws", children=[
                FakeNode(",", ","),
                FakeNode("type_identifier", ""),
                FakeNode("scoped_type_identifier", "java.io.IOException"),
            ])
            body = FakeNode("block")
            method = FakeNode(
                "method_declaration",
                "public unresolved() throws java.io.IOException {}",
                fields={
                    "name": FakeNode("identifier", "unresolved"),
                    "body": body,
                },
                children=[fallback_throws],
                start_row=1,
                end_row=1,
            )
            owner.children.append(method)
            method.parent = owner
            with patch.object(
                self.tree.helper,
                "_extract_leading_annotations",
                return_value=["Leading"],
            ), patch.object(
                self.tree.helper,
                "_extract_modifiers",
                return_value=["public"],
            ):
                parsed = self.tree._parse_method_node(
                    method, b"", ["@Leading\n", "public unresolved() {}\n"],
                )
            self.assertEqual(parsed.method_name, "unresolved")
            self.assertEqual(parsed.return_declared_type, "")
            self.assertEqual(parsed.return_type, "")
            self.assertEqual(parsed.throws_declared_types, ["java.io.IOException"])
            self.assertEqual(parsed.annotations, ["Leading"])
            self.assertEqual(parsed.modifiers, ["public"])
            self.assertEqual(parsed._body_lines, ("public unresolved() {}\n",))

            direct_throws = FakeNode("throws", children=[
                FakeNode("type_identifier", "CheckedFailure"),
            ])
            direct_throw_method = FakeNode(
                "method_declaration",
                fields={
                    "name": FakeNode("identifier", "directThrow"),
                    "type": FakeNode("void_type", "void"),
                    "throws": direct_throws,
                },
            )
            owner.children.append(direct_throw_method)
            direct_throw_method.parent = owner
            parsed_direct_throw = self.tree._parse_method_node(
                direct_throw_method, b"", [],
            )
            self.assertEqual(
                parsed_direct_throw.throws_declared_types,
                ["CheckedFailure"],
            )

            compact = FakeNode("compact_constructor_declaration")
            owner.children.append(compact)
            compact.parent = owner
            parsed_compact = self.tree._parse_method_node(compact, b"", [])
            self.assertEqual(parsed_compact.method_name, "Owner")
            self.assertEqual(parsed_compact.param_declared_types, {})

            compact_with_parameters = FakeNode(
                "compact_constructor_declaration",
                fields={"parameters": FakeNode("formal_parameters", children=[
                    FakeNode("formal_parameter", fields={
                        "type": FakeNode("type_identifier", "String"),
                        "name": FakeNode("identifier", "value"),
                    }),
                ])},
            )
            owner.children.append(compact_with_parameters)
            compact_with_parameters.parent = owner
            parsed_compact_with_parameters = self.tree._parse_method_node(
                compact_with_parameters, b"", [],
            )
            self.assertEqual(
                parsed_compact_with_parameters.param_declared_types,
                {"value": "String"},
            )

    def test_declared_type_inference_obeys_scope_parameter_and_field_order(self):
        local = FakeNode("identifier", "local")
        param = FakeNode("identifier", "input")
        field = FakeNode("identifier", "orders")
        unknown = FakeNode("identifier", "missing")
        infer = lambda node: self.tree._infer_expression_declared_type(
            node, b"", self.definition, {"local": "List<Order>"},
        )
        self.assertEqual(infer(local), "List<Order>")
        self.assertEqual(infer(param), "Input")
        self.assertEqual(infer(field), "List<Order>")
        self.assertIsNone(infer(unknown))

        this_node = FakeNode("this", "this")
        field_name = FakeNode("identifier", "orders")
        access = FakeNode("field_access", "this.orders", fields={
            "object": this_node,
            "field": field_name,
        })
        self.assertEqual(infer(access), "List<Order>")
        nested = FakeNode("field_access", "input.value", fields={
            "object": param,
            "field": FakeNode("identifier", "value"),
        })
        self.assertIsNone(infer(nested))
        for unresolved_access in (
            FakeNode("field_access", "missing.value"),
            FakeNode("field_access", "this.missing", fields={
                "object": FakeNode("this", "this"),
                "field": FakeNode("identifier", "missing"),
            }),
            FakeNode("field_access", "this.<missing>", fields={
                "object": FakeNode("this", "this"),
            }),
        ):
            self.assertIsNone(infer(unresolved_access))
        self.assertIsNone(infer(None))

    def test_expression_type_inference_covers_ast_node_families(self):
        infer = lambda node, locals_=None: self.tree._infer_expression_type(
            node, b"", self.definition, locals_ or {"local": "com.acme.Local"},
        )
        self.assertEqual(infer(FakeNode("super", "super")), "com.acme.Base")
        self.assertEqual(infer(FakeNode("identifier", "local")), "com.acme.Local")
        self.assertEqual(infer(FakeNode("identifier", "input")), "com.acme.Input")
        self.assertEqual(infer(FakeNode("identifier", "Order")), "com.acme.model.Order")
        self.assertIsNone(infer(FakeNode("identifier", "missing")))
        self.assertEqual(infer(FakeNode("this", "this")), "com.acme.Sample")
        created = FakeNode("object_creation_expression", "new Order()", fields={
            "type": FakeNode("type_identifier", "Order"),
        })
        self.assertEqual(infer(created), "com.acme.model.Order")

        invocation = FakeNode("method_invocation", "current()", fields={
            "name": FakeNode("identifier", "current"),
            "arguments": FakeNode("argument_list", "()", children=[]),
        })
        self.assertEqual(infer(invocation), "com.acme.model.Order")
        access = FakeNode("field_access", "input.value", fields={
            "object": FakeNode("identifier", "input"),
            "field": FakeNode("identifier", "value"),
        })
        self.assertIsNone(infer(access))
        own_field = FakeNode("field_access", "this.orders", fields={
            "object": FakeNode("this", "this"),
            "field": FakeNode("identifier", "orders"),
        })
        self.assertEqual(infer(own_field), "java.util.List")
        parenthesized = FakeNode("parenthesized_expression", "(input)", children=[
            FakeNode("(", "("), FakeNode("identifier", "input"), FakeNode(")", ")"),
        ])
        self.assertEqual(infer(parenthesized), "com.acme.Input")
        cast = FakeNode("cast_expression", "(Order) input", fields={
            "type": FakeNode("type_identifier", "Order"),
        })
        self.assertEqual(infer(cast), "com.acme.model.Order")
        self.assertEqual(infer(FakeNode("string_literal", '"x"')), "java.lang.String")
        self.assertEqual(infer(FakeNode("hex_integer_literal", "0xff")), "int")
        self.assertEqual(infer(FakeNode("decimal_integer_literal", "12L")), "long")
        self.assertEqual(infer(FakeNode("decimal_floating_point_literal", "1.0")), "double")
        self.assertEqual(infer(FakeNode("decimal_floating_point_literal", "1F")), "float")
        self.assertEqual(infer(FakeNode("character_literal", "'a'")), "char")
        self.assertEqual(infer(FakeNode("true", "true")), "boolean")
        self.assertIsNone(infer(FakeNode("null_literal", "null")))
        self.assertIsNone(infer(None))

    def test_expression_type_inference_fails_closed_at_every_unknown_ast_boundary(self):
        infer = lambda node, locals_=None: self.tree._infer_expression_type(
            node,
            b"",
            self.definition,
            {} if locals_ is None else locals_,
        )
        self.assertEqual(infer(FakeNode("identifier", "orders")), "java.util.List")
        self.assertIsNone(infer(FakeNode("identifier", "")))
        self.assertIsNone(infer(FakeNode(
            "object_creation_expression",
            "new <missing>()",
        )))
        self.assertIsNone(infer(FakeNode(
            "method_invocation",
            "missing-name()",
            fields={"arguments": FakeNode("argument_list")},
        )))

        no_arguments = FakeNode(
            "method_invocation",
            "current()",
            fields={"name": FakeNode("identifier", "current")},
        )
        self.assertEqual(infer(no_arguments), "com.acme.model.Order")

        invocation = FakeNode(
            "method_invocation",
            'Order.convert("x", unknown)',
            fields={
                "object": FakeNode("identifier", "Order"),
                "name": FakeNode("identifier", "convert"),
                "arguments": FakeNode("argument_list", children=[
                    FakeNode("(", "("),
                    FakeNode("string_literal", '"x"'),
                    FakeNode(",", ","),
                    FakeNode("identifier", "unknown"),
                    FakeNode(")", ")"),
                ]),
            },
        )
        with patch.object(
            analyzer,
            "infer_invocation_return_type",
            return_value="com.acme.Result",
        ) as resolve_return:
            self.assertEqual(infer(invocation), "com.acme.Result")
        self.assertEqual(resolve_return.call_args.args[:3], (
            "com.acme.model.Order", "convert", self.definition,
        ))
        self.assertEqual(
            resolve_return.call_args.kwargs["invocation_signature"],
            "",
        )

        for field_access in (
            FakeNode("field_access", "unknown.value"),
            FakeNode("field_access", "input.value", fields={
                "object": FakeNode("identifier", "input"),
                "field": FakeNode("identifier", "value"),
            }),
            FakeNode("field_access", "this.missing", fields={
                "object": FakeNode("this", "this"),
                "field": FakeNode("identifier", "missing"),
            }),
            FakeNode("field_access", "this.<missing>", fields={
                "object": FakeNode("this", "this"),
            }),
        ):
            self.assertIsNone(infer(field_access))

        self.assertIsNone(infer(FakeNode(
            "parenthesized_expression",
            "()",
            children=[FakeNode("(", "("), FakeNode(")", ")")],
        )))
        self.assertIsNone(infer(FakeNode("cast_expression", "(missing) value")))
        self.assertEqual(infer(FakeNode("false", "false")), "boolean")
        self.assertEqual(infer(FakeNode("boolean_literal", "true")), "boolean")
        self.assertIsNone(infer(FakeNode("array_access", "values[0]")))

    def test_lambda_parameter_types_use_explicit_declarations_and_stream_context(self):
        formal = FakeNode("formal_parameter", "Order order", fields={
            "type": FakeNode("type_identifier", "Order"),
            "name": FakeNode("identifier", "order"),
        })
        explicit_parameters = FakeNode("formal_parameters", "(Order order)", children=[formal])
        explicit_lambda = FakeNode("lambda_expression", "order -> order.id", fields={
            "parameters": explicit_parameters,
        })
        local, declared = self.tree._infer_lambda_parameter_types(
            explicit_lambda, b"", self.definition, {},
        )
        self.assertEqual(local, {"order": "com.acme.model.Order"})
        self.assertEqual(declared, {"order": "Order"})

        inferred_name = FakeNode("identifier", "order")
        inferred_lambda = FakeNode("lambda_expression", "order -> order.id", fields={
            "parameters": inferred_name,
        })
        upstream = FakeNode("identifier", "orders")
        stream = FakeNode("method_invocation", "orders.stream()", fields={
            "object": upstream,
            "name": FakeNode("identifier", "stream"),
        })
        outer = FakeNode("method_invocation", "orders.stream().map(...)" , fields={
            "object": stream,
            "name": FakeNode("identifier", "map"),
        })
        inferred_lambda.parent = outer
        local, declared = self.tree._infer_lambda_parameter_types(
            inferred_lambda, b"", self.definition, {},
        )
        self.assertEqual(local, {"order": "com.acme.model.Order"})
        self.assertEqual(declared, {})

        detached = FakeNode("lambda_expression", "x -> x", fields={
            "parameters": FakeNode("identifier", "x"),
        })
        self.assertEqual(
            self.tree._infer_lambda_parameter_types(detached, b"", self.definition, {}),
            ({}, {}),
        )

    def test_lambda_parameter_inference_handles_malformed_and_non_stream_contexts(self):
        no_parameters = FakeNode("lambda_expression", "() -> 1")
        self.assertEqual(
            self.tree._infer_lambda_parameter_types(
                no_parameters, b"", self.definition, {},
            ),
            ({}, {}),
        )

        nameless = FakeNode("formal_parameter", "Order", fields={
            "type": FakeNode("type_identifier", "Order"),
        })
        untyped = FakeNode("formal_parameter", "item", fields={
            "name": FakeNode("identifier", "item"),
        })
        inferred_one = FakeNode("inferred_parameter", "left")
        inferred_two = FakeNode("identifier", "right")
        parameters = FakeNode("formal_parameters", children=[
            FakeNode("(", "("), nameless, untyped, inferred_one,
            FakeNode(",", ","), inferred_two, FakeNode("unknown_parameter"),
            FakeNode(")", ")"),
        ])
        mixed = FakeNode("lambda_expression", fields={"parameters": parameters})
        local, declared = self.tree._infer_lambda_parameter_types(
            mixed, b"", self.definition, {},
        )
        self.assertEqual(local, {})
        self.assertEqual(declared, {})

        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, [],
            ),
            {},
        )
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, ["item"],
            ),
            {},
        )

        no_object_call = FakeNode("method_invocation", "map(item)")
        mixed.parent = FakeNode("arguments", children=[no_object_call])
        no_object_call.parent = mixed.parent
        # The lambda must be below the invocation to model the AST ancestor
        # relationship; a detached sibling remains unresolved.
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, ["item"],
            ),
            {},
        )
        mixed.parent = no_object_call
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, ["item"],
            ),
            {},
        )

        non_generic_call = FakeNode(
            "method_invocation",
            "input.map(item)",
            fields={"object": FakeNode("identifier", "input")},
        )
        mixed.parent = FakeNode("argument_list", parent=non_generic_call)
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, ["item"],
            ),
            {},
        )

        stream_without_object = FakeNode(
            "method_invocation",
            "stream()",
            fields={"name": FakeNode("identifier", "stream")},
        )
        map_call = FakeNode(
            "method_invocation",
            "stream().map(item)",
            fields={"object": stream_without_object},
        )
        mixed.parent = map_call
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed, b"", self.definition, {}, ["item"],
            ),
            {},
        )

        for receiver_invocation in (
            FakeNode("method_invocation", "unknown()"),
            FakeNode(
                "method_invocation",
                "orders.other()",
                fields={
                    "name": FakeNode("identifier", "other"),
                    "object": FakeNode("identifier", "orders"),
                },
            ),
        ):
            outer_call = FakeNode(
                "method_invocation",
                "receiver.map(item)",
                fields={"object": receiver_invocation},
            )
            mixed.parent = outer_call
            self.assertEqual(
                self.tree._infer_lambda_parameter_types_from_context(
                    mixed, b"", self.definition, {}, ["item"],
                ),
                {},
            )

        direct_collection_call = FakeNode(
            "method_invocation",
            "orders.map(left, right)",
            fields={"object": FakeNode("identifier", "orders")},
        )
        mixed.parent = direct_collection_call
        self.assertEqual(
            self.tree._infer_lambda_parameter_types_from_context(
                mixed,
                b"",
                self.definition,
                {"orders": "List<Order>"},
                ["left", "right"],
            ),
            {
                "left": "com.acme.model.Order",
                "right": "com.acme.model.Order",
            },
        )

    def test_ast_structural_helpers_preserve_only_well_formed_metadata(self):
        self.assertEqual(
            self.tree._build_class_context([], b"", []),
            ("", "", [], False),
        )

        modifiers = FakeNode("modifiers", children=[
            FakeNode("marker_annotation", "@pkg.Mark"),
            FakeNode("annotation", "@Other(value = 1)"),
            FakeNode("annotation", "@123"),
            FakeNode("public", "public"),
            FakeNode("token", ""),
        ])
        outer = FakeNode(
            "class_declaration",
            fields={"name": FakeNode("identifier", "Outer")},
            children=[modifiers],
            start_row=2,
        )
        inner = FakeNode(
            "interface_declaration",
            fields={"name": FakeNode("identifier", "Inner")},
        )
        self.assertEqual(
            self.tree._build_class_context([outer, inner], b"", []),
            ("com.acme.Outer.Inner", "Inner", [], True),
        )
        self.assertEqual(
            self.tree._collect_node_annotations(outer, b""),
            ["Mark", "Other"],
        )
        self.assertEqual(
            self.tree._collect_node_modifiers(outer, b""),
            ["public"],
        )
        self.assertEqual(
            self.tree._collect_node_annotations(FakeNode("class_declaration"), b""),
            [],
        )
        self.assertEqual(
            self.tree._collect_node_modifiers(FakeNode("class_declaration"), b""),
            [],
        )

        unnamed = FakeNode("annotation_type_declaration", start_row=1)
        with patch.object(
            self.tree.helper,
            "_extract_leading_annotations",
            return_value=["Leading"],
        ) as leading:
            self.tree.helper.package_name = ""
            self.assertEqual(
                self.tree._build_class_context([unnamed], b"", ["@Leading\n"]),
                ("Unknown", "Unknown", ["Leading"], True),
            )
        leading.assert_called_once_with(["@Leading\n"], 1)
        self.tree.helper.package_name = "com.acme"

        valid_declarator = FakeNode(
            "variable_declarator",
            fields={"name": FakeNode("identifier", "orders")},
        )
        nameless_declarator = FakeNode("variable_declarator")
        blank_declarator = FakeNode(
            "variable_declarator",
            fields={"name": FakeNode("identifier", "")},
        )
        field = FakeNode(
            "field_declaration",
            fields={"type": FakeNode("generic_type", "java.util.List<Order>")},
            children=[
                FakeNode("modifiers", "private"),
                valid_declarator,
                nameless_declarator,
                blank_declarator,
            ],
        )
        no_type = FakeNode("field_declaration", children=[valid_declarator])
        blank_type = FakeNode(
            "field_declaration",
            fields={"type": FakeNode("type_identifier", "")},
            children=[valid_declarator],
        )
        self.tree._merge_ast_field_types(
            FakeNode("program", children=[FakeNode("comment"), no_type, blank_type, field]),
            b"",
        )
        self.assertEqual(self.tree.helper.field_types["orders"], "java.util.List")
        self.assertEqual(
            self.tree.helper.field_declared_types["orders"],
            "java.util.List<Order>",
        )

        superclass = FakeNode("superclass", children=[
            FakeNode("type_identifier", "Base"),
            FakeNode("type_identifier", ""),
            FakeNode("type_identifier", "<Unresolvable>"),
        ])
        interfaces = FakeNode("interfaces", children=[
            FakeNode("type_identifier", "Api"),
            FakeNode("type_identifier", "Api"),
        ])
        extra_extends = FakeNode("extends_interfaces", children=[
            FakeNode("type_identifier", "ParentApi"),
        ])
        declaration = FakeNode(
            "class_declaration",
            fields={
                "name": FakeNode("identifier", "Sample"),
                "superclass": superclass,
                "interfaces": interfaces,
            },
            children=[superclass, interfaces, extra_extends],
        )
        metadata = self.tree._collect_type_metadata(
            FakeNode("program", children=[FakeNode("comment"), declaration]),
            b"",
            [],
        )
        self.assertEqual(
            metadata,
            {
                "com.acme.Sample": {
                    "extends": ["com.acme.Base", "com.acme.ParentApi"],
                    "implements": ["com.acme.Api"],
                },
            },
        )

        ast_root = FakeNode("program", children=[
            FakeNode("ERROR"),
            FakeNode("method_declaration"),
            FakeNode("constructor_declaration"),
        ])
        self.assertEqual(self.tree._count_error_nodes(ast_root), 1)
        self.assertEqual(
            [node.type for node in self.tree._walk_ast(ast_root)],
            ["program", "ERROR", "method_declaration", "constructor_declaration"],
        )
        with patch.object(
            self.tree,
            "_parse_method_node",
            side_effect=[None, "constructor"],
        ):
            self.assertEqual(
                self.tree._extract_methods_from_ast(ast_root, b"", []),
                ["constructor"],
            )

        raw_tree = object.__new__(analyzer.TreeSitterAnalyzer)
        name = FakeNode("identifier", start_byte=1, end_byte=4)
        owner = FakeNode("method_declaration", fields={"name": name})
        self.assertEqual(raw_tree._field_text(owner, "name", b"_abc_"), "abc")
        self.assertIsNone(raw_tree._field_text(owner, "missing", b"_abc_"))

    def test_ast_parameter_and_local_declaration_boundaries_fail_closed(self):
        self.assertEqual(self.tree._parse_params(None, b""), ({}, {}))

        dimensions = FakeNode("dimensions", children=[
            FakeNode("marker_annotation", "@Dim"),
            FakeNode("[", "["),
            FakeNode("]", "]"),
            FakeNode("[", "["),
            FakeNode("]", "]"),
        ])
        formal = FakeNode(
            "formal_parameter",
            fields={
                "type": FakeNode("type_identifier", "String"),
                "name": FakeNode("identifier", "values"),
            },
            children=[dimensions],
        )
        structural_spread_name = FakeNode(
            "variable_declarator",
            fields={"name": FakeNode("identifier", "orders")},
        )
        structural_spread = FakeNode(
            "spread_parameter",
            children=[
                FakeNode("modifiers", "@Mark final"),
                FakeNode("generic_type", "java.util.List<Order>"),
                FakeNode("...", "..."),
                structural_spread_name,
            ],
        )
        fielded_spread = FakeNode(
            "spread_parameter",
            fields={
                "type": FakeNode("type_identifier", "Order"),
                "name": FakeNode("identifier", "moreOrders"),
            },
        )
        spread_without_declarator = FakeNode(
            "spread_parameter",
            children=[FakeNode("type_identifier", "Order"), FakeNode("...", "...")],
        )
        spread_without_type_candidate = FakeNode(
            "spread_parameter",
            fields={"name": FakeNode("identifier", "missingSpreadType")},
            children=[FakeNode("modifiers", "final"), FakeNode("...", "...")],
        )
        empty_dimensions = FakeNode("dimensions")
        empty_dimension_formal = FakeNode(
            "formal_parameter",
            fields={
                "type": FakeNode("type_identifier", "Order"),
                "name": FakeNode("identifier", "plainOrder"),
            },
            children=[empty_dimensions],
        )
        missing_type = FakeNode(
            "formal_parameter",
            fields={"name": FakeNode("identifier", "missingType")},
        )
        missing_name = FakeNode(
            "formal_parameter",
            fields={"type": FakeNode("type_identifier", "Order")},
        )
        blank_name = FakeNode(
            "formal_parameter",
            fields={
                "type": FakeNode("type_identifier", "Order"),
                "name": FakeNode("identifier", ""),
            },
        )
        blank_type = FakeNode(
            "formal_parameter",
            fields={
                "type": FakeNode("type_identifier", ""),
                "name": FakeNode("identifier", "blankType"),
            },
        )
        receiver = FakeNode("receiver_parameter", "Sample this")
        params = FakeNode("formal_parameters", children=[
            FakeNode("(", "("), formal, FakeNode(",", ","),
            structural_spread, fielded_spread, spread_without_declarator,
            spread_without_type_candidate,
            empty_dimension_formal, missing_type, missing_name, blank_name, blank_type,
            receiver, FakeNode(")", ")"),
        ])
        self.assertEqual(
            self.tree._parse_params(params, b""),
            (
                {
                    "values": "java.lang.String[][]",
                    "orders": "java.util.List[]",
                    "moreOrders": "com.acme.model.Order[]",
                    "plainOrder": "com.acme.model.Order",
                },
                {
                    "values": "String[][]",
                    "orders": "java.util.List<Order>...",
                    "moreOrders": "Order...",
                    "plainOrder": "Order",
                },
            ),
        )

        explicit_type = FakeNode("type_identifier", "Order")
        first = FakeNode(
            "variable_declarator",
            fields={"name": FakeNode("identifier", "first")},
        )
        second = FakeNode(
            "variable_declarator",
            fields={
                "name": FakeNode("identifier", "second"),
                "value": FakeNode("object_creation_expression", "new Order()", fields={
                    "type": FakeNode("type_identifier", "Order"),
                }),
            },
        )
        explicit = FakeNode(
            "local_variable_declaration",
            fields={"type": explicit_type},
            children=[explicit_type, first, FakeNode(",", ","), second],
        )
        var_type = FakeNode("type_identifier", "var")
        inferred = FakeNode(
            "variable_declarator",
            fields={
                "name": FakeNode("identifier", "inferred"),
                "value": FakeNode("object_creation_expression", "new Order()", fields={
                    "type": FakeNode("type_identifier", "Order"),
                }),
            },
        )
        unresolved = FakeNode(
            "variable_declarator",
            fields={"name": FakeNode("identifier", "unresolved")},
        )
        inferred_declaration = FakeNode(
            "local_variable_declaration",
            fields={"type": var_type},
            children=[var_type, inferred, unresolved],
        )
        malformed = [
            FakeNode("local_variable_declaration"),
            FakeNode(
                "local_variable_declaration",
                fields={"type": FakeNode("type_identifier", "Order")},
            ),
            FakeNode(
                "local_variable_declaration",
                fields={"type": FakeNode("type_identifier", "Order")},
                children=[FakeNode("variable_declarator")],
            ),
            FakeNode(
                "local_variable_declaration",
                fields={"type": FakeNode("type_identifier", "Order")},
                children=[FakeNode(
                    "variable_declarator",
                    fields={"name": FakeNode("identifier", "")},
                )],
            ),
        ]
        local_types, sites = self.tree._collect_local_variable_types(
            FakeNode("block", children=[FakeNode("statement"), explicit, inferred_declaration, *malformed]),
            b"",
            self.definition,
        )
        self.assertEqual(
            local_types,
            {
                "first": "com.acme.model.Order",
                "second": "com.acme.model.Order",
                "inferred": "com.acme.model.Order",
            },
        )
        self.assertEqual(
            [(site["name"], site["initializer_expr"], site["resolved_declared_type"]) for site in sites],
            [
                ("first", "", "com.acme.model.Order"),
                ("second", "new Order()", "com.acme.model.Order"),
                ("inferred", "new Order()", "com.acme.model.Order"),
                ("unresolved", "", ""),
            ],
        )

    def test_ast_call_site_collection_preserves_lexical_scope_and_rejects_malformed_sites(self):
        definition = method_def(
            imports={"Order": "com.acme.model.Order"},
            param_types={"input": "com.acme.Input"},
            param_declared_types={"input": "Input"},
            ast_local_var_sites=[
                {"name": "known", "declared_type": "Order"},
                {"name": "resolved", "resolved_declared_type": "com.acme.Resolved"},
                {"name": ""},
            ],
        )

        matched_call = FakeNode(
            "method_invocation",
            "matched.run()",
            fields={
                "object": FakeNode("identifier", "matched"),
                "name": FakeNode("identifier", "run"),
            },
            start_row=4,
        )
        switch_rule = FakeNode("switch_rule", children=[
            FakeNode("type_pattern", children=[
                FakeNode("type_identifier", "Order"),
                FakeNode("token", "when"),
                FakeNode("identifier", "matched"),
            ]),
            FakeNode("type_pattern", children=[FakeNode("identifier", "incomplete")]),
            FakeNode("type_pattern", children=[
                FakeNode("type_identifier", ""),
                FakeNode("identifier", "blankType"),
            ]),
            FakeNode("type_pattern", children=[
                FakeNode("type_identifier", "Order"),
                FakeNode("identifier", ""),
            ]),
            matched_call,
        ])

        lambda_call = FakeNode(
            "method_invocation",
            "item.run()",
            fields={
                "object": FakeNode("identifier", "item"),
                "name": FakeNode("identifier", "run"),
            },
            start_row=6,
        )
        lambda_body = FakeNode("expression", children=[lambda_call])
        typed_lambda = FakeNode(
            "lambda_expression",
            fields={
                "parameters": FakeNode("formal_parameter", fields={
                    "type": FakeNode("type_identifier", "Order"),
                    "name": FakeNode("identifier", "item"),
                }),
                "body": lambda_body,
            },
        )
        bodyless_lambda = FakeNode(
            "lambda_expression",
            fields={"parameters": FakeNode("identifier", "ignored")},
        )

        direct_call = FakeNode(
            "method_invocation",
            'consume("x", input)',
            fields={
                "name": FakeNode("identifier", "consume"),
                "arguments": FakeNode("argument_list", children=[
                    FakeNode("(", "("), FakeNode("string_literal", '"x"'),
                    FakeNode(",", ","), FakeNode("identifier", "input"),
                    FakeNode(")", ")"),
                ]),
            },
            start_row=8,
        )
        nameless_call = FakeNode(
            "method_invocation",
            "invalid()",
            fields={"arguments": FakeNode("argument_list")},
        )
        method_reference = FakeNode("method_reference", "Order::new", start_row=9)
        invalid_reference = FakeNode("method_reference", "Order.new", start_row=10)
        constructor = FakeNode(
            "object_creation_expression",
            "new Order(input)",
            fields={
                "type": FakeNode("type_identifier", "Order"),
                "arguments": FakeNode("argument_list", children=[
                    FakeNode("(", "("), FakeNode("identifier", "input"),
                    FakeNode(")", ")"),
                ]),
            },
            start_row=11,
        )
        missing_constructor_type = FakeNode("object_creation_expression", "new ()")
        no_argument_constructor = FakeNode(
            "object_creation_expression",
            "new Order()",
            fields={"type": FakeNode("type_identifier", "Order")},
            start_row=11,
        )
        blank_constructor_type = FakeNode(
            "object_creation_expression",
            "new ()",
            fields={"type": FakeNode("type_identifier", "")},
        )
        delegate_this = FakeNode(
            "explicit_constructor_invocation",
            "this(input);",
            fields={
                "constructor": FakeNode("this", "this"),
                "arguments": FakeNode("argument_list", children=[
                    FakeNode("(", "("), FakeNode("identifier", "input"),
                    FakeNode(")", ")"),
                ]),
            },
            start_row=12,
        )
        delegate_super = FakeNode(
            "explicit_constructor_invocation",
            "super();",
            fields={"constructor": FakeNode("super", "super")},
            start_row=13,
        )
        invalid_delegate = FakeNode(
            "explicit_constructor_invocation",
            "other();",
            fields={"constructor": FakeNode("identifier", "other")},
        )
        missing_delegate = FakeNode("explicit_constructor_invocation", "();")

        sites = self.tree._collect_call_sites(
            FakeNode("block", children=[
                switch_rule, typed_lambda, bodyless_lambda,
                direct_call, nameless_call, method_reference, invalid_reference,
                constructor, no_argument_constructor,
                missing_constructor_type, blank_constructor_type,
                delegate_this, delegate_super, invalid_delegate, missing_delegate,
            ]),
            b"",
            definition,
            {"local": "com.acme.Local"},
        )
        self.assertEqual(
            [site["kind"] for site in sites],
            [
                "method_invocation", "method_invocation", "method_invocation",
                "method_reference", "constructor_invocation", "constructor_invocation",
                "constructor_delegation", "constructor_delegation",
            ],
        )
        by_content = {site["content"]: site for site in sites}
        self.assertEqual(
            by_content["matched.run()"]["scope_local_var_types"]["matched"],
            "com.acme.model.Order",
        )
        self.assertEqual(
            by_content["item.run()"]["scope_local_var_types"]["item"],
            "com.acme.model.Order",
        )
        self.assertEqual(
            by_content['consume("x", input)']["arg_exprs"],
            ['"x"', "input"],
        )
        self.assertEqual(by_content["Order::new"]["method_name"], "new")
        self.assertEqual(by_content["new Order(input)"]["receiver_type"], "com.acme.model.Order")
        self.assertEqual(by_content["this(input);"]["arg_exprs"], ["input"])
        self.assertEqual(by_content["super();"]["arg_exprs"], [])
        self.assertNotIn("new ()", by_content)

    def test_ast_type_reference_collection_excludes_instance_qualifiers_and_nested_methods(self):
        class_type = FakeNode("type_identifier", "Order")
        class_literal = FakeNode(
            "class_literal",
            fields={},
            children=[class_type],
            start_row=1,
        )
        duplicate_class_literal = FakeNode(
            "class_literal",
            children=[FakeNode("type_identifier", "Order")],
            start_row=1,
        )
        no_class_type = FakeNode(
            "class_literal",
            children=[FakeNode("identifier", "missing")],
            start_row=2,
        )
        instanceof = FakeNode(
            "instanceof_expression",
            fields={"right": FakeNode("type_identifier", "Input")},
            start_row=3,
        )
        missing_instanceof = FakeNode("instanceof_expression", start_row=4)
        blank_cast = FakeNode(
            "cast_expression",
            fields={"type": FakeNode("type_identifier", "")},
            start_row=4,
        )
        cast = FakeNode(
            "cast_expression",
            fields={"type": FakeNode("type_identifier", "Order")},
            start_row=5,
        )
        creation = FakeNode(
            "object_creation_expression",
            fields={"type": FakeNode("type_identifier", "Order")},
            start_row=6,
        )
        static_field = FakeNode(
            "field_access",
            "Order.CODE",
            fields={"object": FakeNode("identifier", "Order")},
            start_row=7,
        )
        qualified_static_field = FakeNode(
            "field_access",
            "java.lang.Integer.MAX_VALUE",
            fields={"object": FakeNode("field_access", "java.lang.Integer")},
            start_row=8,
        )
        instance_field = FakeNode(
            "field_access",
            "input.value",
            fields={"object": FakeNode("identifier", "input")},
            start_row=9,
        )
        unsupported_field_object = FakeNode(
            "field_access",
            "call().value",
            fields={"object": FakeNode("method_invocation", "call()")},
            start_row=10,
        )
        missing_field_object = FakeNode("field_access", "<missing>.value", start_row=10)
        annotation = FakeNode("marker_annotation", "@pkg.Mark", start_row=11)
        duplicate_annotation = FakeNode("annotation", "@pkg.Mark(value=1)", start_row=11)
        invalid_annotation = FakeNode("annotation", "@123", start_row=12)
        nested_method = FakeNode(
            "method_declaration",
            children=[FakeNode(
                "object_creation_expression",
                fields={"type": FakeNode("type_identifier", "Hidden")},
                start_row=13,
            )],
        )
        method = FakeNode("method_declaration", children=[
            class_literal, duplicate_class_literal, no_class_type,
            instanceof, missing_instanceof, blank_cast, cast, creation,
            static_field, qualified_static_field, instance_field,
            unsupported_field_object, missing_field_object,
            annotation, duplicate_annotation,
            invalid_annotation, nested_method,
        ])

        sites = self.tree._collect_type_reference_sites(method, b"")
        self.assertEqual(
            {(site["kind"], site["declared_type"], site["line"]) for site in sites},
            {
                ("class_literal_type", "Order", 2),
                ("instanceof_type", "Input", 4),
                ("cast_type", "Order", 6),
                ("constructor_type", "Order", 7),
                ("static_qualified_type", "Order", 8),
                ("static_qualified_type", "java.lang.Integer", 9),
                ("annotation_type", "pkg.Mark", 12),
            },
        )
        self.assertFalse(any(site["declared_type"] == "input" for site in sites))
        self.assertFalse(any(site["declared_type"] == "Hidden" for site in sites))

    @unittest.skipUnless(
        analyzer.TREE_SITTER_AVAILABLE, "requires the tree-sitter Java parser",
    )
    def test_real_java_ast_preserves_descriptor_parameters_and_all_local_declarators(self):
        from binary_source_overlay import source_method_descriptor

        source_text = """package p;
@interface Dim {}
@interface Mark { int[] value(); }
class Order {}
class Sample {
  void work(
      Sample this,
      Order first,
      String value @Dim [],
      @Mark(value={1, 2}) final java.util.List<Order>... rest) {
    Order left = new Order(), right = new Order();
    left.toString();
    right.toString();
  }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_text(source_text, encoding="utf-8")
            methods, diagnostics = analyzer.analyze_file(
                str(source),
                {"root": temporary, "module": "root"},
                return_diagnostics=True,
            )

        self.assertEqual(diagnostics["actual_parser"], "tree_sitter")
        work = next(method for method in methods if method.qualified_key == "p.Sample.work")
        self.assertEqual(
            work.param_declared_types,
            {
                "first": "Order",
                "value": "String[]",
                "rest": "java.util.List<Order>...",
            },
        )
        self.assertNotIn("this", work.param_declared_types)
        self.assertEqual(work.param_types["value"], "java.lang.String[]")
        self.assertEqual(work.param_types["rest"], "java.util.List[]")
        self.assertEqual(work.local_var_types, {"left": "p.Order", "right": "p.Order"})
        self.assertEqual(
            [site["name"] for site in work.ast_local_var_sites],
            ["left", "right"],
        )
        invocation_scopes = {
            site["receiver_expr"]: site["scope_local_var_types"]
            for site in work.ast_call_sites
            if site["kind"] == "method_invocation"
        }
        self.assertEqual(invocation_scopes["right"]["right"], "p.Order")
        work.known_classes_by_simple = {"Order": "p.Order"}
        self.assertEqual(
            source_method_descriptor(work),
            "(Lp/Order;[Ljava/lang/String;[Ljava/util/List;)V",
        )

    @unittest.skipUnless(
        analyzer.TREE_SITTER_AVAILABLE, "requires the tree-sitter Java parser",
    )
    def test_real_java_ast_covers_all_explicit_method_like_declarations(self):
        from binary_source_overlay import source_method_descriptor

        source_text = """package p;
import java.io.IOException;
@interface Meta {
  String value() default "x";
  int count();
}
interface Parent {}
interface Api extends Parent {
  String run(int value) throws IOException;
}
class Base {}
enum State { ON; void toggle() {} }
record Rec(String value, int count) {
  Rec { if (value == null) throw new IllegalArgumentException(); }
  Rec(String value) { this(value, 0); }
}
@Meta(value="outer", count=1)
class Outer extends Base implements Api {
  @Meta(value="inner", count=2)
  class Inner { Inner() {} }
  @Override public String run(int value) throws IOException { return ""; }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Declarations.java"
            source.write_text(source_text, encoding="utf-8")
            methods, diagnostics = analyzer.analyze_file(
                str(source),
                {
                    "root": temporary,
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "declarations",
                },
                return_diagnostics=True,
            )

        self.assertEqual(diagnostics["actual_parser"], "tree_sitter")
        self.assertEqual(diagnostics["error_nodes"], 0)
        by_key = {}
        for method in methods:
            by_key.setdefault(method.qualified_key, []).append(method)
        self.assertTrue({
            "p.Meta.value", "p.Meta.count", "p.Api.run", "p.State.toggle",
            "p.Rec.Rec", "p.Outer.Inner.Inner", "p.Outer.run",
        }.issubset(by_key))

        annotation_value = by_key["p.Meta.value"][0]
        self.assertTrue(annotation_value.is_interface)
        self.assertEqual(annotation_value.return_declared_type, "String")
        self.assertEqual(annotation_value.param_declared_types, {})
        interface_run = by_key["p.Api.run"][0]
        self.assertTrue(interface_run.is_interface)
        self.assertEqual(interface_run.throws_declared_types, ["IOException"])
        self.assertEqual(interface_run.ast_call_sites, [])

        constructors = by_key["p.Rec.Rec"]
        self.assertEqual(len(constructors), 2)
        descriptors = {source_method_descriptor(item) for item in constructors}
        self.assertEqual(
            descriptors,
            {"(Ljava/lang/String;I)V", "(Ljava/lang/String;)V"},
        )
        compact = next(item for item in constructors if len(item.param_declared_types) == 2)
        self.assertEqual(
            compact.param_declared_types,
            {"value": "String", "count": "int"},
        )
        delegated = next(item for item in constructors if len(item.param_declared_types) == 1)
        self.assertTrue(any(
            site["kind"] == "constructor_delegation"
            and site["receiver_expr"] == "this"
            and site["arg_exprs"] == ["value", "0"]
            for site in delegated.ast_call_sites
        ))

        inner_constructor = by_key["p.Outer.Inner.Inner"][0]
        self.assertEqual(inner_constructor.class_annotations, ["Meta"])
        outer_run = by_key["p.Outer.run"][0]
        self.assertEqual(outer_run.annotations, ["Override"])
        self.assertIn("public", outer_run.modifiers)
        self.assertEqual(outer_run.throws_declared_types, ["IOException"])
        self.assertEqual(
            outer_run.known_type_metadata["p.Outer"],
            {"extends": ["p.Base"], "implements": ["p.Api"]},
        )
        self.assertEqual(
            outer_run.known_type_metadata["p.Api"],
            {"extends": ["p.Parent"], "implements": []},
        )

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "DefaultPackage.java"
            source.write_text("class DefaultPackage { void run() {} }", encoding="utf-8")
            default_methods = analyzer.analyze_file(
                str(source), {"root": temporary, "module": "root"},
            )
        self.assertEqual(default_methods[0].class_fqcn, "DefaultPackage")

    @unittest.skipUnless(
        analyzer.TREE_SITTER_AVAILABLE, "requires the tree-sitter Java parser",
    )
    def test_real_java_ast_covers_scoped_locals_lambdas_types_and_calls(self):
        source_text = """package com.acme;
import java.util.List;
@interface Mark {}
class Base { Base() {} void parent() {} }
class Order { void run() {} static void staticCall() {} }
class Input { void run() {} }
@Mark
public class Sample extends Base {
  private List<Order> orders;
  public Sample() { super(); }
  private Order create(Input input) { return new Order(); }
  @Mark public void work(Input input) {
    var inferred = new Order();
    var created = create(input);
    orders.stream().map(order -> order.toString()).forEach(System.out::println);
    super.parent();
    Order.staticCall();
    inferred.run();
    if (input instanceof Input) { ((Input) input).run(); }
    switch (input) { case Input matched -> matched.run(); default -> {} }
  }
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Sample.java"
            source.write_text(source_text, encoding="utf-8")
            methods, diagnostics = analyzer.analyze_file(
                str(source),
                {
                    "root": temporary,
                    "owner_type": "business",
                    "owner_coord": "BUSINESS",
                    "module": "root",
                },
                return_diagnostics=True,
            )

        self.assertEqual(diagnostics["actual_parser"], "tree_sitter")
        work = next(
            method for method in methods
            if method.qualified_key == "com.acme.Sample.work"
        )
        self.assertEqual(work.local_var_types["inferred"], "com.acme.Order")
        self.assertTrue({
            "constructor_type", "instanceof_type", "cast_type",
            "annotation_type",
        }.issubset({site["kind"] for site in work.ast_type_reference_sites}))
        targets = {
            edge.callee_key
            for edge in analyzer.extract_call_edges_enhanced(work)
        }
        self.assertIn("com.acme.Base.parent()", targets)
        self.assertIn("com.acme.Order.staticCall()", targets)
        self.assertIn("com.acme.Order.run()", targets)


class DiagnosticEntrypointContractTest(unittest.TestCase):
    def test_test_analyzer_and_cli_report_the_analyzer_result(self):
        sample = method_def(method_name="one", qualified_key="com.acme.Sample.one")
        stdout = io.StringIO()
        with patch.object(analyzer, "analyze_file", return_value=[sample]) as analyze, patch.object(
            analyzer.sys, "stdout", stdout,
        ):
            result = analyzer.test_analyzer("Sample.java")
        self.assertEqual(result, [sample])
        analyze.assert_called_once()
        self.assertIn("识别方法数：1", stdout.getvalue())
        self.assertIn("com.acme.Sample.one", stdout.getvalue())

        with patch.object(analyzer, "test_analyzer", return_value=[]) as test_entry, patch.object(
            analyzer.sys, "argv", ["enhanced_source_analyzer.py", "--file", "Sample.java"],
        ):
            self.assertEqual(analyzer.main(), 0)
        test_entry.assert_called_once_with("Sample.java")


if __name__ == "__main__":
    unittest.main()
