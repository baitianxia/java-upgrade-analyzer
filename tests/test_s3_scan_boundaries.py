import csv
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s3_scan as scan  # noqa: E402


def jar_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


class Step3ScanBoundaryTest(unittest.TestCase):
    def setUp(self):
        scan.reset_scan_diagnostics()

    @staticmethod
    def _class_header(major):
        return b"\xca\xfe\xba\xbe\x00\x00" + int(major).to_bytes(2, "big")

    @staticmethod
    def _csv_rows(path):
        with Path(path).open(encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_orchestrated_input_and_dependency_source_shape_matrix(self):
        self.assertEqual(scan.normalize_dependency_source_dirs(None), [])
        self.assertEqual(scan.normalize_dependency_source_dirs("/one"), [])
        self.assertEqual(
            scan.get_scan_diagnostics()[-1]["stage"],
            "dependency_source_dirs_input",
        )
        scan.reset_scan_diagnostics()
        self.assertEqual(
            scan.normalize_dependency_source_dirs([
                " /one ", Path("/two"), "", 3, None,
            ]),
            [" /one ", "/two"],
        )

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(scan.load_orchestrated_step3_input("/missing"), ({}, {}))

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            state_path = scan.runtime_state_path(report)
            context_path = scan.context_path(report)
            state_path.parent.mkdir(parents=True)
            context_path.parent.mkdir(parents=True)

            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}, clear=False):
                self.assertEqual(scan.load_orchestrated_step3_input(report), ({}, {}))

                state_path.write_text("[]", encoding="utf-8")
                context_path.write_text("[]", encoding="utf-8")
                self.assertEqual(scan.load_orchestrated_step3_input(report), ({}, {}))
                self.assertEqual(len(scan.get_scan_diagnostics()), 2)

                scan.reset_scan_diagnostics()
                state_path.write_text(
                    json.dumps({"step3": ["bad"]}), encoding="utf-8",
                )
                context_path.write_text("{}", encoding="utf-8")
                self.assertEqual(scan.load_orchestrated_step3_input(report), ({}, {}))
                self.assertEqual(scan.get_scan_diagnostics()[0]["stage"], "orchestrated_state_load")

                scan.reset_scan_diagnostics()
                state_path.write_text(
                    json.dumps({"step3": {"input": ["bad"]}}), encoding="utf-8",
                )
                self.assertEqual(scan.load_orchestrated_step3_input(report), ({}, {}))

                scan.reset_scan_diagnostics()
                state_path.write_text(
                    json.dumps({"step3": {"input": {"source_dirs": ["src"]}}}),
                    encoding="utf-8",
                )
                context_path.write_text(
                    json.dumps({"jdk_current": "17"}), encoding="utf-8",
                )
                self.assertEqual(
                    scan.load_orchestrated_step3_input(report),
                    ({"source_dirs": ["src"]}, {"jdk_current": "17"}),
                )

                state_path.write_text("{", encoding="utf-8")
                context_path.write_text("{", encoding="utf-8")
                self.assertEqual(scan.load_orchestrated_step3_input(report), ({}, {}))

    def test_source_root_walk_and_pattern_scan_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            main = root / "src" / "main" / "java"
            test = root / "src" / "test" / "java"
            integration = root / "src" / "integrationTest" / "java"
            skipped = root / "target"
            for directory in (main, test, integration, skipped):
                directory.mkdir(parents=True)
            (main / "App.java").write_text(
                "// HIT\n* HIT\n/* HIT\nclass App { String x = \"HIT\"; }\nHIT again\n",
                encoding="utf-8",
            )
            (main / "App.txt").write_text("HIT\n", encoding="utf-8")
            (main / "WorkerIT.java").write_text("HIT\n", encoding="utf-8")
            (main / "WorkerTests.java").write_text("HIT\n", encoding="utf-8")
            (main / "Test.java").write_text("HIT\n", encoding="utf-8")
            (test / "Unit.java").write_text("HIT\n", encoding="utf-8")
            (integration / "IT.java").write_text("HIT\n", encoding="utf-8")
            (skipped / "Generated.java").write_text("HIT\n", encoding="utf-8")

            roots = list(scan.iter_source_roots([
                None, "", root / "missing", root, str(root),
            ]))
            self.assertEqual(roots, [os.path.abspath(str(root))])
            self.assertEqual(list(scan.iter_source_roots(root)), roots)

            all_java = list(scan.walk_files(root, {".java"}))
            self.assertTrue(any(path.endswith("Unit.java") for path in all_java))
            self.assertFalse(any("target" in path for path in all_java))
            production = list(scan.walk_files(root, {".java"}, skip_test=True))
            self.assertEqual([Path(path).name for path in production], ["App.java"])

            self.assertEqual(scan.scan_pattern(root, "["), [])
            hits = scan.scan_pattern(root, "HIT", max_per_file=1)
            self.assertTrue(hits)
            self.assertEqual(
                len([row for row in hits if row[0].endswith("App.java")]), 1,
            )
            unfiltered = scan.scan_pattern(
                root, "HIT", skip_comment=False, skip_test=True,
            )
            self.assertGreaterEqual(len(unfiltered), 5)

            scan.reset_scan_diagnostics()
            with patch.object(scan, "walk_files", return_value=[str(main / "App.java")]), patch.object(
                scan, "open_text", side_effect=OSError("unreadable"),
            ):
                self.assertEqual(scan.scan_pattern(root, "HIT"), [])
            self.assertEqual(scan.get_scan_diagnostics()[0]["stage"], "source_pattern_scan")

    def test_dependency_csv_loading_and_version_matrix(self):
        self.assertIsNone(scan.resolve_dep_version({"old_version": "-", "new_version": "-"}))
        self.assertEqual(scan.resolve_dep_version({"old_version": "1", "new_version": "2"}), "2")
        self.assertEqual(scan.resolve_dep_version({"old_version": "1", "new_version": "-"}), "1")
        self.assertIsNone(scan.resolve_current_dep_version({"new_version": None}))
        self.assertIsNone(scan.resolve_current_dep_version({"new_version": "-"}))
        self.assertEqual(scan.resolve_current_dep_version({"new_version": " 2 "}), "2")
        self.assertEqual(scan.load_dep_changes(None), [])
        self.assertEqual(scan.load_dep_changes("/missing"), [])
        self.assertEqual(scan.load_current_deps("/missing"), [])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changes = root / "changes.csv"
            changes.write_text(
                "coord,old_version,new_version,scope,resolution_status,change_type\n"
                "g:skip,1,2,compile,unresolved,upgraded\n"
                ",1,2,compile,resolved,upgraded\n"
                "g:ok,1,2,,resolved,upgraded\n"
                "g:removed,1,-,test,resolved,removed\n",
                encoding="utf-8",
            )
            dep_rows = scan.load_dep_changes(changes)
            self.assertEqual([row["coord"] for row in dep_rows], ["g:ok", "g:removed"])
            current = scan.load_current_deps(changes)
            self.assertEqual([row["coord"] for row in current], ["g:ok"])
            self.assertEqual(current[0]["scope"], "compile")

            ledger = root / "current.csv"
            ledger.write_text(
                "coord,version,scope,lib_entry,entry_id\n"
                ",,,BOOT-INF/lib/physical.jar,\n"
                "g:no-version,,, ,\n"
                "g:ok,3,runtime,,entry.jar\n",
                encoding="utf-8",
            )
            current = scan.load_current_deps(ledger)
            self.assertEqual(len(current), 2)
            self.assertEqual(current[0]["lib_entry"], "BOOT-INF/lib/physical.jar")
            self.assertEqual(current[1]["coord"], "g:ok")

            unknown = root / "unknown.csv"
            unknown.write_text("coord,scope\ng:x,compile\n", encoding="utf-8")
            self.assertEqual(scan.load_current_deps(unknown), [])

            scan.reset_scan_diagnostics()
            with patch.object(scan, "open_csv_read", side_effect=OSError("bad")):
                self.assertEqual(scan.load_dep_changes(changes), [])
                self.assertEqual(scan.load_current_deps(changes), [])
            self.assertEqual(len(scan.get_scan_diagnostics()), 2)

    def test_provenance_resolution_and_artifact_dependency_iteration_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            report.mkdir()
            dep_list = report / "deps.csv"
            dep_list.write_text("coord,version\n", encoding="utf-8")

            with patch.object(scan, "STEP3_REPORT_DIR", ""):
                candidates = list(scan._step3_build_provenance_candidates(dep_list))
                self.assertEqual(
                    candidates,
                    [(report / "build_provenance.json").resolve()],
                )
                self.assertEqual(list(scan._step3_build_provenance_candidates(None)), [])
            with patch.object(scan, "STEP3_REPORT_DIR", str(report)):
                candidates = list(scan._step3_build_provenance_candidates(dep_list))
            self.assertEqual(len(candidates), len(set(map(str, candidates))))

            with patch.object(scan, "STEP3_REPORT_DIR", ""):
                self.assertEqual(
                    scan.resolve_current_final_artifact_path(dep_list)[1],
                    "current_final_artifact_provenance_missing",
                )

            provenance = report / "build_provenance.json"
            for payload in ([], {"sides": {}}, {"sides": ["bad"]}):
                provenance.write_text(json.dumps(payload), encoding="utf-8")
                scan.reset_scan_diagnostics()
                path, reason = scan.resolve_current_final_artifact_path(dep_list)
                self.assertEqual(path, "")
                self.assertEqual(reason, "current_final_artifact_provenance_unreadable")
                self.assertEqual(
                    scan.get_scan_diagnostics()[0]["stage"],
                    "current_final_artifact_provenance_load",
                )

            provenance.write_text(json.dumps({"sides": []}), encoding="utf-8")
            self.assertEqual(
                scan.resolve_current_final_artifact_path(dep_list),
                ("", "current_final_artifact_missing"),
            )
            missing_artifact = root / "missing.jar"
            provenance.write_text(json.dumps({
                "sides": [{"side": "current", "artifact_path": str(missing_artifact)}],
            }), encoding="utf-8")
            self.assertEqual(
                scan.resolve_current_final_artifact_path(dep_list),
                (str(missing_artifact), "current_final_artifact_missing"),
            )

            nested = jar_bytes({"X.class": b"class"})
            artifact = root / "app.jar"
            artifact.write_bytes(jar_bytes({"lib/good.jar": nested}))
            provenance.write_text(json.dumps({
                "sides": [{"side": "base"}, {
                    "side": "current", "artifact_path": str(artifact),
                }],
            }), encoding="utf-8")
            resolved, reason = scan.resolve_current_final_artifact_path(dep_list)
            self.assertEqual(resolved, str(artifact.resolve()))
            self.assertEqual(reason, "")

            deps = [
                {"coord": "g:none"},
                {"coord": "g:missing", "lib_entry": "lib/missing.jar"},
                {"coord": "g:good", "lib_entry": "lib/good.jar"},
                {"coord": "g:dupe", "entry_id": "lib/good.jar"},
            ]
            with patch.object(scan, "load_current_deps", return_value=[]):
                self.assertEqual(list(scan.iter_current_final_artifact_dependencies(dep_list)), [])
            with patch.object(scan, "load_current_deps", return_value=deps), patch.object(
                scan,
                "resolve_current_final_artifact_path",
                return_value=("", "current_final_artifact_missing"),
            ):
                rows = list(scan.iter_current_final_artifact_dependencies(dep_list))
            self.assertEqual(len(rows), 4)

            with patch.object(scan, "load_current_deps", return_value=deps), patch.object(
                scan, "resolve_current_final_artifact_path", return_value=(str(artifact), ""),
            ):
                rows = list(scan.iter_current_final_artifact_dependencies(dep_list))
            self.assertEqual(
                [row["error_code"] for row in rows],
                ["dependency_artifact_entry_missing", "current_final_artifact_entry_missing", ""],
            )
            self.assertEqual(rows[-1]["jar_bytes"], nested)

            broken = root / "broken.jar"
            broken.write_bytes(b"not zip")
            with patch.object(scan, "load_current_deps", return_value=deps[:2]), patch.object(
                scan, "resolve_current_final_artifact_path", return_value=(str(broken), ""),
            ):
                rows = list(scan.iter_current_final_artifact_dependencies(dep_list))
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(
                row["error_code"] == "current_final_artifact_unreadable" for row in rows
            ))

    def test_candidate_helper_and_class_usage_matrix(self):
        for value, expected in (
            (None, "CHANGED"), ("", "CHANGED"), ("移除", "REMOVED"),
            ("removed", "REMOVED"), ("新增", "ADDED"), ("added", "ADDED"),
            ("小版本升级", "CHANGED"), ("custom", "custom"),
        ):
            self.assertEqual(scan._change_type_to_contract(value), expected)

        usage_cases = (
            ("a.xml", "anything", "resource_reference"),
            ("A.java", 'Class.forName("com.acme.Widget")', "reflection_string"),
            ("A.java", "import static com.acme.Widget.make;", "static_import"),
            ("A.java", "import com.acme.Widget;", "import_reference"),
            ("A.java", "new Widget()", "class_reference"),
            ("A.java", "Widget.class", "class_literal"),
            ("A.java", "Widget.CONSTANT", "qualified_reference"),
            ("A.java", "\"Widget\"", "string_reference"),
            ("A.java", "new Outer.Inner()", "class_reference"),
        )
        for file_path, line, expected_kind in usage_cases:
            fqcn = "com.acme.Outer$Inner" if "Inner" in line else "com.acme.Widget"
            simple = "Outer$Inner" if "Inner" in line else "Widget"
            self.assertEqual(
                scan._class_usage_match_kind(file_path, line, fqcn, simple)[0],
                expected_kind,
            )
        self.assertEqual(
            scan._class_usage_match_kind("A.java", None, "A", "A")[0],
            "string_reference",
        )

        full = {
            "coord": " g:a ", "old_version": " 1 ", "new_version": " - ",
            "change_type": "removed",
        }
        row = scan._candidate_row_from_hit(
            full, "com.acme.Widget", "A.java", 3, "new Widget(),value", "system_source",
        )
        self.assertEqual(row["severity"], "P1")
        self.assertEqual(row["content"], "new Widget(),value")
        sparse = scan._candidate_row_from_hit(
            {}, "Widget", "A.txt", 1, None, "dependency_with_source",
        )
        self.assertEqual(sparse["coord"], "")
        self.assertEqual(sparse["severity"], "P2")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.csv"
            scan._write_candidate_rows(path, None)
            self.assertEqual(scan.load_csv_rows(path), [])
            scan._write_candidate_rows(path, [row])
            self.assertEqual(scan.load_csv_rows(path)[0]["coord"], "g:a")

    def test_candidate_files_jar_names_ledger_and_token_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target").mkdir()
            (root / "target" / "Skip.java").write_text("x", encoding="utf-8")
            for name in (
                "A.java", "B.XML", "spring.factories", "AutoConfiguration.imports",
                "ignored.bin",
            ):
                (root / name).write_text("x", encoding="utf-8")
            files = {Path(path).name for path in scan._iter_candidate_scan_files(root)}
            self.assertEqual(
                files,
                {"A.java", "B.XML", "spring.factories", "AutoConfiguration.imports"},
            )

            self.assertEqual(scan._iter_jar_class_names(None), [])
            self.assertEqual(scan._iter_jar_class_names(b"bad"), [])
            archive = jar_bytes({
                "module-info.class": b"x",
                "p/package-info.class": b"x",
                "META-INF/versions/17/p/V.class": b"x",
                "p/A.class": b"x",
                "B.class": b"x",
                "p/readme.txt": b"x",
            })
            self.assertEqual(
                scan._iter_jar_class_names(archive), ["B", "p.A"],
            )
            self.assertEqual(scan._iter_jar_class_names(archive, max_classes=1), ["B"])

            report = root / "report"
            candidates = [
                report / scan.EVIDENCE_DIRNAME / "dependencies" / "deps_current_resolved.csv",
                report / "dependencies" / "deps_current_resolved.csv",
                report / "deps_current_resolved.csv",
            ]
            self.assertEqual(scan._current_dependency_ledger_path(""), "")
            for candidate in reversed(candidates):
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("coord,version\n", encoding="utf-8")
            self.assertEqual(
                scan._current_dependency_ledger_path(report),
                str(candidates[0].resolve()),
            )

            classes = ["Top"] + [f"p{i % 45}.Class{i % 125}" for i in range(140)]
            inputs = [
                {"dependency": {"coord": "other"}, "error_code": ""},
                {"dependency": {"coord": "g:a"}, "error_code": "failed"},
                {
                    "dependency": {
                        "coord": "g:a", "lib_entry": "lib/a.jar",
                    },
                    "error_code": "",
                    "jar_bytes": b"jar",
                },
            ]
            with patch.object(scan, "_current_dependency_ledger_path", return_value="ledger"), patch.object(
                scan, "iter_current_final_artifact_dependencies", return_value=inputs,
            ), patch.object(scan, "_iter_jar_class_names", return_value=classes):
                result = scan._build_coord_scan_tokens({"coord": " g:a "}, report)
            self.assertEqual(result["jar_path"], "lib/a.jar")
            self.assertLessEqual(len(result["package_prefixes"]), 40)
            self.assertLessEqual(len(result["simple_names"]), 120)
            self.assertIn("Top", result["simple_names"])
            with patch.object(scan, "_current_dependency_ledger_path", return_value=""):
                self.assertEqual(
                    scan._build_coord_scan_tokens({}, report)["class_names"], [],
                )

    def test_csv_scope_class_version_rule_and_database_contract_matrix(self):
        self.assertEqual(scan.load_csv_rows(None), [])
        self.assertEqual(scan.load_csv_rows("/missing"), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "rows.csv"
            path.write_text("a,b\n1,\n\n2,3\n", encoding="utf-8")
            self.assertEqual(scan.load_csv_rows(path), [{"a": "1", "b": ""}, {"a": "2", "b": "3"}])
            with patch.object(scan, "open_csv_read", side_effect=OSError("bad")):
                self.assertEqual(scan.load_csv_rows(path), [])

            old_scope = scan.DEP_COMPAT_INCLUDE_TEST_SCOPE
            try:
                scan.DEP_COMPAT_INCLUDE_TEST_SCOPE = False
                self.assertFalse(scan.should_scan_dep_scope(" TEST "))
                self.assertTrue(scan.should_scan_dep_scope(None))
                scan.DEP_COMPAT_INCLUDE_TEST_SCOPE = True
                self.assertTrue(scan.should_scan_dep_scope("test"))
            finally:
                scan.DEP_COMPAT_INCLUDE_TEST_SCOPE = old_scope

            self.assertIsNone(scan.parse_class_major_version(None))
            self.assertIsNone(scan.parse_class_major_version(b"short"))
            self.assertIsNone(scan.parse_class_major_version(b"NOT!\x00\x00\x00\x34"))
            self.assertEqual(
                scan.parse_class_major_version(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"), 61,
            )
            self.assertEqual(scan.classfile_major_to_java(61), 17)
            self.assertIsNone(scan.classfile_major_to_java(999))

            for rule, base, target, expected in (
                ({}, None, None, True),
                ({"affected_major": 3}, None, 4, True),
                ({"affected_major": 3}, 2, None, True),
                ({"affected_major": 3}, 2, 4, True),
                ({"affected_major": 3}, 3, 4, False),
                ({"affected_major": 5}, 2, 4, False),
            ):
                self.assertIs(
                    scan.rule_applies_to_major_interval(rule, base, target), expected,
                )
            for rule, base, target, expected in (
                ({}, None, None, True),
                ({"affected_version": 11}, None, 17, True),
                ({"affected_version": 11}, 8, None, True),
                ({"affected_version": 11}, 8, 17, True),
                ({"affected_version": 11}, 11, 17, False),
                ({"affected_version": 21}, 8, 17, False),
            ):
                self.assertIs(
                    scan.rule_applies_to_jdk_interval(rule, base, target), expected,
                )

            pack_dir = root / "rules"
            pack_dir.mkdir()
            valid = {
                "schema": "java-upgrade-analyzer.rule-pack.v1",
                "id": "test", "version": "1", "source": "third-party",
                "last_verified": "today",
                "rules": [{"id": "r1", "kind": "removed_api", "pattern": "x"}],
            }
            rule_path = pack_dir / "test.json"
            with patch.object(scan, "RULE_PACK_DIR", pack_dir):
                for payload in (
                    [],
                    {**valid, "schema": "bad"},
                    {key: value for key, value in valid.items() if key != "source"},
                    {**valid, "rules": "bad"},
                    {**valid, "rules": ["bad"]},
                    {**valid, "rules": [{"id": "", "kind": "x", "pattern": "x"}]},
                    {**valid, "rules": [valid["rules"][0], valid["rules"][0]]},
                ):
                    rule_path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        scan.load_rule_pack("test")
                rule_path.write_text(json.dumps(valid), encoding="utf-8")
                loaded = scan.load_rule_pack("test")
            self.assertEqual(loaded["rules"][0]["source"], "third-party")
            self.assertRegex(loaded["_sha256"], r"^[0-9a-f]{64}$")

            pack = {
                "rules": [
                    {"kind": "removed_api", "affected_version": 11},
                    {"kind": "other", "affected_version": 11},
                ],
            }
            with patch.object(scan, "load_rule_pack", return_value=pack):
                self.assertEqual(len(scan.active_jdk_removed_rules(8, 17)), 1)
            with patch.object(scan, "load_rule_pack", side_effect=OSError("missing")), patch.object(
                scan,
                "JDK_REMOVED_RULES",
                [("x", "X", "unknown", "REMOVED"), ("y", "Y", "JDK11", "REMOVED")],
            ):
                fallback = scan.active_jdk_removed_rules(8, 17)
            self.assertEqual([row[0]["affected_version"] for row in fallback], [0, 11])

            output = root / "database.csv"
            for summary, expected in (
                ({"coverage_status": "complete", "change_count": 2}, 2),
                ({"coverage_status": "partial", "coverage_gaps": ["gap"], "change_count": 0}, 0),
                ({}, 0),
            ):
                scan.reset_scan_diagnostics()
                with patch.object(scan, "scan_database_contracts", return_value=summary), patch.object(
                    scan, "STEP3_JDK_HOME", "",
                ):
                    self.assertEqual(
                        scan.scan_database_contract_changes(None, output), expected,
                    )
                if summary.get("coverage_status") != "complete":
                    self.assertTrue(scan.get_scan_diagnostics())

    def test_residual_helper_short_circuit_matrix(self):
        self.assertTrue(scan.is_jdk_javax("javax.sql.rowset"))
        self.assertFalse(scan.is_jdk_javax("javax.servlet"))
        self.assertIsNone(scan.resolve_dep_version({"new_version": "", "old_version": ""}))
        self.assertIsNone(scan.resolve_dep_version({"new_version": "-", "old_version": "-"}))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            short = root / "short.txt"
            short.write_text("one\n", encoding="utf-8")
            self.assertEqual(scan._safe_read_lines(short, limit=5), [(1, "one")])

            headerless = root / "headerless.csv"
            headerless.write_text("", encoding="utf-8")
            self.assertEqual(scan.load_current_deps(headerless), [])

            rules = root / "rules"
            rules.mkdir()
            payload = {
                "schema": "java-upgrade-analyzer.rule-pack.v1",
                "id": "test", "version": "1", "source": "source",
                "last_verified": "today", "rules": [],
            }
            with patch.object(scan, "RULE_PACK_DIR", rules):
                for bad_rule in (
                    {"id": "r", "kind": "", "pattern": "x"},
                    {"id": "r", "kind": "kind", "pattern": ""},
                ):
                    (rules / "test.json").write_text(
                        json.dumps({**payload, "rules": [bad_rule]}), encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        scan.load_rule_pack("test")

            with patch.object(scan, "load_rule_pack", return_value={"rules": []}):
                self.assertEqual(scan.active_jdk_removed_rules(8, 17), [])

            with patch.object(scan, "scan_database_contracts", return_value={
                "coverage_status": "complete", "change_count": 1,
            }), patch.object(scan, "STEP3_JDK_HOME", "/jdk") as _jdk:
                self.assertEqual(
                    scan.scan_database_contract_changes(None, root / "db.csv"), 1,
                )

            inputs = [
                {},
                {"dependency": {}, "error_code": "failed"},
                {"dependency": {"coord": "other"}, "error_code": ""},
            ]
            with patch.object(scan, "_current_dependency_ledger_path", return_value="ledger"), patch.object(
                scan, "iter_current_final_artifact_dependencies", return_value=inputs,
            ):
                result = scan._build_coord_scan_tokens({"coord": "wanted"}, root)
            self.assertEqual(result["class_names"], [])

            entry_inputs = [{
                "dependency": {"coord": "wanted", "entry_id": "entry.jar"},
                "jar_bytes": b"jar", "error_code": "",
            }]
            with patch.object(scan, "_current_dependency_ledger_path", return_value="ledger"), patch.object(
                scan, "iter_current_final_artifact_dependencies", return_value=entry_inputs,
            ), patch.object(
                scan, "_iter_jar_class_names", return_value=["p.A", "q.A", "Top"],
            ):
                result = scan._build_coord_scan_tokens({"coord": "wanted"}, root)
            self.assertEqual(result["jar_path"], "entry.jar")
            self.assertEqual(result["simple_names"], ["A", "Top"])

    def test_thread_lifecycle_and_jdk_removed_confidence_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java = root / "Worker.java"
            java.write_text(
                """
                class Worker extends java.lang.Thread {
                  Thread worker;
                  void runIt(Object obj) {
                    // worker.stop();
                    * worker.suspend();
                    /* worker.resume();
                    Thread.currentThread().stop();
                    java.lang.Thread.currentThread().suspend();
                    ((Thread) obj).resume();
                    ((java.lang.Thread) obj).stop();
                    this.resume();
                    worker.stop();
                    stopwatch.stop();
                  }
                }
                class Plain { void x() { this.stop(); } }
                outside.stop();
                """,
                encoding="utf-8",
            )
            rows = scan.scan_thread_lifecycle_calls(root)
            evidence = {row["证据"] for row in rows}
            self.assertIn("Thread.currentThread", evidence)
            self.assertIn("cast_to_Thread", evidence)
            self.assertIn("extends_Thread_this", evidence)
            self.assertIn("declared_as_Thread:worker", evidence)
            self.assertTrue(all(row["置信度"] == "CONFIRMED" for row in rows))
            self.assertFalse(any("class Plain" in row["内容"] for row in rows))

            with patch.object(scan, "walk_files", return_value=[str(java)]), patch.object(
                scan, "open_text", side_effect=OSError("bad"),
            ):
                self.assertEqual(scan.scan_thread_lifecycle_calls(root), [])

            output = root / "removed.csv"
            rules = [
                ({
                    "id": "removed", "pattern": "REMOVED_HIT", "name": "Removed",
                    "affected_version": 11, "status": "REMOVED",
                }, {"id": "jdk", "version": "1"}),
                ({
                    "id": "deprecated", "pattern": "DEPRECATED_HIT", "name": "Deprecated",
                    "affected_version": 17, "status": "DEPRECATED",
                }, {"id": "jdk", "version": "1"}),
            ]
            with patch.object(scan, "active_jdk_removed_rules", return_value=rules), patch.object(
                scan,
                "scan_pattern",
                side_effect=[[("A.java", 1, "REMOVED_HIT")], [("B.java", 2, "DEPRECATED_HIT")]],
            ), patch.object(scan, "scan_thread_lifecycle_calls", return_value=[]):
                self.assertEqual(scan.scan_jdk_removed(root, output), 2)
            loaded = scan.load_csv_rows(output)
            self.assertEqual(
                [row["置信度"] for row in loaded], ["CONFIRMED", "SUSPECT"],
            )

    def test_residual_file_csv_and_provenance_short_circuit_matrix(self):
        class ReaderRows:
            def __init__(self, fieldnames, rows):
                self.fieldnames = fieldnames
                self._rows = rows

            def __iter__(self):
                return iter(self._rows)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            (source / "nested").mkdir(parents=True)
            (source / "target").mkdir()
            (source / "nested" / "Use.java").write_text("HIT\n", encoding="utf-8")
            (source / "ignored.bin").write_text("HIT\n", encoding="utf-8")
            self.assertEqual(
                [Path(path).name for path in scan._iter_candidate_scan_files([source])],
                ["Use.java"],
            )
            empty = root / "empty"
            empty.mkdir()
            self.assertEqual(list(scan._iter_candidate_scan_files([empty])), [])

            pattern_hits = scan.scan_pattern(source, "HIT", max_per_file=2)
            self.assertEqual(len(pattern_hits), 1)

            with patch.object(scan, "_current_dependency_ledger_path", return_value="ledger"), patch.object(
                scan, "iter_current_final_artifact_dependencies", return_value=[{
                    "dependency": {"coord": "g:a"}, "jar_bytes": b"jar", "error_code": "",
                }],
            ), patch.object(
                scan, "_iter_jar_class_names", return_value=["p.A", "p.B"],
            ):
                tokens = scan._build_coord_scan_tokens({"coord": "g:a"}, root)
            self.assertEqual(tokens["package_prefixes"], ["p"])

            path = root / "rows.csv"
            path.write_text("placeholder\n", encoding="utf-8")
            with patch.object(
                scan.csv, "DictReader", return_value=ReaderRows(["a"], [{}, {"a": None}]),
            ):
                self.assertEqual(scan.load_csv_rows(path), [{"a": ""}])

            with patch.object(
                scan.csv,
                "DictReader",
                return_value=ReaderRows(
                    ["coord", "new_version", "resolution_status"],
                    [
                        {},
                        {"coord": "", "new_version": "2", "resolution_status": ""},
                        {"coord": "g:no-version", "new_version": "", "resolution_status": ""},
                        {"coord": "g:ok", "new_version": "2", "resolution_status": ""},
                    ],
                ),
            ):
                self.assertEqual(
                    [row["coord"] for row in scan.load_dep_changes(path)], ["g:no-version", "g:ok"],
                )

            with patch.object(
                scan.csv,
                "DictReader",
                return_value=ReaderRows(
                    ["coord", "version", "scope"],
                    [
                        {},
                        {"coord": "", "version": "2", "scope": ""},
                        {"coord": "g:no-version", "version": "", "scope": ""},
                        {"coord": "g:removed", "version": "-", "scope": ""},
                        {"coord": "g:ok", "version": "2", "scope": ""},
                    ],
                ),
            ):
                current = scan.load_current_deps(path)
            self.assertEqual([row["coord"] for row in current], ["g:ok"])

            provenance = root / "build_provenance.json"
            provenance.write_text("{}", encoding="utf-8")
            with patch.object(
                scan, "_step3_build_provenance_candidates", return_value=iter([provenance]),
            ):
                self.assertEqual(
                    scan.resolve_current_final_artifact_path(path),
                    ("", "current_final_artifact_missing"),
                )

            javax_output = root / "javax-short-circuit.csv"
            scan_calls = [
                [("f", 1, "")],
                [("f", 2, "javax.sql.DataSource value")],
                [("f", 3, "@javax.crypto.SecretKey annotation")],
                [], [], [], [],
            ]
            jakarta_pack = {
                "id": "jakarta", "version": "1",
                "rules": [
                    {"id": "other", "kind": "other", "pattern": "x"},
                    {
                        "id": "inactive", "kind": "namespace_migration",
                        "pattern": "x", "affected_major": 5,
                    },
                    {
                        "id": "fallback", "kind": "namespace_migration",
                        "pattern": "", "affected_major": 3,
                    },
                ],
            }
            with patch.object(scan, "scan_pattern", side_effect=scan_calls), patch.object(
                scan, "iter_source_roots", return_value=[]), patch.object(
                scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", return_value=jakarta_pack,
            ), patch.object(scan, "BASE_SPRING_BOOT_MAJOR", 2), patch.object(
                scan, "TARGET_SPRING_BOOT_MAJOR", 3,
            ):
                self.assertEqual(scan.scan_javax([], javax_output), 3)
            javax_rows = self._csv_rows(javax_output)
            self.assertTrue(any(row["需迁移"] == "N" for row in javax_rows))
            self.assertTrue(any(
                row["规则ID"] == "jakarta-generic-review" for row in javax_rows
            ))
            with patch.object(scan, "scan_pattern", return_value=[]), patch.object(
                scan, "iter_source_roots", return_value=[]), patch.object(
                scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", return_value={
                    "id": "jakarta", "version": "1", "rules": [],
                },
            ):
                self.assertEqual(scan.scan_javax([], root / "javax-no-rules.csv"), 0)

    def test_javax_scan_real_files_and_parser_fallback_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java = root / "src" / "App.java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "import javax.sql.DataSource;\n"
                "import javax.servlet.Filter;\n"
                "class App { javax.crypto.Cipher c; @javax.inject.Inject Object x; }\n",
                encoding="utf-8",
            )
            for name, content in (
                ("app.xml", "javax.servlet.Filter"),
                ("app.properties", "type=javax.persistence.Entity"),
                ("app.yml", "type: javax.validation.Validator"),
                ("app.yaml", "type: javax.ws.rs.Path"),
                ("spring.factories", "key=javax.servlet.Filter\nno.match=true"),
            ):
                (root / name).write_text(content, encoding="utf-8")
            services = root / "META-INF" / "services"
            services.mkdir(parents=True)
            (root / "allowed-directory").mkdir()
            (root / "target").mkdir()
            (services / "service").write_text(
                "javax.servlet.ServletContainerInitializer\nother.Type\n",
                encoding="utf-8",
            )
            broken_service = services / "broken"
            broken_service.write_text("javax.servlet.Bad", encoding="utf-8")
            broken_factories = root / "broken.factories"
            broken_factories.write_text("javax.servlet.Bad", encoding="utf-8")

            real_open = scan.open_text

            def selective_open(path, *args, **kwargs):
                if str(path).endswith(("/broken", "broken.factories")):
                    raise OSError("unreadable")
                return real_open(path, *args, **kwargs)

            pack = {
                "id": "jakarta", "version": "1",
                "rules": [{
                    "id": "servlet", "kind": "namespace_migration",
                    "pattern": "javax\\.servlet", "replacement": "jakarta.servlet",
                    "affected_major": 3,
                }],
            }
            output = root / "javax.csv"
            with patch.object(scan, "open_text", side_effect=selective_open), patch.object(
                scan, "load_rule_pack", return_value=pack,
            ), patch.object(scan, "BASE_SPRING_BOOT_MAJOR", 2), patch.object(
                scan, "TARGET_SPRING_BOOT_MAJOR", 3,
            ):
                count = scan.scan_javax(root, output)
            self.assertGreaterEqual(count, 9)
            rows = scan.load_csv_rows(output)
            self.assertTrue(any(row["需迁移"] == "N" for row in rows))
            self.assertTrue(any(row["规则ID"] == "servlet" for row in rows))
            self.assertTrue(any(row["需迁移"] == "UNKNOWN" for row in rows))

            calls = [
                [("f", 1, "noise")],
                [("f", 2, "import javax.bad.X"), ("f", 3, "@javax.bad.X"), ("f", 4, "noise")],
                [("f", 5, "noise")],
                [], [], [], [],
            ]
            with patch.object(scan, "scan_pattern", side_effect=calls), patch.object(
                scan, "iter_source_roots", return_value=[]), patch.object(
                scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", side_effect=OSError("missing"),
            ):
                fallback_count = scan.scan_javax([], root / "fallback.csv")
            self.assertEqual(fallback_count, 3)

    def test_serialization_runtime_flags_and_spring_scanners_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty"
            empty.mkdir()
            self.assertEqual(scan.scan_serialization(empty, root / "empty.txt"), 0)

            serial = root / "serial"
            serial.mkdir()
            for index in range(31):
                content = f"public class C{index} implements Serializable {{"
                if index % 2:
                    content += " private static final long serialVersionUID = 1L;"
                content += " }"
                (serial / f"C{index}.java").write_text(content, encoding="utf-8")
            (serial / "Record.java").write_text(
                "record R() implements Serializable {}", encoding="utf-8",
            )
            (serial / "Plain.java").write_text(
                "class Plain {}", encoding="utf-8",
            )
            risk_hits = [("Use.java", i, "@Cacheable") for i in range(1, 7)]
            with patch.object(
                scan, "scan_pattern",
                side_effect=[risk_hits, [], [], [], [], [], [], [], [], []],
            ):
                risk_count = scan.scan_serialization(serial, root / "serial.txt")
            self.assertGreater(risk_count, 0)
            report = (root / "serial.txt").read_text(encoding="utf-8")
            self.assertIn("... 还有", report)
            self.assertIn("[?]", report)
            self.assertIn("Redis 缓存", report)

            flags = root / "flags"
            flags.mkdir()
            (flags / "nested").mkdir()
            (flags / "target").mkdir()
            (flags / "Jenkinsfile").write_text(
                "# --illegal-access\njava --illegal-access=permit\n", encoding="utf-8",
            )
            (flags / "Dockerfile.dev").write_text(
                "RUN java --add-opens=x\n", encoding="utf-8",
            )
            (flags / "Procfile").write_text("java -XX:+UseConcMarkSweepGC\n", encoding="utf-8")
            (flags / "run.sh").write_text("\n// --add-exports=x\njava -Djava.ext.dirs=x\n", encoding="utf-8")
            (flags / "ignored.bin").write_text("--illegal-access", encoding="utf-8")
            flag_output = root / "flags.csv"
            self.assertGreaterEqual(scan.scan_jdk_runtime_flags(flags, flag_output), 4)

            config = root / "config"
            config.mkdir()
            (config / "app.properties").write_text(
                "\n# comment\nserver.port=8080\nno_equals\n=value\nempty=\n", encoding="utf-8",
            )
            (config / "app.yml").write_text(
                "\n"
                "# comment\n"
                "server:\n"
                "  port: 8080\n"
                "profiles: &profiles\n"
                "  active: prod\n"
                "text: |\n"
                "  body: ignored\n"
                "after: value\n"
                "list:\n"
                "  - name: first\n"
                "flow: {x: y}\n"
                "array: [x]\n"
                "bad\tindent: value\n"
                "'quoted-key': yes\n"
                "commented: # value\n"
                "not a key\n",
                encoding="utf-8",
            )
            (config / "tab-first.yml").write_text(
                "\tbad: value\nflow: {x: y}\n", encoding="utf-8",
            )
            config_output = root / "config.csv"
            self.assertGreater(scan.scan_sb_config(config, config_output), 0)
            config_rows = scan.load_csv_rows(config_output)
            self.assertTrue(any(row.get("扫描状态") == "未完成" for row in config_rows))
            self.assertTrue(any(row["配置键"] == "profiles.active" for row in config_rows))

            auto = root / "auto"
            factories = auto / "META-INF" / "spring.factories"
            imports = auto / "META-INF" / "spring" / "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
            imports.parent.mkdir(parents=True)
            factories.parent.mkdir(parents=True, exist_ok=True)
            factories.write_text(
                "EnableAutoConfiguration=com.acme.Auto\nunrelated=value\n",
                encoding="utf-8",
            )
            imports.write_text("com.acme.Auto\n\n", encoding="utf-8")
            (auto / "META-INF" / "other.factories").write_text("other=value\n", encoding="utf-8")
            (imports.parent / "other.imports").write_text("other.Value\n", encoding="utf-8")
            source = auto / "Auto.java"
            source.write_text("@AutoConfiguration @ConstructorBinding class Auto {}", encoding="utf-8")
            pack = {
                "id": "spring-boot", "version": "1",
                "rules": [
                    {"id": "r", "affected_major": 3},
                    {"id": "inactive", "affected_major": 5},
                ],
            }
            auto_output = root / "auto.txt"
            with patch.object(scan, "load_rule_pack", return_value=pack):
                with patch.object(scan, "BASE_SPRING_BOOT_MAJOR", 2), patch.object(
                    scan, "TARGET_SPRING_BOOT_MAJOR", 3,
                ):
                    self.assertEqual(scan.scan_sb_autoconfig(auto, auto_output), 4)
            with patch.object(scan, "load_rule_pack", side_effect=OSError("missing")):
                self.assertEqual(scan.scan_sb_autoconfig(empty, root / "auto-empty.txt"), 0)
            with patch.object(scan, "load_rule_pack", return_value={
                "id": "spring-boot", "version": "1", "rules": [],
            }):
                self.assertEqual(scan.scan_sb_autoconfig(empty, root / "auto-no-rules.txt"), 0)

    def test_cleanup_step3_outputs_complete_state_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan.cleanup_step3_outputs(root / "missing")

            report = root / "report"
            report.mkdir()
            scan.cleanup_step3_outputs(report)

            default_output = report / next(iter(scan.SCAN_FUNCS.values()))[1]
            default_output.write_text("stale", encoding="utf-8")
            database_output = report / scan.DATABASE_CONTRACT_SUMMARY_NAME
            database_output.write_text("stale", encoding="utf-8")
            aggregate = report / scan.STEP3_RISK_CANDIDATES_FILE
            aggregate.write_text("stale", encoding="utf-8")
            per_root = report / scan.PER_DEPENDENCY_DIRNAME
            per_root.mkdir()
            (per_root / "not-a-directory").write_text("keep", encoding="utf-8")

            missing_summary = per_root / "missing-summary"
            missing_summary.mkdir()
            (missing_summary / scan.PER_DEPENDENCY_CANDIDATE_HITS_FILE).write_text(
                "stale", encoding="utf-8",
            )

            invalid_summary = per_root / "invalid-summary"
            invalid_summary.mkdir()
            (invalid_summary / scan.PER_DEPENDENCY_SUMMARY_FILE).write_text(
                "{", encoding="utf-8",
            )

            empty_summary = per_root / "empty-summary"
            empty_summary.mkdir()
            empty_path = empty_summary / scan.PER_DEPENDENCY_SUMMARY_FILE
            empty_path.write_text("{}", encoding="utf-8")

            step3_only = per_root / "step3-only"
            step3_only.mkdir()
            step3_only_path = step3_only / scan.PER_DEPENDENCY_SUMMARY_FILE
            step3_only_path.write_text(
                json.dumps({
                    "step3": {"status": "done"},
                    "artifacts": {"candidate_hits_csv": "stale.csv"},
                }),
                encoding="utf-8",
            )

            coord_only = per_root / "coord-only"
            coord_only.mkdir()
            coord_path = coord_only / scan.PER_DEPENDENCY_SUMMARY_FILE
            coord_path.write_text(
                json.dumps({
                    "coord": "g:a",
                    "step3": {"status": "done"},
                    "artifacts": {"candidate_hits_csv": "stale.csv"},
                }),
                encoding="utf-8",
            )

            scan.cleanup_step3_outputs(report)

            self.assertFalse(default_output.exists())
            self.assertFalse(database_output.exists())
            self.assertFalse(aggregate.exists())
            self.assertFalse(
                (missing_summary / scan.PER_DEPENDENCY_CANDIDATE_HITS_FILE).exists()
            )
            self.assertTrue(
                (invalid_summary / scan.PER_DEPENDENCY_SUMMARY_FILE).exists()
            )
            self.assertFalse(empty_path.exists())
            self.assertFalse(step3_only_path.exists())
            self.assertEqual(
                json.loads(coord_path.read_text(encoding="utf-8")), {"coord": "g:a"},
            )

    def test_candidate_output_complete_state_and_recovery_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            report.mkdir()
            system_source = root / "system"
            dependency_source = root / "dependency"
            system_source.mkdir()
            dependency_source.mkdir()
            system_file = system_source / "Use.java"
            system_file.write_text(
                "\nno reference\nTarget value;\np.Other value;\n",
                encoding="utf-8",
            )
            broken_file = system_source / "Broken.java"
            broken_file.write_text("Target value;", encoding="utf-8")
            dependency_file = dependency_source / "Dep.java"
            dependency_file.write_text("new Target();\n", encoding="utf-8")

            compat_path = report / "s3_dependency_compat.csv"
            compat_path.write_text(
                "坐标,风险类型,证据,最终制品内路径,jar路径\n"
                ",ignored,no coordinate,,none.jar\n"
                "g:other,ignored,other,,other.jar\n"
                "g:a,,binary evidence,,fallback.jar\n"
                "g:a,empty-evidence,,,empty.jar\n",
                encoding="utf-8",
            )
            per_dir = scan.get_per_dependency_dir(report, "g:a")
            per_dir.mkdir(parents=True)
            summary_path = per_dir / scan.PER_DEPENDENCY_SUMMARY_FILE
            summary_path.write_text("[]", encoding="utf-8")

            rows = [
                {},
                {"coord": "g:none", "old_version": "1", "new_version": "2"},
                {
                    "coord": "g:a",
                    "change_type": "小版本升级",
                },
            ]

            def token_bundle(dep_row, _report):
                if dep_row.get("coord") == "g:a":
                    return {"class_names": ["p.Target", "p.Other"]}
                return {"class_names": []}

            def candidate_files(paths):
                if str(system_source) in paths:
                    return iter([str(system_file), str(system_file), str(broken_file)])
                return iter([str(dependency_file)])

            real_open = scan.open_text

            def selective_open(path, *args, **kwargs):
                if str(path) == str(broken_file):
                    raise OSError("unreadable")
                return real_open(path, *args, **kwargs)

            with patch.object(scan, "load_dep_changes", return_value=[]):
                self.assertEqual(
                    scan.build_per_dependency_candidate_outputs([], "deps.csv", report), 0,
                )
            with patch.object(scan, "load_dep_changes", return_value=[{"coord": "g:a"}]):
                self.assertEqual(
                    scan.build_per_dependency_candidate_outputs([], "deps.csv", None), 0,
                )

            with patch.object(scan, "load_dep_changes", return_value=rows), patch.object(
                scan, "_build_coord_scan_tokens", side_effect=token_bundle,
            ), patch.object(
                scan, "_iter_candidate_scan_files", side_effect=candidate_files,
            ), patch.object(scan, "open_text", side_effect=selective_open):
                hit_count = scan.build_per_dependency_candidate_outputs(
                    [str(system_source)], "deps.csv", report,
                    dependency_source_dirs=[str(dependency_source)],
                )

            self.assertEqual(hit_count, 5)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["coord"], "g:a")
            self.assertEqual(summary["step3"]["candidate_hit_count"], 5)
            self.assertEqual(
                summary["step3"]["bucket_counts"],
                {
                    "system_source": 2,
                    "dependency_with_source": 1,
                    "dependency_without_source": 2,
                },
            )
            candidate_rows = self._csv_rows(
                per_dir / scan.PER_DEPENDENCY_CANDIDATE_HITS_FILE
            )
            self.assertEqual(len(candidate_rows), 5)
            binary_row = next(
                row for row in candidate_rows
                if row["candidate_bucket"] == "dependency_without_source"
            )
            self.assertEqual(binary_row["file"], "fallback.jar")
            self.assertEqual(binary_row["candidate_kind"], "")

            summary_path.write_text(
                json.dumps({"artifacts": {}}), encoding="utf-8",
            )
            with patch.object(scan, "load_dep_changes", return_value=rows), patch.object(
                scan, "_build_coord_scan_tokens", side_effect=token_bundle,
            ), patch.object(
                scan, "_iter_candidate_scan_files", side_effect=candidate_files,
            ), patch.object(scan, "open_text", side_effect=selective_open):
                self.assertEqual(
                    scan.build_per_dependency_candidate_outputs(
                        [str(system_source)], "deps.csv", report,
                        dependency_source_dirs=[str(dependency_source)],
                    ),
                    5,
                )

    def test_step3_coverage_status_source_and_rule_pack_matrix(self):
        valid_packs = {
            pack_id: {
                "id": pack_id, "version": "1", "_sha256": f"sha-{pack_id}",
                "source": "third-party", "last_verified": "today",
                "rules": ([{"id": "r"}] if pack_id == "jdk" else []),
            }
            for pack_id in ("jdk", "jakarta", "spring-boot")
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "coverage.json"
            scan.reset_scan_diagnostics()

            def open_for_metrics(path):
                if str(path).endswith("README"):
                    raise OSError("unreadable")
                return io.StringIO("x")

            def mixed_pack(pack_id):
                if pack_id == "jakarta":
                    raise OSError("missing")
                return valid_packs[pack_id]

            with patch.object(
                scan, "walk_files", return_value=["A.java", "README"],
            ), patch.object(scan, "open_text", side_effect=open_for_metrics), patch.object(
                scan, "load_rule_pack", side_effect=mixed_pack,
            ):
                partial = scan.write_step3_coverage(
                    root, ["src"], ["javax", "javax", "reflection"],
                    ["javax", "javax"], output,
                )
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(partial["metrics"]["files_scanned"], 2)
            self.assertEqual(
                partial["metrics"]["extension_counts"], {".java": 1, "<none>": 1},
            )
            self.assertEqual(
                set(partial["reason_codes"]),
                {
                    "planned_scan_not_executed", "source_file_read_failures",
                    "rule_pack_unavailable",
                },
            )

            with patch.object(scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", side_effect=OSError("all missing"),
            ):
                insufficient = scan.write_step3_coverage(
                    root, [], None, None, "",
                    business_source_status="not_provided",
                    dependency_source_status="available",
                )
            self.assertEqual(insufficient["status"], "insufficient")
            self.assertEqual(insufficient["source_coverage_status"], "dependency_source_only")
            self.assertTrue((root / "s3_coverage.json").is_file())

            scan.reset_scan_diagnostics()
            scan.record_scan_diagnostic(
                stage="test_scan", path="input", error=OSError("failed"),
            )
            with patch.object(scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", side_effect=lambda pack_id: valid_packs[pack_id],
            ):
                diagnosed = scan.write_step3_coverage(
                    root, [], ["javax"], ["javax"], output,
                )
            self.assertEqual(diagnosed["status"], "partial")
            self.assertEqual(diagnosed["source_coverage_status"], "not_provided")
            self.assertIn("scan_operation_failures", diagnosed["reason_codes"])

            with patch.object(scan, "walk_files", return_value=[]), patch.object(
                scan, "load_rule_pack", side_effect=lambda pack_id: valid_packs[pack_id],
            ):
                diagnosed_without_execution = scan.write_step3_coverage(
                    root, [], ["javax"], [], output,
                )
            self.assertEqual(diagnosed_without_execution["status"], "insufficient")

            scan.reset_scan_diagnostics()
            with patch.object(scan, "walk_files", return_value=["README"]), patch.object(
                scan, "open_text", side_effect=OSError("unreadable"),
            ), patch.object(
                scan, "load_rule_pack", side_effect=lambda pack_id: valid_packs[pack_id],
            ):
                read_failure_only = scan.write_step3_coverage(
                    root, ["src"], ["javax"], ["javax"], output,
                )
            self.assertEqual(read_failure_only["status"], "partial")
            self.assertEqual(read_failure_only["metrics"]["read_failures"], 1)

    def test_main_argument_orchestration_and_scan_plan_matrix(self):
        original_scan_names = list(scan.SCAN_FUNCS)
        tracked_globals = (
            "STEP3_DEPENDENCY_SOURCE_DIRS", "STEP3_REPORT_DIR", "STEP3_JDK_HOME",
            "DEP_COMPAT_INCLUDE_TEST_SCOPE", "TARGET_JDK", "BASE_JDK",
            "BASE_SPRING_BOOT_MAJOR", "TARGET_SPRING_BOOT_MAJOR",
        )
        old_globals = {name: getattr(scan, name) for name in tracked_globals}

        def namespace(**overrides):
            values = {
                "type": "dep_compat",
                "all": False,
                "source_dir": "src",
                "source_dirs": None,
                "no_source": False,
                "no_business_source": False,
                "output": None,
                "output_dir": "/tmp/s3-output",
                "report_dir": "",
                "coverage_output": "",
                "dep_changes": None,
                "dep_current": None,
                "include_test_scope": False,
                "jdk_upgraded": False,
                "sb_major_upgrade": False,
                "target_jdk": "",
                "jdk_home": "",
            }
            values.update(overrides)
            return scan.argparse.Namespace(**values)

        def run_case(
            args,
            *,
            orchestrated_input=None,
            context=None,
            roots=None,
            function_result=1,
        ):
            calls = []

            def fake_function(name):
                def invoke(_source, _output, _deps):
                    calls.append(name)
                    return function_result

                return invoke

            fake_funcs = {
                name: (fake_function(name), f"{name}.out")
                for name in original_scan_names
            }
            with patch.object(
                scan.argparse.ArgumentParser, "parse_args", return_value=args,
            ), patch.object(
                scan, "load_orchestrated_step3_input",
                return_value=(orchestrated_input or {}, context or {}),
            ), patch.object(
                scan, "normalize_dependency_source_dirs", return_value=["dependency-src"],
            ), patch.object(
                scan, "iter_source_roots", return_value=list(roots or []),
            ), patch.object(scan, "SCAN_FUNCS", fake_funcs), patch.object(
                scan, "cleanup_step3_outputs",
            ), patch.object(scan.os, "makedirs"), patch.object(
                scan, "write_step3_coverage",
            ) as coverage, patch.object(scan, "emit_progress"):
                exit_code = None
                try:
                    scan.main()
                except SystemExit as exc:
                    exit_code = exc.code
            snapshot = {name: getattr(scan, name) for name in tracked_globals}
            return exit_code, calls, snapshot, coverage.call_args

        try:
            self.assertEqual(
                run_case(namespace(type=None, all=False), roots=["src"])[0], 1,
            )
            self.assertEqual(
                run_case(namespace(no_source=True, no_business_source=True))[0], 2,
            )
            self.assertEqual(
                run_case(namespace(type="javax", no_source=True))[0], 2,
            )
            self.assertEqual(
                run_case(namespace(type="javax", no_business_source=True))[0], 2,
            )
            self.assertEqual(
                run_case(namespace(), roots=[])[0], 2,
            )

            code, calls, state, coverage_call = run_case(
                namespace(
                    source_dir=None,
                    source_dirs=["src-a", "src-b"],
                    output="explicit.csv",
                    report_dir="report",
                    dep_current="current.csv",
                    include_test_scope=True,
                    jdk_upgraded=True,
                    sb_major_upgrade=True,
                    target_jdk="17",
                    jdk_home="/jdk-explicit",
                ),
                roots=["src-a", "src-b"],
                function_result=2,
            )
            self.assertIsNone(code)
            self.assertEqual(calls, ["dep_compat"])
            self.assertEqual(state["TARGET_JDK"], 17)
            self.assertEqual(state["STEP3_REPORT_DIR"], "report")
            self.assertEqual(state["STEP3_JDK_HOME"], "/jdk-explicit")
            self.assertEqual(coverage_call.args[1], ["src-a", "src-b"])

            _, calls, state, _ = run_case(
                namespace(dep_changes="changes.csv", target_jdk="not-a-number"),
                context={
                    "jdk_upgraded": False,
                    "springboot_major_upgrade": False,
                    "jdk_current": "",
                    "jdk_base": "",
                    "springboot_base": "",
                    "springboot_current": "",
                },
                roots=["src"],
                function_result=None,
            )
            self.assertEqual(calls, ["dep_compat"])
            self.assertIsNone(state["TARGET_JDK"])
            self.assertIsNone(state["BASE_JDK"])

            orchestrated = {
                "source_dirs": ["orchestrated-src"],
                "include_test_scope": True,
                "dependency_source_dirs": ["dependency-src"],
                "current_jdk_home": "/jdk-orchestrated",
            }
            upgrade_context = {
                "jdk_upgraded": True,
                "springboot_major_upgrade": True,
                "jdk_current": "21",
                "jdk_base": "8",
                "springboot_base": "2.7.18",
                "springboot_current": "3.2.0",
            }
            _, calls, state, _ = run_case(
                namespace(source_dir=None, source_dirs=None),
                orchestrated_input=orchestrated,
                context=upgrade_context,
                roots=["orchestrated-src"],
            )
            self.assertEqual(calls, ["dep_compat"])
            self.assertEqual(state["TARGET_JDK"], 21)
            self.assertEqual(state["BASE_JDK"], 8)
            self.assertEqual(state["BASE_SPRING_BOOT_MAJOR"], 2)
            self.assertEqual(state["TARGET_SPRING_BOOT_MAJOR"], 3)
            self.assertTrue(state["DEP_COMPAT_INCLUDE_TEST_SCOPE"])
            self.assertEqual(state["STEP3_JDK_HOME"], "/jdk-orchestrated")

            _, _, state, _ = run_case(
                namespace(
                    source_dir="explicit-src",
                    source_dirs=None,
                    include_test_scope=True,
                    jdk_upgraded=True,
                    sb_major_upgrade=True,
                    target_jdk="17",
                ),
                orchestrated_input={
                    "source_dirs": [], "include_test_scope": False,
                    "dependency_source_dirs": [],
                },
                context=upgrade_context,
                roots=["explicit-src"],
            )
            self.assertEqual(state["TARGET_JDK"], 17)

            _, calls, _, _ = run_case(
                namespace(source_dir=None, source_dirs=["provided-src"]),
                orchestrated_input={"source_dirs": ["ignored-src"]},
                roots=["provided-src"],
            )
            self.assertEqual(calls, ["dep_compat"])

            _, calls, state, _ = run_case(
                namespace(source_dir=None, source_dirs=None),
                orchestrated_input={
                    "marker": True,
                    "source_dirs": [],
                    "include_test_scope": False,
                },
                context={"jdk_current": None},
                roots=["synthetic-root"],
            )
            self.assertEqual(calls, ["dep_compat"])
            self.assertIsNone(state["TARGET_JDK"])

            for unavailable_flag in ("no_source", "no_business_source"):
                options = {unavailable_flag: True, "source_dir": None}
                code, calls, _, coverage_call = run_case(
                    namespace(**options), roots=[],
                )
                self.assertIsNone(code)
                self.assertEqual(calls, ["dep_compat"])
                expected_dependency_status = (
                    "available" if unavailable_flag == "no_business_source"
                    else "not_provided"
                )
                self.assertEqual(
                    coverage_call.kwargs["dependency_source_status"],
                    expected_dependency_status,
                )

            _, calls, _, _ = run_case(
                namespace(type=None, all=True), roots=["src"], function_result=None,
            )
            self.assertEqual(calls, original_scan_names)

            _, calls, _, _ = run_case(
                namespace(type=None, all=True, jdk_upgraded=True), roots=["src"],
            )
            self.assertEqual(
                calls,
                [
                    "database_contract", "jdk_removed", "javax", "jdk_internal",
                    "reflection", "serialization", "jdk_runtime_flags",
                ],
            )

            _, calls, _, _ = run_case(
                namespace(type=None, all=True, sb_major_upgrade=True), roots=["src"],
            )
            self.assertEqual(
                calls, ["database_contract", "javax", "sb_config", "sb_autoconfig"],
            )

            _, calls, _, _ = run_case(
                namespace(type=None, all=True, dep_changes="changes.csv"), roots=["src"],
            )
            self.assertEqual(
                calls, ["database_contract", "dep_compat", "dep_classfile"],
            )

            _, calls, _, _ = run_case(
                namespace(
                    type=None,
                    all=True,
                    source_dir=None,
                    no_source=True,
                    jdk_upgraded=True,
                    sb_major_upgrade=True,
                    dep_changes="changes.csv",
                ),
                roots=[],
            )
            self.assertEqual(
                calls, ["database_contract", "dep_compat", "dep_classfile"],
            )
        finally:
            for name, value in old_globals.items():
                setattr(scan, name, value)

    def test_dependency_compat_complete_branch_matrix(self):
        full_risk_jar = jar_bytes({
            "README.txt": b"not a class",
            "META-INF/ignored.class": b"javax/ignored",
            "META-INF/spring.factories": b"factory",
            "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports": b"auto",
            "META-INF/versions/17/demo/Versioned.class": b"javax/",
            "demo/All.class": (
                b"javax/ sun/misc/Unsafe jdk/internal/ com/sun/ "
                b"java/lang/SecurityManager setAccessible"
            ),
            "demo/AfterAll.class": b"javax/",
        })
        inputs = [
            {
                "dependency": {"coord": "skip:test", "version": "1", "scope": "test"},
                "jar_bytes": full_risk_jar,
                "error_code": "",
            },
            {
                "dependency": {},
                "jar_bytes": b"",
                "error_code": "unknown_final_artifact_error",
            },
            {
                "dependency": {"coord": "g:error", "version": "1"},
                "jar_bytes": b"",
                "error_code": "current_final_artifact_entry_missing",
            },
            {
                "dependency": {"scope": "runtime", "entry_id": "lib/fallback.jar"},
                "jar_bytes": full_risk_jar,
                "error_code": "",
            },
            {
                "dependency": {"entry_id": "lib/bad.jar"},
                "jar_bytes": b"not-a-jar",
                "error_code": "",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scan, "iter_current_final_artifact_dependencies", return_value=inputs,
        ), patch.object(scan, "DEP_COMPAT_INCLUDE_TEST_SCOPE", False):
            output = Path(tmp) / "compat.csv"
            self.assertEqual(scan.scan_dependency_compat([], output, "deps.csv"), 9)
            rows = self._csv_rows(output)

        self.assertEqual(len(rows), 9)
        self.assertEqual(
            {row["风险类型"] for row in rows},
            {
                "unknown_final_artifact_error", "current_final_artifact_entry_missing",
                "spring_factories",
                "auto_configuration_imports", "javax_reference",
                "jdk_internal_reference", "security_manager", "deep_reflection",
                "nested_jar_unreadable",
            },
        )
        fallback_rows = [row for row in rows if row["最终制品内路径"] == "lib/fallback.jar"]
        self.assertTrue(fallback_rows)
        self.assertTrue(all(row["坐标"] == "未解析" for row in fallback_rows))
        self.assertTrue(all(row["版本"] == "未解析" for row in fallback_rows))
        self.assertIn(
            "dependency_compat_nested_jar_open",
            {item["stage"] for item in scan.get_scan_diagnostics()},
        )

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scan, "iter_current_final_artifact_dependencies", return_value=[],
        ):
            output = Path(tmp) / "empty.csv"
            self.assertEqual(scan.scan_dependency_compat([], output, "deps.csv"), 0)
            self.assertEqual(self._csv_rows(output), [])

    def test_dependency_classfile_complete_branch_matrix(self):
        matrix_jar = jar_bytes({
            "README.txt": b"ignored",
            "META-INF/ignored.class": self._class_header(99),
            "demo/Base8.class": self._class_header(52),
            "demo/Base17.class": self._class_header(61),
            "demo/Base11.class": self._class_header(55),
            "META-INF/versions/17/demo/Old.class": self._class_header(61),
            "META-INF/versions/21/demo/New.class": self._class_header(65),
            "META-INF/versions/17/demo/Older.class": self._class_header(61),
        })
        inputs = [
            {
                "dependency": {"coord": "skip:test", "version": "1", "scope": "test"},
                "jar_bytes": matrix_jar, "error_code": "",
            },
            {
                "dependency": {}, "jar_bytes": b"",
                "error_code": "unknown_final_artifact_error",
            },
            {
                "dependency": {
                    "coord": "g:risky", "version": "2", "scope": "runtime",
                    "lib_entry": "lib/risky.jar",
                },
                "jar_bytes": matrix_jar, "error_code": "",
            },
            {
                "dependency": {"coord": "g:unknown", "scope": "compile"},
                "jar_bytes": jar_bytes({"Unknown.class": self._class_header(999)}),
                "error_code": "",
            },
            {
                "dependency": {"coord": "g:invalid", "version": "1"},
                "jar_bytes": jar_bytes({"Invalid.class": b"broken"}),
                "error_code": "",
            },
            {
                "dependency": {"coord": "g:empty", "version": "1"},
                "jar_bytes": jar_bytes({"README": b"empty"}),
                "error_code": "",
            },
            {
                "dependency": {"entry_id": "lib/bad.jar"},
                "jar_bytes": b"not-a-jar", "error_code": "",
            },
            {
                "dependency": {"coord": "g:bad", "version": "1"},
                "jar_bytes": b"also-not-a-jar", "error_code": "",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scan, "iter_current_final_artifact_dependencies", return_value=inputs,
        ), patch.object(scan, "DEP_COMPAT_INCLUDE_TEST_SCOPE", False), patch.object(
            scan, "TARGET_JDK", 17,
        ):
            output = Path(tmp) / "classfile.csv"
            self.assertEqual(scan.scan_dependency_classfile_versions([], output, "deps.csv"), 6)
            rows = self._csv_rows(output)

        self.assertEqual(len(rows), 7)
        by_coord = {row["依赖坐标"]: row for row in rows}
        self.assertTrue(any(
            row["扫描结论"] == "unknown_final_artifact_error" for row in rows
        ))
        self.assertEqual(by_coord["g:risky"]["基础区最高Class版本"], "61")
        self.assertEqual(by_coord["g:risky"]["多版本区最高Class版本"], "65")
        self.assertEqual(by_coord["g:risky"]["是否为多版本JAR"], "是")
        self.assertIn("至少需要 JDK 21", by_coord["g:risky"]["扫描结论"])
        self.assertIn("无法识别 Class 版本 999", by_coord["g:unknown"]["扫描结论"])
        self.assertIn("1 个 Class 条目无法读取", by_coord["g:invalid"]["扫描结论"])
        self.assertEqual(by_coord["g:empty"]["是否为多版本JAR"], "否")
        self.assertEqual(by_coord["g:empty"]["最高所需Java版本"], "")
        self.assertTrue(any("无法读取" in row["扫描结论"] for row in rows))
        self.assertIn(
            "dependency_classfile_header_parse",
            {item["stage"] for item in scan.get_scan_diagnostics()},
        )

        clean_input = [
            {
                "dependency": {"coord": "g:clean", "version": "1", "scope": "compile"},
                "jar_bytes": jar_bytes({"Clean.class": self._class_header(61)}),
                "error_code": "",
            },
            {
                "dependency": {"coord": "g:error", "version": "1"},
                "jar_bytes": b"",
                "error_code": "current_final_artifact_entry_missing",
            },
            {
                "dependency": {},
                "jar_bytes": b"not-a-jar",
                "error_code": "",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scan, "iter_current_final_artifact_dependencies", return_value=clean_input,
        ), patch.object(scan, "TARGET_JDK", None):
            output = Path(tmp) / "clean.csv"
            self.assertEqual(scan.scan_dependency_classfile_versions([], output, "deps.csv"), 2)
            self.assertEqual(
                next(row for row in self._csv_rows(output) if row["依赖坐标"] == "g:clean")["扫描结论"],
                "扫描完成，未发现字节码版本风险",
            )

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            scan, "iter_current_final_artifact_dependencies", return_value=[],
        ):
            output = Path(tmp) / "none.csv"
            self.assertEqual(scan.scan_dependency_classfile_versions([], output, "deps.csv"), 0)
            self.assertEqual(self._csv_rows(output), [])


if __name__ == "__main__":
    unittest.main()
