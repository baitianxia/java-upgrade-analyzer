import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import real_project_regression as realreg  # noqa: E402


class RealProjectRegressionTest(unittest.TestCase):
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
                output = report_dir / "s5_call_chain"
                output.mkdir(parents=True)
                (output / "alerts.csv").write_text(
                    "changed_symbol,evidence_files\n"
                    f"org.apache.dubbo.common.utils.StringUtils.isBlank,{java_file}\n",
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
                output = report_dir / "s5_call_chain"
                output.mkdir(parents=True)
                (output / "alerts.csv").write_text(
                    "changed_symbol,evidence_files\n"
                    f"{embedded_row['api_name']},{java_file}\n",
                    encoding="utf-8",
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

        self.assertEqual(result["status"], "passed")
        self.assertEqual(Path(result["changed_apis"]).name, "input_all_changed_apis.csv")


if __name__ == "__main__":
    unittest.main()
