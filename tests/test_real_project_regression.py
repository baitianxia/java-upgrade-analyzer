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
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "project asset invalid")
        self.assertLess(result["project_asset_health"]["java_files"], 10)
        self.assertTrue(
            any(item["signal_type"] == "project_asset_invalid" for item in result["quality_signals"])
        )
        self.assertTrue(any(item["blocking"] for item in result["quality_signals"]))

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

        self.assertEqual(result["status"], "passed")
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

        self.assertEqual(result["status"], "passed")
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

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["step6"]["returncode"], 0)
        self.assertEqual(result["queries"][0]["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
