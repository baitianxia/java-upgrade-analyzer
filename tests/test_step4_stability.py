import hashlib
import io
import json
import csv
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import compat  # noqa: E402
import auto_discover_bridge_sources as auto_sources  # noqa: E402
import run_step  # noqa: E402
import s4_jar_compare as step4  # noqa: E402


class Step4StabilityTest(unittest.TestCase):
    def test_runtime_provider_set_jar_is_byte_deterministic_across_build_times(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "primary.jar"
            companion = root / "companion.jar"
            with zipfile.ZipFile(primary, "w") as archive:
                archive.writestr("p/A.class", b"primary")
            with zipfile.ZipFile(companion, "w") as archive:
                archive.writestr("p/B.class", b"companion")

            with patch("zipfile.time.localtime", return_value=(2020, 1, 2, 3, 4, 6, 0, 0, -1)):
                output = Path(step4._write_runtime_provider_set_jar([primary, companion]))
            first_sha = hashlib.sha256(output.read_bytes()).hexdigest()
            output.unlink()
            with patch("zipfile.time.localtime", return_value=(2025, 6, 7, 8, 9, 10, 0, 0, -1)):
                rebuilt = Path(step4._write_runtime_provider_set_jar([primary, companion]))
            second_sha = hashlib.sha256(rebuilt.read_bytes()).hexdigest()

        self.assertEqual(first_sha, second_sha)

    def test_pair_artifact_replacements_uses_unique_complete_class_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "jna-5.18.1.jar"
            new_jar = root / "jna-jpms-5.19.0.jar"
            with zipfile.ZipFile(old_jar, "w") as archive:
                for name in ("com/sun/jna/Native.class", "com/sun/jna/Pointer.class"):
                    archive.writestr(name, b"old")
            with zipfile.ZipFile(new_jar, "w") as archive:
                for name in (
                    "com/sun/jna/Native.class",
                    "com/sun/jna/Pointer.class",
                    "com/sun/jna/SecurityManagerExposer.class",
                ):
                    archive.writestr(name, b"new")
            rows = [
                {
                    "coord": "net.java.dev.jna:jna",
                    "base_coord": "net.java.dev.jna:jna",
                    "old_version": "5.18.1",
                    "new_version": "-",
                    "change_type": "移除",
                    "base_lib_entry": "BOOT-INF/lib/jna-5.18.1.jar",
                    "_step4_base_jar_path": str(old_jar),
                },
                {
                    "coord": "net.java.dev.jna:jna-jpms",
                    "current_coord": "net.java.dev.jna:jna-jpms",
                    "old_version": "-",
                    "new_version": "5.19.0",
                    "change_type": "新增",
                    "current_lib_entry": "BOOT-INF/lib/jna-jpms-5.19.0.jar",
                    "_step4_current_jar_path": str(new_jar),
                },
            ]

            paired, evidence = step4.pair_artifact_replacement_rows(rows)

        self.assertEqual(len(paired), 1)
        self.assertEqual(paired[0]["base_coord"], "net.java.dev.jna:jna")
        self.assertEqual(paired[0]["current_coord"], "net.java.dev.jna:jna-jpms")
        self.assertEqual(paired[0]["coord"], "net.java.dev.jna:jna-jpms")
        self.assertEqual(paired[0]["old_version"], "5.18.1")
        self.assertEqual(paired[0]["new_version"], "5.19.0")
        self.assertEqual(paired[0]["pairing_status"], "artifact_class_set_replacement")
        self.assertEqual(evidence[0]["shared_classes"], 2)
        self.assertEqual(evidence[0]["old_class_coverage"], 1.0)

    def test_pair_artifact_replacements_compares_split_runtime_provider_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "core-1.jar"
            new_core = root / "core-2.jar"
            new_common = root / "common-2.jar"
            with zipfile.ZipFile(old_jar, "w") as archive:
                for name in ("p/A.class", "p/B.class", "p/C.class", "p/D.class"):
                    archive.writestr(name, name.encode())
            with zipfile.ZipFile(new_core, "w") as archive:
                for name in ("p/A.class", "p/B.class"):
                    archive.writestr(name, name.encode())
            with zipfile.ZipFile(new_common, "w") as archive:
                for name in ("p/C.class", "p/D.class", "p/E.class"):
                    archive.writestr(name, name.encode())
            rows = [
                {
                    "coord": "g:core", "base_coord": "g:core", "current_coord": "g:core",
                    "old_version": "1", "new_version": "2", "change_type": "大版本升级",
                    "_step4_base_jar_path": str(old_jar),
                    "_step4_current_jar_path": str(new_core),
                },
                {
                    "coord": "g:common", "current_coord": "g:common",
                    "old_version": "-", "new_version": "2", "change_type": "新增",
                    "_step4_current_jar_path": str(new_common),
                },
            ]

            paired, evidence = step4.pair_artifact_replacement_rows(rows)
            merged_path = Path(paired[0]["_step4_current_jar_path"])
            with zipfile.ZipFile(merged_path) as merged:
                merged_classes = {
                    name for name in merged.namelist() if name.endswith(".class")
                }

        self.assertEqual(len(paired), 1)
        self.assertEqual(paired[0]["pairing_status"], "artifact_provider_set_replacement")
        self.assertEqual(merged_classes, {
            "p/A.class", "p/B.class", "p/C.class", "p/D.class", "p/E.class",
        })
        self.assertEqual(evidence[0]["current_provider_count"], 2)

    def test_split_runtime_provider_set_prefers_primary_artifact_for_duplicate_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "core-1.jar"
            new_core = root / "z-core-2.jar"
            new_common = root / "a-common-2.jar"
            with zipfile.ZipFile(old_jar, "w") as archive:
                archive.writestr("p/A.class", b"old-a")
                archive.writestr("p/B.class", b"old-b")
            with zipfile.ZipFile(new_core, "w") as archive:
                archive.writestr("p/A.class", b"primary-a")
                archive.writestr("p/B.class", b"primary-b")
            with zipfile.ZipFile(new_common, "w") as archive:
                archive.writestr("p/A.class", b"companion-a")
                archive.writestr("p/B.class", b"companion-b")
                archive.writestr("p/C.class", b"companion-c")
            rows = [
                {
                    "coord": "g:core", "base_coord": "g:core", "current_coord": "g:core",
                    "old_version": "1", "new_version": "2", "change_type": "major",
                    "_step4_base_jar_path": str(old_jar),
                    "_step4_current_jar_path": str(new_core),
                },
                {
                    "coord": "g:common", "current_coord": "g:common",
                    "old_version": "-", "new_version": "2", "change_type": "new",
                    "_step4_current_jar_path": str(new_common),
                },
            ]

            paired, _evidence = step4.pair_artifact_replacement_rows(rows)
            with zipfile.ZipFile(paired[0]["_step4_current_jar_path"]) as merged:
                duplicate_payload = merged.read("p/A.class")

        self.assertEqual(duplicate_payload, b"primary-a")

    def test_pair_artifact_replacements_does_not_pair_cross_group_containment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            for path in (old_jar, new_jar):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("p/A.class", b"a")
                    archive.writestr("p/B.class", b"b")
            rows = [
                {"coord": "old.group:a", "old_version": "1", "new_version": "-",
                 "change_type": "移除", "_step4_base_jar_path": str(old_jar)},
                {"coord": "new.group:b", "old_version": "-", "new_version": "1",
                 "change_type": "新增", "_step4_current_jar_path": str(new_jar)},
            ]

            paired, evidence = step4.pair_artifact_replacement_rows(rows)

        self.assertEqual(len(paired), 2)
        self.assertEqual(evidence, [])

    def test_japicmp_xml_signature_erases_nested_generic_arguments_only_for_binary_identity(self):
        element = step4.ET.fromstring(
            '<method name="consume">'
            '<parameter type="java.util.Map&lt;java.lang.String, java.util.List&lt;java.lang.Long&gt;&gt;" />'
            '<parameter type="java.util.List&lt;? extends com.acme.Value&gt;[]" />'
            '</method>'
        )

        self.assertEqual(
            step4._xml_member_signature(element),
            '(java.util.Map, java.util.List[])',
        )
        self.assertEqual(
            step4.build_api_signature_from_types(['java.util.List<java.lang.String>']),
            '(java.util.List<java.lang.String>)',
        )

    def test_changed_dependencies_view_groups_api_rows_by_coord(self):
        rows = [
            {
                "coord": "com.acme:alpha",
                "change_type": "removed",
                "severity": "P1",
                "api_name": "com.acme.Alpha.removed",
                "symbol_kind": "method",
            },
            {
                "coord": "com.acme:alpha",
                "change_type": "signature_changed",
                "severity": "P2",
                "api_name": "com.acme.Alpha.changed",
                "symbol_kind": "method",
            },
            {
                "coord": "com.acme:beta",
                "change_type": "behavior_changed",
                "severity": "P0",
                "api_name": "com.acme.Beta.risky",
                "symbol_kind": "field",
            },
        ]

        result = step4.build_changed_dependency_rows(rows)

        self.assertEqual([item["coord"] for item in result], ["com.acme:alpha", "com.acme:beta"])
        self.assertEqual(result[0]["selection_key"], "coord:com.acme:alpha")
        self.assertEqual(result[0]["dependency_name"], "alpha")
        self.assertEqual(result[0]["changed_api_count"], 2)
        self.assertEqual(result[0]["high_risk_api_count"], 1)
        self.assertEqual(result[0]["change_types"], "removed, signature_changed")
        self.assertEqual(result[1]["high_risk_api_count"], 1)

    def test_write_changed_dependencies_outputs_csv_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            rows = [
                {
                    "coord": "com.acme:alpha",
                    "change_type": "removed",
                    "severity": "P1",
                    "api_name": "com.acme.Alpha.removed",
                    "symbol_kind": "method",
                }
            ]

            csv_path, md_path = step4.write_changed_dependencies(rows, output_dir)

            self.assertTrue(csv_path.exists())
            self.assertTrue(md_path.exists())
            csv_text = csv_path.read_text(encoding="utf-8")
            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("selection_key,coord,dependency_name,changed_api_count", csv_text)
            self.assertIn("coord:com.acme:alpha", csv_text)
            self.assertIn("本文件列出全部发生 API 变化", md_text)
            self.assertIn("## 如何选择定向分析范围", md_text)
            self.assertIn("复制“依赖包”列中的完整坐标", md_text)
            self.assertIn("只分析 com.example:demo-lib", md_text)
            self.assertIn("推荐依据是：含高风险 API、删除或签名变化，或变化 API 数不少于 20 个", md_text)
            self.assertIn("| 推荐候选 | 依赖包 |", md_text)
            self.assertIn("| 是 | `com.acme:alpha` |", md_text)
            self.assertIn("为什么先看", md_text)
            self.assertIn("含高风险 API，优先做系统触达分析", md_text)
            self.assertIn("`com.acme:alpha`", md_text)
            self.assertIn("完整 API 明细", md_text)

    def test_source_refs_compare_resolved_commits_not_only_branch_names(self):
        with patch.object(
            step4,
            "run_cmd",
            side_effect=[("same-commit\n", "", 0), ("same-commit\n", "", 0)],
        ):
            self.assertFalse(
                step4.source_refs_have_different_commits(
                    ["jua/base-artifact", "jua/current-artifact"],
                    "/repo",
                )
            )

        with patch.object(
            step4,
            "run_cmd",
            side_effect=[("base-commit\n", "", 0), ("current-commit\n", "", 0)],
        ):
            self.assertTrue(
                step4.source_refs_have_different_commits(["base", "current"], "/repo")
            )

    def test_source_refs_stay_conservative_when_commit_cannot_be_resolved(self):
        with patch.object(step4, "run_cmd", return_value=("", "missing", 1)):
            self.assertTrue(
                step4.source_refs_have_different_commits(["base", "current"], "/repo")
            )

    def test_write_readable_outputs_uses_human_first_summary_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            all_changed = output_dir / "all_changed_apis.csv"
            with all_changed.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=step4.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow({
                    "coord": "com.acme:api",
                    "api_name": "com.acme.Api.removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "confirmed": "true",
                    "source": "japicmp",
                })

            alerts_path, summary_path = step4.write_readable_outputs(
                dep_rows=[{"coord": "com.acme:api", "change_type": "小版本升级"}],
                output_dir=str(output_dir),
                all_apis=[{"coord": "com.acme:api"}],
                jar_missing_deps=[],
                japicmp_missing_deps=[],
                other_failed_deps=[],
                changed_deps_missing_source=[],
                valid_count=1,
                invalid_count=0,
            )

            summary_text = Path(summary_path).read_text(encoding="utf-8")
            with Path(alerts_path).open(encoding="utf-8") as f:
                alert_rows = list(csv.DictReader(f))

        self.assertIn("Step4 依赖 API 变化摘要", summary_text)
        self.assertLess(summary_text.index("一、先看什么"), summary_text.index("二、本次是否能进入 Step5"))
        self.assertLess(summary_text.index("二、本次是否能进入 Step5"), summary_text.index("三、复核入口"))
        self.assertIn(
            "如果只决定系统触达分析范围，先打开 changed_dependencies.md，复制“依赖包”列中的完整坐标",
            summary_text,
        )
        self.assertIn("- 变更 API 有效行：1", summary_text)
        self.assertIn("- 完整变更 API 清单：", summary_text)
        self.assertIn("附录：统计分布", summary_text)
        self.assertNotIn("generated_at=", summary_text)
        self.assertNotIn("all_changed_apis=", summary_text)
        self.assertEqual(
            ["conclusion", "change_summary", "review_reason"],
            list(alert_rows[0].keys())[:3],
        )
        self.assertEqual("需关注变更", alert_rows[0]["conclusion"])
        self.assertIn("删除方法，removed", alert_rows[0]["change_summary"])
        self.assertIn("严重级别 P1", alert_rows[0]["review_reason"])

    def test_human_checkpoint_uses_reader_friendly_console_format(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            step4.human_checkpoint_1(
                dep_rows=[{"coord": "com.acme:api", "change_type": "小版本升级"}],
                all_apis=[],
                output_dir="/tmp/report/evidence/api_changes",
            )

        output = stdout.getvalue()

        self.assertIn("【Step4 摘要】依赖 API 变化识别完成", output)
        self.assertIn("先看什么：", output)
        self.assertIn("本次是否能进入 Step5：", output)
        self.assertIn("changed_dependencies.md", output)
        self.assertIn("复核文件：", output)
        self.assertNotIn("人工抽查节点", output)
        self.assertNotIn("建议优先查看", output)

    def test_main_emits_japicmp_missing_checkpoint_before_degraded_step4(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            output_dir = report_dir / "s4_jar_compare"
            output_dir.mkdir(parents=True)
            dep_changes = report_dir / "s1_dep_changes.csv"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "com.acme:api,1.0.0,2.0.0,小版本升级,compile\n",
                encoding="utf-8",
            )
            context = report_dir / "s2_context.json"
            context.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.acme:api"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()

            with patch.dict("os.environ", {"JUA_ORCHESTRATED": "1"}), patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context),
                    "--output-dir",
                    str(output_dir),
                    "--japicmp-jar",
                    str(Path(tmp) / "missing-japicmp.jar"),
                ],
            ), patch.object(
                step4,
                "auto_install_japicmp",
                return_value=(False, str(Path(tmp) / "missing-japicmp.jar"), "network unavailable"),
            ) as install_mock, redirect_stdout(stdout), redirect_stderr(stderr):
                rc = step4.main()

            self.assertEqual(rc, 0)
            install_mock.assert_called_once()
            output = stdout.getvalue()
            self.assertIn(step4.INTERACTION_PREFIX, output)
            payload = json.loads(output.split(step4.INTERACTION_PREFIX, 1)[1].strip())
            self.assertEqual(payload["reason_code"], "step4_japicmp_missing_need_resolution")
            self.assertNotIn("allow_degraded", payload["response_schema"]["properties"])
            self.assertIn("japicmp_jar", payload["response_schema"]["properties"])
            self.assertEqual(
                payload["action_requirements"]["rerun_current_step"]["required_fields"],
                ["japicmp_jar"],
            )
            self.assertTrue((output_dir / "japicmp_preflight.json").exists())

    def test_parse_japicmp_xml_preserves_binary_and_source_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                """<japicmp><classes>
                <class name="com.acme.Api" changeStatus="MODIFIED" binaryCompatible="true" sourceCompatible="true">
                  <methods>
                    <method name="call" changeStatus="MODIFIED" binaryCompatible="true" sourceCompatible="false">
                      <parameters><parameter type="java.lang.String"/></parameters>
                      <compatibilityChanges><compatibilityChange type="METHOD_NEW_DEFAULT"/></compatibilityChanges>
                    </method>
                    <method name="gone" changeStatus="REMOVED" binaryCompatible="false" sourceCompatible="false"/>
                  </methods>
                </class></classes></japicmp>""",
                encoding="utf-8",
            )

            rows = step4.parse_japicmp_xml(xml_path, "com.acme:api", "1", "2")

        by_name = {row["api_name"]: row for row in rows}
        source_only = by_name["com.acme.Api.call"]
        self.assertEqual(source_only["change_type"], "SOURCE_INCOMPATIBLE")
        self.assertEqual(source_only["binary_compatible"], "true")
        self.assertEqual(source_only["source_compatible"], "false")
        self.assertEqual(source_only["api_signature"], "(java.lang.String)")
        self.assertIn("METHOD_NEW_DEFAULT", source_only["compatibility_flags"])
        self.assertEqual(by_name["com.acme.Api.gone"]["change_type"], "REMOVED")

    def test_parse_japicmp_xml_keeps_all_compatibility_flags_without_downgrading(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                """<japicmp><classes>
                <class name="com.acme.Api" changeStatus="MODIFIED" binaryCompatible="false" sourceCompatible="false">
                  <methods><method name="call" changeStatus="MODIFIED" binaryCompatible="false" sourceCompatible="false">
                    <compatibilityChanges>
                      <compatibilityChange type="METHOD_LESS_ACCESSIBLE"/>
                      <compatibilityChange type="METHOD_REMOVED_IN_SUPERCLASS"/>
                    </compatibilityChanges>
                  </method></methods>
                </class></classes></japicmp>""",
                encoding="utf-8",
            )
            rows = step4.parse_japicmp_xml(xml_path, "com.acme:api", "1", "2")

        self.assertEqual("SIGNATURE_CHANGED", rows[0]["change_type"])
        self.assertEqual("P0", rows[0]["severity"])
        self.assertEqual(
            "METHOD_LESS_ACCESSIBLE|METHOD_REMOVED_IN_SUPERCLASS",
            rows[0]["compatibility_flags"],
        )

    def test_removed_overload_remains_removed_when_sibling_overload_is_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                """<japicmp><classes><class name="org.apache.dubbo.common.URL" changeStatus="MODIFIED"
                binaryCompatible="false" sourceCompatible="false"><methods>
                <method name="valueOf" changeStatus="REMOVED" binaryCompatible="false" sourceCompatible="false">
                  <parameters><parameter type="java.lang.String"/></parameters>
                </method>
                <method name="valueOf" changeStatus="NEW" binaryCompatible="true" sourceCompatible="true">
                  <parameters><parameter type="java.net.URI"/></parameters>
                </method>
                </methods></class></classes></japicmp>""",
                encoding="utf-8",
            )
            rows = step4.parse_japicmp_xml(xml_path, "org.apache.dubbo:dubbo-common", "3.2", "3.3")

        self.assertEqual(1, len(rows))
        self.assertEqual("method", rows[0]["symbol_kind"])
        self.assertEqual("REMOVED", rows[0]["change_type"])
        self.assertEqual("(java.lang.String)", rows[0]["api_signature"])
        self.assertEqual("P0", rows[0]["severity"])

    def test_parse_japicmp_xml_preserves_constant_value_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                '<japicmp><classes><class name="com.acme.Flags" changeStatus="MODIFIED" '
                'binaryCompatible="true" sourceCompatible="true"><fields><field name="LIMIT" '
                'changeStatus="MODIFIED" binaryCompatible="true" sourceCompatible="true" '
                'oldValue="10" newValue="20"/></fields></class></classes></japicmp>',
                encoding="utf-8",
            )
            rows = step4.parse_japicmp_xml(xml_path, "com.acme:api", "1", "2")
        self.assertEqual(rows[0]["change_type"], "CONSTANT_VALUE_CHANGED")
        self.assertEqual((rows[0]["old_value"], rows[0]["new_value"]), ("10", "20"))

    def test_removed_compile_time_constant_preserves_inlining_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                '<japicmp><classes><class name="com.acme.Flags" changeStatus="MODIFIED" '
                'binaryCompatible="false" sourceCompatible="false"><fields><field name="LIMIT" '
                'changeStatus="REMOVED" binaryCompatible="false" sourceCompatible="false" '
                'oldValue="10"/></fields></class></classes></japicmp>',
                encoding="utf-8",
            )
            rows = step4.parse_japicmp_xml(xml_path, "com.acme:api", "1", "2")

        self.assertEqual(rows[0]["change_type"], "REMOVED")
        self.assertIn("CONSTANT_REMOVED", rows[0]["compatibility_flags"])
        self.assertEqual(rows[0]["old_value"], "10")

    def test_parse_japicmp_xml_ignores_nested_and_top_level_jdk_type_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "diff.xml"
            xml_path.write_text(
                """<japicmp><classes>
                <class name="io.seata.common.Foo" changeStatus="MODIFIED"
                       binaryCompatible="false" sourceCompatible="false">
                  <interfaces>
                    <interface name="java.io.Serializable" changeStatus="REMOVED"
                               binaryCompatible="false" sourceCompatible="false"/>
                    <interface name="java.lang.Comparable" changeStatus="REMOVED"
                               binaryCompatible="false" sourceCompatible="false"/>
                    <interface name="org.external.Marker" changeStatus="REMOVED"
                               binaryCompatible="false" sourceCompatible="false"/>
                  </interfaces>
                  <methods>
                    <method name="call" changeStatus="REMOVED"
                            binaryCompatible="false" sourceCompatible="false"/>
                  </methods>
                </class>
                <annotation name="java.lang.annotation.Annotation" changeStatus="REMOVED"
                            binaryCompatible="false" sourceCompatible="false"/>
                </classes></japicmp>""",
                encoding="utf-8",
            )

            rows = step4.parse_japicmp_xml(xml_path, "io.seata:seata-common", "1", "2")

        api_names = {row["api_name"] for row in rows}
        self.assertIn("io.seata.common.Foo", api_names)
        self.assertIn("io.seata.common.Foo.call", api_names)
        self.assertNotIn("java.io.Serializable", api_names)
        self.assertNotIn("java.lang.Comparable", api_names)
        self.assertNotIn("java.lang.annotation.Annotation", api_names)
        self.assertNotIn("org.external.Marker", api_names)

    def test_step4_default_timeouts_are_unbounded(self):
        self.assertIsNone(step4.DEFAULT_GIT_DIFF_TIMEOUT)
        self.assertIsNone(step4.DEFAULT_JAPICMP_TIMEOUT)
        self.assertIsNone(step4.DEFAULT_FETCH_TIMEOUT)

    def test_run_gitdiff_uses_no_timeout_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            repo_dir.mkdir(parents=True)
            (repo_dir / ".git").mkdir()
            lib_info = {
                "coord": "com.example:demo",
                "repo_path": str(repo_dir),
                "module_path": str(repo_dir),
                "old_version": "1.0.0",
                "new_version": "2.0.0",
            }
            captured = []

            def fake_run_cmd(cmd, cwd=None, timeout=None, **_kwargs):
                captured.append({"cmd": list(cmd), "cwd": cwd, "timeout": timeout})
                return "", "", 0

            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=("v1", "v2", "pair-old", "pair-new", [], []),
            ), \
                 patch.object(step4, "run_cmd", side_effect=fake_run_cmd):
                result = step4.run_gitdiff(lib_info, tmp)

        self.assertEqual(result["status"], "success")
        self.assertTrue(captured)
        self.assertIsNone(captured[0]["timeout"])

    def test_run_japicmp_uses_no_timeout_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")
            captured = {}

            def fake_run_cmd(_cmd, _cwd=None, timeout=None, **_kwargs):
                captured["timeout"] = timeout
                return "", "", 0

            with patch.object(step4, "run_cmd", side_effect=fake_run_cmd):
                step4.run_japicmp(
                    "com.example:demo",
                    "1.0.0",
                    "2.0.0",
                    tmp,
                    str(japicmp_jar),
                    old_jar_path=str(old_jar),
                    new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                )

        self.assertIsNone(captured["timeout"])

    def test_japicmp_tool_digest_is_reused_until_file_identity_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "japicmp.jar"
            tool.write_bytes(b"first")
            step4.clear_japicmp_tool_digest_cache()

            def read_tool_bytes(path):
                with Path.open(path, "rb") as handle:
                    return handle.read()

            with patch.object(
                step4.Path,
                "read_bytes",
                autospec=True,
                side_effect=read_tool_bytes,
            ) as read_bytes:
                first = step4.japicmp_tool_sha256(tool)
                repeated = step4.japicmp_tool_sha256(tool)
                tool.write_bytes(b"second-version")
                changed = step4.japicmp_tool_sha256(tool)

        self.assertEqual(first, repeated)
        self.assertNotEqual(first, changed)
        self.assertEqual(read_bytes.call_count, 2)

    def test_run_japicmp_reuses_valid_content_addressed_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "japicmp.jar"
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            cache_dir = root / "cache"
            tool.write_bytes(b"tool")
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")

            def successful_japicmp(cmd, **_kwargs):
                xml_path = Path(cmd[cmd.index("--xml-file") + 1])
                xml_path.write_text(
                    '<japicmp><classes><class name="com.acme.Api" '
                    'changeStatus="MODIFIED" binaryCompatible="false" '
                    'sourceCompatible="false"><methods><method name="gone" '
                    'changeStatus="REMOVED" binaryCompatible="false" '
                    'sourceCompatible="false"/></methods></class></classes></japicmp>',
                    encoding="utf-8",
                )
                return "japicmp-output", "", 0

            with patch.object(step4, "run_cmd", side_effect=successful_japicmp) as run_cmd:
                first = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )
                second = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )
                next(cache_dir.glob("*.json")).write_text("{broken", encoding="utf-8")
                recovered = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertEqual(first[1], second[1])
        self.assertEqual(first[1], recovered[1])
        self.assertIsNone(second[3])
        self.assertTrue(second[2]["comparison_cache_hit"])
        self.assertFalse(recovered[2]["comparison_cache_hit"])
        self.assertEqual(run_cmd.call_count, 2)

    def test_run_japicmp_does_not_cache_failed_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "japicmp.jar"
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            tool.write_bytes(b"tool")
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")

            with patch.object(
                step4, "run_cmd", return_value=("", "failed", 1)
            ) as run_cmd:
                for _ in range(2):
                    result = step4.run_japicmp(
                        "com.acme:api", "1", "2", root, str(tool),
                        old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                        old_jar_evidence={"source": "step1_final_artifact"},
                        new_jar_evidence={"source": "step1_final_artifact"},
                        cache_dir=root / "cache",
                    )

        self.assertIsNotNone(result[3])
        self.assertEqual(run_cmd.call_count, 2)

    def test_run_japicmp_uses_old_and_new_flags_and_rejects_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")

            with patch.object(
                step4,
                "run_cmd",
                return_value=("See '--help' or '-h' for more information.\n", "E: Required option -o, --old is missing.\n", 1),
            ) as run_cmd_mock:
                out_file, apis, jar_info, err = step4.run_japicmp(
                    "com.example:demo",
                    "1.0.0",
                    "2.0.0",
                    tmp,
                    str(japicmp_jar),
                    old_jar_path=str(old_jar),
                    new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                )
                content = Path(out_file).read_text(encoding="utf-8")

        called_cmd = run_cmd_mock.call_args.args[0]
        self.assertIn("--old", called_cmd)
        self.assertIn("--new", called_cmd)
        self.assertNotIn("--old-classpath", called_cmd)
        self.assertNotIn("--new-classpath", called_cmd)
        self.assertEqual(apis, [])
        self.assertEqual(jar_info["old_jar"], str(old_jar))
        self.assertEqual(jar_info["new_jar"], str(new_jar))
        self.assertIn("Required option -o, --old is missing.", err)
        self.assertIn("JApiCmp 执行失败（退出码 1）", content)
        self.assertIn("stderr:", content)
        self.assertIn("stdout:", content)

    def test_run_japicmp_uses_distinct_old_and_new_coords_when_group_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")

            with patch.object(step4, "run_cmd", return_value=("", "", 0)):
                out_file, apis, jar_info, err = step4.run_japicmp(
                    "tools.jackson.core:jackson-core",
                    "2.14.1",
                    "3.0.4",
                    tmp,
                    str(japicmp_jar),
                    old_coord="com.fasterxml.jackson.core:jackson-core",
                    new_coord="tools.jackson.core:jackson-core",
                    old_jar_path=str(old_jar),
                    new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                )
                content = Path(out_file).read_text(encoding="utf-8")

        self.assertIsNone(err)
        self.assertEqual(apis, [])
        self.assertEqual(jar_info["old_jar"], str(old_jar))
        self.assertEqual(jar_info["new_jar"], str(new_jar))
        self.assertIn("旧坐标：com.fasterxml.jackson.core:jackson-core", content)
        self.assertIn("新坐标：tools.jackson.core:jackson-core", content)

    def test_resolve_repo_ref_for_version_requires_unique_remote_branch_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "heads": [],
                    "remotes": ["origin/release-1.0.0", "upstream/support-1.0.0"],
                    "tags": ["release-1.0.0", "v1.0.0"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "1.0.0")

        self.assertIsNone(resolved)
        self.assertEqual(reason, "ambiguous_ref_matches_for_version=1.0.0")
        self.assertEqual(
            [item["ref"] for item in candidates if item["score"] == 140],
            ["origin/release-1.0.0", "upstream/support-1.0.0"],
        )
        self.assertEqual([item["ref"] for item in candidates], ["origin/release-1.0.0", "upstream/support-1.0.0"])

    def test_resolve_repo_ref_for_version_matches_branch_name_containing_normalized_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release-3.0.7-hotfix"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7-SNAPSHOT")

        self.assertEqual(resolved, "origin/release-3.0.7-hotfix")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.7)")
        self.assertEqual([item["ref"] for item in candidates], ["origin/release-3.0.7-hotfix"])

    def test_resolve_repo_ref_for_version_prefers_non_dev_branch_over_dev_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release-3.0.7-dev", "origin/release-3.0.7"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7")

        self.assertEqual(resolved, "origin/release-3.0.7")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.7)")
        self.assertEqual(
            [(item["ref"], item["score"]) for item in candidates],
            [("origin/release-3.0.7", 140), ("origin/release-3.0.7-dev", 130)],
        )

    def test_resolve_repo_ref_for_version_requires_manual_confirmation_when_full_version_not_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release/3.0.x", "origin/main"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7-SNAPSHOT")

        self.assertIsNone(resolved)
        self.assertEqual(reason, "no_ref_match_for_version=3.0.7")
        self.assertEqual(candidates, [])

    def test_preflight_gitdiff_refs_reports_pending_before_expensive_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            dep_rows = [
                {
                    "coord": "com.acme:acct-sdk",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "小版本升级",
                }
            ]
            dependency_paths = {
                "com.acme:acct-sdk": {
                    "repo_path": str(repo_dir),
                    "module_path": str(repo_dir),
                }
            }
            dependency_path_meta = {
                "com.acme:acct-sdk": {
                    "mapping_mode": "explicit",
                }
            }

            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(None, None, "miss-old", "miss-new", [], []),
            ):
                matched, pending = step4.preflight_gitdiff_refs(
                    dep_rows,
                    dependency_paths,
                    dependency_path_meta,
                    {},
                )

        self.assertEqual(matched, [])
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["coord"], "com.acme:acct-sdk")
        self.assertEqual(pending[0]["reason"], "无法定位对比 ref")

    def test_main_preflights_git_refs_before_japicmp_or_removed_jar_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            repo_dir = report_dir / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            japicmp_jar = report_dir / "japicmp.jar"
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "com.acme:acct-sdk,1.0.0,2.0.0,小版本升级,compile",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.acme:acct-sdk"}]}, ensure_ascii=False),
                encoding="utf-8",
            )

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                    "--japicmp-jar",
                    str(japicmp_jar),
                    "--dependency-repo-mappings",
                    f"com.acme:acct-sdk={repo_dir}",
                ],
            ), patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(None, None, "miss-old", "miss-new", [], []),
            ), patch.object(
                step4,
                "run_japicmp",
                side_effect=AssertionError("JApiCmp should not run before git ref confirmation"),
            ), patch.object(
                step4,
                "auto_install_japicmp",
                side_effect=AssertionError("JApiCmp install should not run before git ref confirmation"),
            ), patch.object(
                step4,
                "export_removed_jar_apis",
                side_effect=AssertionError("removed jar export should not run before git ref confirmation"),
            ):
                exit_code = step4.main()

            pending = json.loads((output_dir / "git_ref_pending.json").read_text(encoding="utf-8"))
            matches = json.loads((output_dir / "git_ref_matches.json").read_text(encoding="utf-8"))
            summary_text = (output_dir / "summary.txt").read_text(encoding="utf-8")
            with (report_dir / ".runtime/observability" / step4.STEP4_TIMING_FILE).open(encoding="utf-8") as fh:
                timing_rows = list(csv.DictReader(fh))

        self.assertEqual(exit_code, 2)
        self.assertEqual(len(pending["items"]), 1)
        self.assertEqual(pending["items"][0]["coord"], "com.acme:acct-sdk")
        self.assertTrue(matches["need_user_confirmation"])
        self.assertIn("Step4 依赖源码 git refs 预检摘要", summary_text)
        self.assertIn("一、结论总览", summary_text)
        self.assertIn("preflight.git_refs", {row["phase"] for row in timing_rows})
        self.assertIn("step4.total", {row["phase"] for row in timing_rows})
        self.assertEqual(timing_rows[-1]["status"], "awaiting_git_ref_confirmation")

    def test_main_writes_step4_timing_csv_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n",
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": []}, ensure_ascii=False),
                encoding="utf-8",
            )

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                    "--japicmp-jar",
                    str(report_dir / "missing-but-unused-japicmp.jar"),
                ],
            ):
                exit_code = step4.main()

            timing_path = report_dir / ".runtime/observability" / step4.STEP4_TIMING_FILE
            timing_exists = timing_path.exists()
            with timing_path.open(encoding="utf-8") as fh:
                timing_rows = list(csv.DictReader(fh))

        phases = {row["phase"] for row in timing_rows}
        self.assertEqual(exit_code, 0)
        self.assertTrue(timing_exists)
        self.assertIn("input.load", phases)
        self.assertIn("artifact_resolve", phases)
        self.assertIn("dependencies.process_all", phases)
        self.assertIn("write.all_changed_apis", phases)
        self.assertIn("step4.total", phases)
        self.assertEqual(timing_rows[-1]["status"], "done")

    def test_resolve_repo_ref_for_version_accepts_manual_override_when_no_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [],
                },
            ):
                with patch.object(step4, "_git_ref_exists", return_value=True):
                    resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                        tmp,
                        "3.5.14",
                        selected_ref="mybatis-3.5.14",
                    )

        self.assertEqual(resolved, "mybatis-3.5.14")
        self.assertEqual(reason, "selected_by_user(kind=manual,score=-1,version=3.5.14)")
        self.assertEqual(candidates, [])

    def test_resolve_repo_ref_for_version_accepts_branch_names_containing_exact_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": ["release-1.2.3"],
                    "heads": ["release/1.2.x"],
                    "remotes": ["origin/release-1.2.3", "origin/release/1.2.x", "origin/release-1.2.3-DEV"],
                },
            ):
                resolved_exact, reason_exact, candidates_exact = step4.resolve_repo_ref_for_version(tmp, "1.2.3")

        self.assertEqual(resolved_exact, "origin/release-1.2.3")
        self.assertEqual(reason_exact, "matched_by_version(kind=remote,score=140,version=1.2.3)")
        self.assertEqual(
            [(item["ref"], item["score"]) for item in candidates_exact],
            [("origin/release-1.2.3", 140), ("origin/release-1.2.3-DEV", 130)],
        )

    def test_resolve_repo_ref_for_version_requires_strict_boundary_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/auth-sdk3.0.2", "origin/auth-sdk3.0.2.1"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.2")

        self.assertEqual(resolved, "origin/auth-sdk3.0.2")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.2)")
        self.assertEqual(
            [(item["ref"], item["score"], item["match_kind"]) for item in candidates],
            [
                ("origin/auth-sdk3.0.2", 140, "exact_boundary"),
            ],
        )

    def test_resolve_repo_ref_for_version_allows_separator_suffix_but_rejects_letter_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/auth-sdk3.0.2-DEV", "origin/auth-sdk3.0.2SB3"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.2")

        self.assertEqual(resolved, "origin/auth-sdk3.0.2-DEV")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=130,version=3.0.2)")
        self.assertEqual(
            [(item["ref"], item["score"], item["match_kind"]) for item in candidates],
            [
                ("origin/auth-sdk3.0.2-DEV", 130, "exact_boundary"),
            ],
        )

    def test_resolve_repo_ref_pair_for_versions_prefers_same_prefix_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/auth-sdk3.0.2",
                        "origin/release-3.0.2",
                        "origin/auth-sdk3.12.0-SB3",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    old_candidates,
                    new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.2", "3.12.0-SB3")

        self.assertEqual(resolved_old, "origin/auth-sdk3.0.2")
        self.assertEqual(resolved_new, "origin/auth-sdk3.12.0-SB3")
        self.assertIn("matched_by_version_pair(", old_reason)
        self.assertIn("matched_by_version_pair(", new_reason)
        self.assertIn("same_prefix=true", old_reason)
        self.assertIn("same_remote=true", old_reason)
        self.assertEqual(
            [item["ref"] for item in old_candidates],
            ["origin/auth-sdk3.0.2", "origin/release-3.0.2"],
        )
        self.assertEqual(
            [item["ref"] for item in new_candidates],
            ["origin/auth-sdk3.12.0-SB3"],
        )

    def test_resolve_repo_ref_pair_for_versions_prefers_pair_delta_matching_version_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/acct-sdk3.0.8",
                        "origin/acct-sdk3.0.8-SB3",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    old_candidates,
                    new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.8-SNAPSHOT", "3.0.8-SB3-SNAPSHOT")

        self.assertEqual(resolved_old, "origin/acct-sdk3.0.8")
        self.assertEqual(resolved_new, "origin/acct-sdk3.0.8-SB3")
        self.assertIn("delta_match=exact", old_reason)
        self.assertIn("delta_match=exact", new_reason)
        self.assertEqual(
            [item["ref"] for item in old_candidates],
            ["origin/acct-sdk3.0.8", "origin/acct-sdk3.0.8-SB3"],
        )
        self.assertEqual(
            [item["ref"] for item in new_candidates],
            ["origin/acct-sdk3.0.8-SB3"],
        )

    def test_resolve_repo_ref_pair_for_versions_matches_generic_token_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/acct-sdk-ee8-3.0.8",
                        "origin/acct-sdk-ee9-3.0.8",
                        "origin/acct-sdk3.0.8",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    _old_candidates,
                    _new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.8-EE8", "3.0.8-EE9")

        self.assertEqual(resolved_old, "origin/acct-sdk-ee8-3.0.8")
        self.assertEqual(resolved_new, "origin/acct-sdk-ee9-3.0.8")
        self.assertIn("delta_match=exact", old_reason)
        self.assertIn("delta_match=exact", new_reason)

    def test_infer_maven_coord_locations_scans_more_than_80_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx in range(120):
                module_dir = root / f"module-{idx:03d}"
                module_dir.mkdir(parents=True)
                (module_dir / "pom.xml").write_text(
                    "\n".join(
                        [
                            "<project>",
                            "  <modelVersion>4.0.0</modelVersion>",
                            f"  <groupId>com.example</groupId>",
                            f"  <artifactId>module-{idx:03d}</artifactId>",
                            "  <version>1.0.0</version>",
                            "</project>",
                        ]
                    ),
                    encoding="utf-8",
                )

            locations = compat.infer_maven_coord_locations(str(root))
            coords = [item.get("coord") for item in locations if item.get("coord")]
            self.assertEqual(len(coords), 120)
            self.assertEqual(coords[0], "com.example:module-000")
            self.assertEqual(coords[-1], "com.example:module-119")

    def test_infer_maven_coord_locations_infers_gradle_submodule_group_from_repo_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "spring-boot-autoconfigure"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text(
                'description = "Spring Boot AutoConfigure"\n',
                encoding="utf-8",
            )

            locations = compat.infer_maven_coord_locations(str(root))
            by_coord = {item.get("coord"): item for item in locations if item.get("coord")}

        self.assertIn("org.springframework.boot:spring-boot-autoconfigure", by_coord)
        self.assertEqual(
            by_coord["org.springframework.boot:spring-boot-autoconfigure"]["module_dir"],
            str(module_dir.resolve()),
        )
        self.assertEqual(
            by_coord["org.springframework.boot:spring-boot-autoconfigure"]["repo_root"],
            str(root.resolve()),
        )

    def test_infer_maven_coord_locations_skips_aggregate_root_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "spring-boot"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text(
                'description = "Spring Boot"\n',
                encoding="utf-8",
            )
            (module_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            locations = compat.infer_maven_coord_locations(str(root))
            spring_boot_locations = [
                item for item in locations if item.get("coord") == "org.springframework.boot:spring-boot"
            ]

        self.assertEqual(len(spring_boot_locations), 1)
        self.assertEqual(
            spring_boot_locations[0]["module_dir"],
            str(module_dir.resolve()),
        )

    def test_infer_maven_coord_locations_skips_embedded_resource_sample_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "com.example"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "demo"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text('description = "Demo"\n', encoding="utf-8")
            (module_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)

            sample_dir = root / "buildSrc" / "src" / "test" / "resources" / "samples" / "spring-boot-project" / "spring-boot"
            sample_dir.mkdir(parents=True)
            (sample_dir / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            locations = compat.infer_maven_coord_locations(str(root))
            coords = {item.get("coord") for item in locations if item.get("coord")}

        self.assertIn("com.example:demo", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_discover_bridge_source_mappings_skips_embedded_resource_sample_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "com.example"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "demo"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text('description = "Demo"\n', encoding="utf-8")
            (module_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)
            (module_dir / "src" / "main" / "java" / "com" / "example" / "Demo.java").write_text(
                "package com.example;\nclass Demo {}\n",
                encoding="utf-8",
            )

            sample_dir = root / "buildSrc" / "src" / "test" / "resources" / "samples" / "spring-boot-project" / "spring-boot"
            sample_dir.mkdir(parents=True)
            (sample_dir / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot" / "Sample.java").write_text(
                "package org.springframework.boot;\nclass Sample {}\n",
                encoding="utf-8",
            )

            mappings = auto_sources.discover_bridge_source_mappings("", str(root))
            coords = {coord for coord, _source_dir in mappings}

        self.assertIn("com.example:demo", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_infer_maven_coord_locations_does_not_scan_sibling_repo_from_workspace_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".git").mkdir()

            security_repo = workspace / "_dependency_sources" / "spring-security"
            security_repo.mkdir(parents=True)
            (security_repo / ".git").mkdir()
            (security_repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            security_module = security_repo / "web"
            security_module.mkdir()
            (security_module / "build.gradle").write_text('description = "Web"\n', encoding="utf-8")
            (security_module / "src" / "main" / "java" / "org" / "springframework" / "security").mkdir(parents=True)

            boot_repo = workspace / "_dependency_sources" / "spring-boot"
            boot_repo.mkdir(parents=True)
            (boot_repo / ".git").mkdir()
            (boot_repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            boot_module = boot_repo / "spring-boot-project" / "spring-boot"
            boot_module.mkdir(parents=True)
            (boot_module / "build.gradle").write_text('description = "Spring Boot"\n', encoding="utf-8")
            (boot_module / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            coords = {
                item.get("coord")
                for item in compat.infer_maven_coord_locations(str(security_repo))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:web", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_infer_maven_coord_locations_supports_named_gradle_module_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            core_dir = root / "core"
            core_dir.mkdir(parents=True)
            (core_dir / "spring-security-core.gradle").write_text(
                "description = 'Core'\n",
                encoding="utf-8",
            )
            (core_dir / "src" / "main" / "java" / "org" / "springframework" / "security" / "core").mkdir(parents=True)

            by_coord = {
                item.get("coord"): item
                for item in compat.infer_maven_coord_locations(str(root))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:spring-security-core", by_coord)
        self.assertEqual(
            by_coord["org.springframework.security:spring-security-core"]["module_dir"],
            str(core_dir.resolve()),
        )

    def test_infer_maven_coord_locations_ignores_task_group_assignment_when_inferring_group_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            web_dir = root / "web"
            web_dir.mkdir(parents=True)
            (web_dir / "spring-security-web.gradle").write_text(
                "\n".join(
                    [
                        "tasks.register('syncJavascript') {",
                        "    group = 'Build'",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (web_dir / "src" / "main" / "java" / "org" / "springframework" / "security" / "web").mkdir(parents=True)

            by_coord = {
                item.get("coord"): item
                for item in compat.infer_maven_coord_locations(str(root))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:spring-security-web", by_coord)
        self.assertEqual(
            by_coord["org.springframework.security:spring-security-web"]["module_dir"],
            str(web_dir.resolve()),
        )

    def test_infer_maven_coord_locations_prioritizes_main_gradle_modules_before_test_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            boot_dir = root / "spring-boot-project" / "spring-boot"
            boot_dir.mkdir(parents=True)
            (boot_dir / "build.gradle").write_text("description = 'Spring Boot'\n", encoding="utf-8")
            (boot_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            auto_dir = root / "spring-boot-project" / "spring-boot-autoconfigure"
            auto_dir.mkdir(parents=True)
            (auto_dir / "build.gradle").write_text(
                "description = 'Spring Boot AutoConfigure'\n",
                encoding="utf-8",
            )
            (auto_dir / "src" / "main" / "java" / "org" / "springframework" / "boot" / "autoconfigure").mkdir(parents=True)

            for index in range(20):
                smoke_dir = root / "spring-boot-tests" / "spring-boot-smoke-tests" / f"spring-boot-smoke-test-{index:02d}"
                smoke_dir.mkdir(parents=True)
                (smoke_dir / "build.gradle").write_text(
                    f"description = 'Smoke {index}'\n",
                    encoding="utf-8",
                )
                (smoke_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)

            coords = compat.infer_maven_coords(str(root), max_poms=2)

        self.assertEqual(
            coords,
            [
                "org.springframework.boot:spring-boot",
                "org.springframework.boot:spring-boot-autoconfigure",
            ],
        )

    def test_is_ephemeral_dependency_source_mapping_detects_hoisted_workspace_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".git").mkdir()
            module_dir = (
                workspace
                / ".tmp-validation"
                / "dependency-sources"
                / "org.yaml__snakeyaml__1.30"
                / "META-INF"
                / "maven"
                / "org.yaml"
                / "snakeyaml"
            )
            module_dir.mkdir(parents=True)

            self.assertTrue(
                step4.is_ephemeral_dependency_source_mapping(
                    {
                        "repo_path": str(workspace),
                        "module_path": str(module_dir),
                    }
                )
            )
            self.assertFalse(
                step4.is_ephemeral_dependency_source_mapping(
                    {
                        "repo_path": str(module_dir),
                        "module_path": str(module_dir),
                    }
                )
            )

    def test_extract_api_signature_handles_nested_annotations_and_kotlin_style(self):
        java_decl = "public void update(@Named(value = \"user\", required = true) List<Map<String, Long>> users, String[] tags)"
        kotlin_decl = "fun update(user: Map<String, List<Long>>, tag: String? = \"x\")"

        self.assertEqual(
            step4.extract_api_signature_from_declaration(java_decl),
            "(List<Map<String, Long>>, String[])",
        )
        self.assertEqual(
            step4.extract_api_signature_from_declaration(kotlin_decl),
            "(Map<String, List<Long>>, String?)",
        )

    def test_extract_api_signature_returns_unit_tuple_for_noarg_method(self):
        self.assertEqual(
            step4.extract_api_signature_from_declaration("public static void removeAll() {"),
            "()",
        )

    def test_run_gitdiff_requests_user_confirmation_when_refs_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            (repo_dir / ".git").mkdir()
            output_dir = repo_dir / "out"
            output_dir.mkdir()

            with patch.object(step4, "resolve_repo_ref_for_version", side_effect=[(None, "miss-old", []), (None, "miss-new", [])]):
                with patch.object(step4, "_list_repo_refs", return_value={"tags": ["v1.0.0"], "heads": [], "remotes": ["origin/2.0.0"]}):
                    result = step4.run_gitdiff(
                        {
                            "coord": "com.example:demo",
                            "repo_path": str(repo_dir),
                            "module_path": str(repo_dir),
                            "old_version": "1.0.0",
                            "new_version": "2.0.0",
                        },
                        str(output_dir),
                    )

            self.assertEqual(result["status"], "needs_user_confirmation")
            self.assertEqual(result["error"], "无法定位对比 ref")
            self.assertEqual(result["meta"]["coord"], "com.example:demo")

    def test_parse_gitdiff_apis_resets_scope_for_sibling_class(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/java/com/example/Foo.java b/src/main/java/com/example/Foo.java",
                "--- a/src/main/java/com/example/Foo.java",
                "+++ b/src/main/java/com/example/Foo.java",
                "@@",
                " package com.example;",
                " class Outer {",
                "     class Inner {",
                "     }",
                " }",
                " class Sibling {",
                "-    public void ping(String value) {",
                "+    public void ping(Integer value) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "com.example.Sibling.ping")
        self.assertEqual(apis[0]["change_type"], "SIGNATURE_CHANGED")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_parse_gitdiff_apis_skips_test_source_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/common/src/test/java/io/netty/util/RecyclerTest.java b/common/src/test/java/io/netty/util/RecyclerTest.java",
                "--- a/common/src/test/java/io/netty/util/RecyclerTest.java",
                "+++ b/common/src/test/java/io/netty/util/RecyclerTest.java",
                "@@",
                " package io.netty.util;",
                "-public class RecyclerTest {",
                "+public class RecyclerTest {",
                "-    public void run(int threads) {",
                "+    public void run(int threads, int batchSize) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "io.netty:netty-common", "4.1.83.Final", "4.1.89.Final")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_skips_root_relative_test_source_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java b/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "--- a/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "+++ b/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "@@",
                " package org.apache.ibatis.submitted.awful_table;",
                "-public class AwfulTable {",
                "+public class AwfulTable {",
                "-    public void setCustomerId(Integer id) {",
                "+    public void setCustomerId(Long id) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "org.mybatis:mybatis", "3.5.9", "3.5.14")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_skips_build_support_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/.mvn/wrapper/MavenWrapperDownloader.java b/.mvn/wrapper/MavenWrapperDownloader.java",
                "--- a/.mvn/wrapper/MavenWrapperDownloader.java",
                "+++ b/.mvn/wrapper/MavenWrapperDownloader.java",
                "@@",
                " package .mvn.wrapper;",
                "-public class MavenWrapperDownloader {",
                "+public class MavenWrapperDownloader {",
                "-    public void run(String url) {",
                "+    public void run(String url, String checksum) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "org.mybatis:mybatis", "3.5.9", "3.5.14")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_collects_multiline_method_signature(self):
        diff_output = "\n".join(
            [
                "diff --git a/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java b/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "--- a/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "+++ b/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "@@",
                " package io.netty.util.concurrent;",
                " public final class FastThreadLocal<V> {",
                "     private static void removeFromVariablesToRemove(",
                "             InternalThreadLocalMap threadLocalMap, FastThreadLocal<?> variable) {",
                "-        Object v = threadLocalMap.indexedVariable(variablesToRemoveIndex);",
                "+        Object v = threadLocalMap.removeIndexedVariable(variablesToRemoveIndex);",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "io.netty:netty-common", "4.1.83.Final", "4.1.89.Final")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "io.netty.util.concurrent.FastThreadLocal.removeFromVariablesToRemove")
        self.assertEqual(apis[0]["api_signature"], "(InternalThreadLocalMap, FastThreadLocal<?>)")

    def test_parse_gitdiff_apis_detects_kotlin_method_with_explicit_visibility(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/kotlin/com/example/Demo.kt b/src/main/kotlin/com/example/Demo.kt",
                "--- a/src/main/kotlin/com/example/Demo.kt",
                "+++ b/src/main/kotlin/com/example/Demo.kt",
                "@@",
                " package com.example",
                " class Demo {",
                "-    public fun load(name: String) {",
                "+    public fun load(id: Long) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "com.example.Demo.load")
        self.assertEqual(apis[0]["change_type"], "SIGNATURE_CHANGED")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_gitdiff_structural_changes_are_auxiliary_when_jar_is_primary_truth(self):
        rows = [
            {
                "coord": "com.example:demo",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "REMOVED",
                "api_name": "com.example.Dto.getName",
                "api_simple": "getName",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P1",
                "source": "gitdiff",
            },
            {
                "coord": "com.example:demo",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "BEHAVIOR_CHANGED",
                "api_name": "com.example.Service.run",
                "api_simple": "run",
                "symbol_kind": "method",
                "api_signature": "(String)",
                "confirmed": "true",
                "severity": "P2",
                "source": "gitdiff",
            },
        ]
        jar_index = {
            "classes": {"com.example.Dto", "com.example.Service"},
            "members": {
                ("com.example.Dto.getName", "method", "()"),
                ("com.example.Service.run", "method", "(String)"),
            },
            "errors": [],
        }

        with patch.object(step4, "_jar_public_api_index", return_value=jar_index):
            accepted, rejected = step4.filter_gitdiff_rows_with_jar_truth(
                rows,
                old_jar="/tmp/old.jar",
                new_jar="/tmp/new.jar",
                coord="com.example:demo",
                old_ver="1.0.0",
                new_ver="2.0.0",
            )

        self.assertEqual([item["api_name"] for item in accepted], ["com.example.Service.run"])
        self.assertEqual([item["api_name"] for item in rejected], ["com.example.Dto.getName"])
        self.assertEqual(
            rejected[0]["filter_reason"],
            "source_structural_change_not_promoted_japicmp_is_primary",
        )

    def test_gitdiff_behavior_change_requires_member_in_both_jars(self):
        row = {
            "coord": "com.example:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "BEHAVIOR_CHANGED",
            "api_name": "com.example.Dto.getName",
            "api_simple": "getName",
            "symbol_kind": "method",
            "api_signature": "()",
            "confirmed": "true",
            "severity": "P2",
            "source": "gitdiff",
        }
        old_index = {
            "classes": {"com.example.Dto"},
            "members": {("com.example.Dto.getName", "method", "()")},
            "errors": [],
        }
        new_index = {
            "classes": {"com.example.Dto"},
            "members": set(),
            "errors": [],
        }

        with patch.object(step4, "_jar_public_api_index", side_effect=[old_index, new_index]):
            accepted, rejected = step4.filter_gitdiff_rows_with_jar_truth(
                [row],
                old_jar="/tmp/old.jar",
                new_jar="/tmp/new.jar",
                coord="com.example:demo",
                old_ver="1.0.0",
                new_ver="2.0.0",
            )

        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("new_jar_member_missing", rejected[0]["filter_reason"])

    def test_gitdiff_jar_truth_accepts_normalized_java_lang_signature(self):
        row = {
            "coord": "com.example:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "BEHAVIOR_CHANGED",
            "api_name": "com.example.Service.run",
            "api_simple": "run",
            "symbol_kind": "method",
            "api_signature": "(String)",
            "confirmed": "true",
            "severity": "P2",
            "source": "gitdiff",
        }
        jar_index = {
            "classes": {"com.example.Service"},
            "members": {("com.example.Service.run", "method", "(String)")},
            "errors": [],
        }

        with patch.object(step4, "_jar_public_api_index", return_value=jar_index):
            accepted, rejected = step4.filter_gitdiff_rows_with_jar_truth(
                [row],
                old_jar="/tmp/old.jar",
                new_jar="/tmp/new.jar",
                coord="com.example:demo",
                old_ver="1.0.0",
                new_ver="2.0.0",
            )

        self.assertEqual(len(accepted), 1)
        self.assertEqual(rejected, [])

    def test_step5_input_dedup_prefers_japicmp_over_gitdiff_for_same_api(self):
        base = {
            "coord": "com.example:demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "SIGNATURE_CHANGED",
            "api_name": "com.example.Service.run",
            "api_simple": "run",
            "symbol_kind": "method",
            "api_signature": "(String)",
            "confirmed": "true",
            "severity": "P1",
        }
        rows = [
            {**base, "source": "gitdiff", "reason_code": "source_only"},
            {**base, "source": "japicmp", "reason_code": "binary_or_source_incompatible"},
        ]

        normalized = step4.normalize_step5_input_rows(rows)

        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["source"], "japicmp")
        self.assertEqual(normalized[0]["reason_code"], "binary_or_source_incompatible")

    def test_parse_japicmp_output_prefers_terminal_method_in_chained_expression(self):
        output = (
            "***! MODIFIED METHOD: "
            "org.example.XmlUtil.from(java.lang.String)."
            "to(java.lang.String)."
            "UniversalNamespaceCache.getPrefixes()"
        )

        apis = step4.parse_japicmp_output(output, "org.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(
            apis[0]["api_name"],
            "org.example.UniversalNamespaceCache.getPrefixes",
        )
        self.assertEqual(apis[0]["api_signature"], "()")
        self.assertEqual(apis[0]["source"], "japicmp")

    def test_parse_japicmp_output_keeps_regular_method_signature(self):
        output = "***! REMOVED METHOD: org.example.Foo.load(java.lang.String, int[])"

        apis = step4.parse_japicmp_output(output, "org.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "org.example.Foo.load")
        self.assertEqual(apis[0]["api_signature"], "(java.lang.String, int[])")
        self.assertEqual(apis[0]["change_type"], "REMOVED")

    def test_parse_japicmp_output_uses_declaring_type_for_h2_removed_method(self):
        output = "\n".join(
            [
                "***! MODIFIED INTERFACE: PUBLIC ABSTRACT org.h2.command.CommandInterface  (not serializable)",
                "---! REMOVED METHOD: PUBLIC(-) ABSTRACT(-) org.h2.result.ResultInterface executeQuery(int, boolean)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.command.CommandInterface.executeQuery")
        self.assertEqual(apis[1]["api_signature"], "(int, boolean)")
        self.assertEqual(apis[1]["symbol_kind"], "method")
        self.assertEqual(apis[1]["change_type"], "REMOVED")

    def test_parse_japicmp_output_uses_declaring_type_for_h2_modified_method(self):
        output = "\n".join(
            [
                "***! MODIFIED INTERFACE: PUBLIC ABSTRACT org.h2.api.Aggregate  (not serializable)",
                "***! MODIFIED METHOD: PUBLIC NON_ABSTRACT (<- ABSTRACT) void init(java.sql.Connection)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.api.Aggregate.init")
        self.assertEqual(apis[1]["api_signature"], "(java.sql.Connection)")
        self.assertEqual(apis[1]["symbol_kind"], "method")
        self.assertEqual(apis[1]["change_type"], "SIGNATURE_CHANGED")

    def test_parse_japicmp_output_uses_declaring_type_for_removed_constructor(self):
        output = "\n".join(
            [
                "---! REMOVED CLASS: PUBLIC(-) FINAL(-) org.h2.api.TimestampWithTimeZone  (class removed)",
                "\t---! REMOVED INTERFACE: java.lang.Cloneable",
                "\t---! REMOVED INTERFACE: java.io.Serializable",
                "---! REMOVED CONSTRUCTOR: PUBLIC(-) TimestampWithTimeZone(long, long, short)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(
            apis[1]["api_name"],
            "org.h2.api.TimestampWithTimeZone.TimestampWithTimeZone",
        )
        self.assertEqual(apis[1]["api_signature"], "(long, long, short)")
        self.assertEqual(apis[1]["symbol_kind"], "constructor")
        self.assertEqual(apis[1]["change_type"], "REMOVED")
        self.assertEqual(apis[0]["api_name"], "org.h2.api.TimestampWithTimeZone")

    def test_parse_japicmp_output_uses_declaring_type_for_modified_field(self):
        output = "\n".join(
            [
                "***! MODIFIED CLASS: PUBLIC ABSTRACT org.h2.command.Command  (not serializable)",
                "***! MODIFIED FIELD: PROTECTED FINAL org.h2.engine.SessionLocal (<- org.h2.engine.Session) session",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.command.Command.session")
        self.assertEqual(apis[1]["api_signature"], "")
        self.assertEqual(apis[1]["symbol_kind"], "field")
        self.assertEqual(apis[1]["change_type"], "SIGNATURE_CHANGED")

    def test_parse_gitdiff_apis_ignores_comment_text_when_tracking_class_scope(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/java/org/example/Real.java b/src/main/java/org/example/Real.java",
                "--- a/src/main/java/org/example/Real.java",
                "+++ b/src/main/java/org/example/Real.java",
                "@@",
                " package org.example;",
                "+ // object FakeObject",
                "-    public void load(String value) {",
                "+    public void load(Integer value) {",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "org.example.Real.load")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_write_git_ref_match_outputs_marks_confirmation_only_when_pending_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path, txt_path = step4.write_git_ref_match_outputs(
                output_dir=tmp,
                gitdiff_runs=[
                    {
                        "coord": "com.example:demo",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "base_ref": "v1.0.0",
                        "cur_ref": "v2.0.0",
                        "old_match_reason": "matched",
                        "new_match_reason": "matched",
                        "old_candidates": [{"ref": "v1.0.0"}],
                        "new_candidates": [{"ref": "v2.0.0"}],
                    }
                ],
                gitdiff_pending=[],
                gitdiff_skipped=[],
                source_repo_mappings=[],
            )
            payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
            text = Path(txt_path).read_text(encoding="utf-8")

        self.assertFalse(payload["need_user_confirmation"])
        self.assertIn("Step4 依赖源码 git ref 匹配结果（自动匹配完成）", text)
        self.assertIn("一、结论总览", text)
        self.assertNotIn("generated_at=", text)

    def test_cleanup_step4_generated_outputs_removes_stale_generated_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            stale_gitdiff = output_dir / "demo-lib_gitdiff_api_changes.txt"
            stale_summary = output_dir / "summary.txt"
            unrelated = output_dir / "keep.me"
            stale_gitdiff.write_text("old diff", encoding="utf-8")
            stale_summary.write_text("old summary", encoding="utf-8")
            unrelated.write_text("keep", encoding="utf-8")

            step4.cleanup_step4_generated_outputs(output_dir)

            self.assertFalse(stale_gitdiff.exists())
            self.assertFalse(stale_summary.exists())
            self.assertTrue(unrelated.exists())

    def test_main_prefers_step1_packaged_jars_for_japicmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            base_artifact = report_dir / "base-app.jar"
            current_artifact = report_dir / "current-app.jar"
            base_entry = "BOOT-INF/lib/demo-1.0.0.jar"
            current_entry = "BOOT-INF/lib/demo-2.0.0.jar"
            with zipfile.ZipFile(base_artifact, "w") as zf:
                zf.writestr(base_entry, b"base demo jar")
                zf.writestr("BOOT-INF/lib/stable-1.0.0.jar", b"stable jar")
            with zipfile.ZipFile(current_artifact, "w") as zf:
                zf.writestr(current_entry, b"current demo jar")
                zf.writestr("BOOT-INF/lib/stable-1.0.0.jar", b"stable jar")
            dependencies_dir = report_dir / "dependencies"
            dependencies_dir.mkdir()
            (dependencies_dir / "build_provenance.json").write_text(
                json.dumps(
                    {
                        "sides": [
                            {"side": "base", "artifact_path": str(base_artifact), "artifact_sha256": "base-sha"},
                            {"side": "current", "artifact_path": str(current_artifact), "artifact_sha256": "current-sha"},
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope,base_coord,current_coord,base_lib_entry,current_lib_entry",
                        f"com.example:demo,1.0.0,2.0.0,小版本升级,compile,com.example:demo,com.example:demo,{base_entry},{current_entry}",
                        "com.example:stable,1.0.0,1.0.0,未变,compile,com.example:stable,com.example:stable,BOOT-INF/lib/stable-1.0.0.jar,BOOT-INF/lib/stable-1.0.0.jar",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.example:demo"}]}, ensure_ascii=False),
                encoding="utf-8",
            )

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                    "--workers",
                    "2",
                ],
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(output_dir / "demo_binary.txt"), [], {"old_jar": "", "new_jar": ""}, None),
            ) as japicmp_mock, patch.object(
                step4,
                "fetch_jar_from_repo",
                side_effect=AssertionError("Step1 packaged jars should avoid Maven fetch"),
                create=True,
            ):
                exit_code = step4.main()

            self.assertEqual(exit_code, 0)
            japicmp_mock.assert_called_once()
            kwargs = japicmp_mock.call_args.kwargs
            self.assertEqual(kwargs["old_jar_evidence"]["source"], "step1_final_artifact")
            self.assertEqual(kwargs["new_jar_evidence"]["source"], "step1_final_artifact")
            self.assertTrue(Path(kwargs["old_jar_path"]).exists())
            self.assertTrue(Path(kwargs["new_jar_path"]).exists())
            self.assertEqual(Path(kwargs["old_jar_path"]).read_bytes(), b"base demo jar")
            self.assertEqual(Path(kwargs["new_jar_path"]).read_bytes(), b"current demo jar")
            self.assertFalse(any(
                "stable" in path.name
                for path in (output_dir / "step4_artifact_jars").rglob("*.jar")
            ))

    def test_main_processes_dependencies_in_parallel_when_workers_gt_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "com.example:demo-a,1.0.0,2.0.0,小版本升级,compile",
                        "com.example:demo-b,1.0.0,2.0.0,小版本升级,compile",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps(
                    {
                        "changed_dependencies": [
                            {"coord": "com.example:demo-a"},
                            {"coord": "com.example:demo-b"},
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            barrier = threading.Barrier(2)
            seen_threads = set()

            def fake_run_japicmp(coord, *_args, **_kwargs):
                seen_threads.add(threading.current_thread().name)
                barrier.wait(timeout=2)
                return str(output_dir / f"{coord.rsplit(':', 1)[-1]}_binary.txt"), [], {"old_jar": "", "new_jar": ""}, None

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                    "--workers",
                    "2",
                ],
            ), patch.object(step4, "run_japicmp", side_effect=fake_run_japicmp) as japicmp_mock:
                exit_code = step4.main()

            self.assertEqual(exit_code, 0)
            self.assertEqual(japicmp_mock.call_count, 2)
            self.assertGreaterEqual(len(seen_threads), 2)

    def test_main_removed_dependency_exports_old_jar_symbols_and_writes_per_dependency_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            output_dir = report_dir / "s4_jar_compare"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope,base_coord",
                        "com.example:legacy-lib,1.0.0,-,移除,compile,com.example:legacy-lib",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.example:legacy-lib"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            removed_api = {
                "coord": "com.example:legacy-lib",
                "old_version": "1.0.0",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.example.LegacyApi.call",
                "api_simple": "call",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P0",
                "source": "old_jar",
            }

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                ],
            ), patch.object(
                step4,
                "export_removed_jar_apis",
                return_value=(
                    str(output_dir / "legacy_removed_symbols.txt"),
                    [removed_api],
                    {"old_jar": str(report_dir / "legacy-1.0.0.jar"), "errors": []},
                    None,
                ),
            ) as export_mock:
                exit_code = step4.main()

            self.assertEqual(exit_code, 0)
            export_mock.assert_called_once()
            per_dependency_dir = step4.get_per_dependency_dir(str(report_dir), "com.example:legacy-lib")
            removed_symbols_csv = per_dependency_dir / step4.PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE
            resolved_targets_csv = per_dependency_dir / step4.PER_DEPENDENCY_RESOLVED_TARGETS_FILE
            summary_json = per_dependency_dir / step4.PER_DEPENDENCY_SUMMARY_FILE

            self.assertTrue(removed_symbols_csv.exists())
            self.assertTrue(resolved_targets_csv.exists())
            self.assertTrue(summary_json.exists())
            self.assertIn("com.example.LegacyApi.call", removed_symbols_csv.read_text(encoding="utf-8"))
            self.assertIn("com.example.LegacyApi.call", resolved_targets_csv.read_text(encoding="utf-8"))
            summary = json.loads(summary_json.read_text(encoding="utf-8"))
            self.assertEqual(summary["coord"], "com.example:legacy-lib")
            self.assertEqual(summary["step4"]["removed_jar_symbol_count"], 1)
            self.assertEqual(summary["step4"]["removed_jar"]["old_jar"], str(report_dir / "legacy-1.0.0.jar"))

    def test_step4_emits_progress_logs_for_long_running_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            output_dir = report_dir / "s4_jar_compare"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "com.example:demo,1.0.0,2.0.0,小版本升级,compile",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.example:demo"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            stderr = io.StringIO()

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                ],
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(output_dir / "demo_binary.txt"), [], {"old_jar": "", "new_jar": ""}, None),
            ), patch.object(
                step4,
                "write_all_changed_apis",
                return_value=(str(output_dir / "all_changed_apis.csv"), 0, 0),
            ), patch.object(
                step4,
                "write_readable_outputs",
                return_value=(str(output_dir / "all_changed_apis_alerts.csv"), str(output_dir / "summary.txt")),
            ), patch.object(
                step4,
                "write_git_ref_match_outputs",
                return_value=(str(output_dir / "git_ref_matches.json"), str(output_dir / "git_ref_matches.txt")),
            ), patch.object(
                step4,
                "human_checkpoint_1",
            ), redirect_stderr(stderr):
                exit_code = step4.main()

        output = stderr.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[progress][step4][plan]", output)
        self.assertIn("[progress][step4][dependency]", output)
        self.assertIn("[progress][step4][japicmp]", output)
        self.assertIn("[progress][step4][done]", output)

    def test_step4_timeout_rerun_requires_timeout_override(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_timeouts_need_resolution",
        }
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                pending_interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "step4_git_diff_timeout": 240,
            },
        )

    def test_step4_timeout_rerun_accepts_dependency_source_dirs_fix(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_timeouts_need_resolution",
        }

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_source_dirs": ["/tmp/dependency-repo"],
            },
        )

    def test_normalize_dependency_git_ref_overrides(self):
        payload = [
            {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"},
            {"coord": "com.foo:baz", "old_ref": "release-1", "new_ref": "release-2"},
        ]
        normalized = run_step.normalize_dependency_git_ref_overrides(payload)
        self.assertEqual(normalized, payload)

        normalized_from_json = run_step.normalize_dependency_git_ref_overrides(json.dumps(payload, ensure_ascii=False))
        self.assertEqual(normalized_from_json, payload)

    def test_step4_rerun_requires_git_ref_overrides(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_git_refs_need_confirmation",
        }
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                pending_interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_git_ref_overrides": [
                    {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"}
                ],
            },
        )

    def test_step4_rerun_accepts_dependency_source_dirs_fix(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_git_refs_need_confirmation",
        }

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_source_dirs": ["/tmp/dependency-repo"],
            },
        )


if __name__ == "__main__":
    unittest.main()
