import hashlib
import io
import json
import csv
import os
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
    def test_classifier_artifact_maps_to_ga_source_module_and_unique_stem(self):
        self.assertEqual(
            step4._filter_inferred_coords_by_prefix(
                ["com.example:native"],
                "com.example:native:osx-aarch_64",
            ),
            ["com.example:native"],
        )
        self.assertEqual(
            step4._artifact_output_stem(
                "com.example:native:osx-aarch_64"
            ),
            "native_osx-aarch_64",
        )

    def test_javap_method_body_parser_ignores_constant_pool_slot_numbers(self):
        old_dump = """
public class com.acme.Api {
  public com.acme.Api();
    descriptor: ()V
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: return
}
"""
        new_dump = old_dump.replace("#1", "#99")

        old_methods = step4._parse_javap_method_bodies(old_dump, "com.acme.Api")
        new_methods = step4._parse_javap_method_bodies(new_dump, "com.acme.Api")

        self.assertEqual(set(old_methods), set(new_methods))
        identity = next(iter(old_methods))
        self.assertEqual(old_methods[identity]["body_sha256"], new_methods[identity]["body_sha256"])

    def test_javap_method_body_parser_includes_static_initializer(self):
        dump = """
public class com.acme.Api {
  static {};
    descriptor: ()V
    Code:
       0: iconst_1
       1: putstatic     #7                  // Field enabled:Z
       4: return
}
"""

        methods = step4._parse_javap_method_bodies(dump, "com.acme.Api")

        self.assertIn(("com.acme.Api", "class", "()V"), methods)

    def test_class_variant_hash_includes_multi_release_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            manifest = "Manifest-Version: 1.0\nMulti-Release: true\n\n"
            for jar_path, versioned_body in ((old_jar, b"old"), (new_jar, b"new")):
                with zipfile.ZipFile(jar_path, "w") as archive:
                    archive.writestr("META-INF/MANIFEST.MF", manifest)
                    archive.writestr("com/acme/Api.class", b"same-base")
                    archive.writestr("META-INF/versions/17/com/acme/Api.class", versioned_body)

            old_hashes, old_multi_release = step4._jar_class_variant_hash_map(old_jar)
            new_hashes, new_multi_release = step4._jar_class_variant_hash_map(new_jar)

        self.assertTrue(old_multi_release)
        self.assertTrue(new_multi_release)
        self.assertNotEqual(old_hashes["com.acme.Api"], new_hashes["com.acme.Api"])

    def test_javap_behavior_batch_failure_isolated_by_per_class_retry(self):
        good_dump = """
public class com.acme.Good {
  public int run();
    descriptor: ()I
    Code:
       0: iconst_1
       1: ireturn
}
"""
        with patch.object(
            step4,
            "run_cmd",
            side_effect=[
                ("", "batch failed", 1),
                (good_dump, "", 0),
                ("", "bad class", 1),
            ],
        ):
            dumps, errors, invocations = step4._run_javap_behavior_dumps(
                "dependency.jar",
                ["com.acme.Good", "com.acme.Bad"],
                batch_size=32,
            )

        self.assertEqual(set(dumps), {"com.acme.Good"})
        self.assertEqual(errors, ["com.acme.Bad:bad class"])
        self.assertEqual(invocations, 3)

    def test_compare_jar_method_bodies_finds_same_signature_private_change(self):
        old_dump = """
public class com.acme.Api {
  public int run(int);
    descriptor: (I)I
    Code:
       0: aload_0
       1: iload_1
       2: invokevirtual #7                  // Method helper:(I)I
       5: ireturn
  private int helper(int);
    descriptor: (I)I
    Code:
       0: iload_1
       1: iconst_1
       2: iadd
       3: ireturn
}
"""
        new_dump = old_dump.replace("iconst_1", "iconst_2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            with zipfile.ZipFile(old_jar, "w") as archive:
                archive.writestr("com/acme/Api.class", b"old-class")
            with zipfile.ZipFile(new_jar, "w") as archive:
                archive.writestr("com/acme/Api.class", b"new-class")
            with patch.object(
                step4,
                "_run_javap_behavior_dumps",
                side_effect=[
                    ({"com.acme.Api": old_dump}, [], 1),
                    ({"com.acme.Api": new_dump}, [], 1),
                ],
            ):
                result = step4.compare_jar_method_bodies(
                    old_jar,
                    new_jar,
                    coord="com.acme:api",
                    old_version="1",
                    new_version="2",
                    output_dir=root,
                )

            evidence = json.loads(Path(result["evidence_path"]).read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["api_name"], "com.acme.Api.helper")
        self.assertEqual(result["rows"][0]["api_signature"], "(int)")
        self.assertEqual(result["rows"][0]["source"], "jar_bytecode")
        self.assertEqual(result["rows"][0]["reason_code"], "FINAL_JAR_METHOD_BODY_CHANGED")
        self.assertEqual(evidence["changed_methods"][0]["descriptor"], "(I)I")

    def test_compare_jar_method_bodies_with_real_jdk_toolchain(self):
        if not step4.shutil.which("javac") or not step4.shutil.which("javap"):
            self.skipTest("JDK toolchain is unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jars = []
            for label, increment in (("old", 1), ("new", 2)):
                source_dir = root / label / "src" / "com" / "acme"
                classes_dir = root / label / "classes"
                source_dir.mkdir(parents=True)
                classes_dir.mkdir(parents=True)
                (source_dir / "Api.java").write_text(
                    "package com.acme;\n"
                    "public class Api {\n"
                    "  public int run(int value) { return helper(value); }\n"
                    f"  private int helper(int value) {{ return value + {increment}; }}\n"
                    "}\n",
                    encoding="utf-8",
                )
                stdout, stderr, rc = step4.run_cmd(
                    ["javac", "-g:none", "-d", str(classes_dir), str(source_dir / "Api.java")]
                )
                self.assertEqual(rc, 0, msg=stderr or stdout)
                jar_path = root / f"{label}.jar"
                with zipfile.ZipFile(jar_path, "w") as archive:
                    archive.write(
                        classes_dir / "com" / "acme" / "Api.class",
                        "com/acme/Api.class",
                    )
                jars.append(jar_path)

            result = step4.compare_jar_method_bodies(
                jars[0],
                jars[1],
                coord="com.acme:api",
                old_version="1",
                new_version="2",
                output_dir=root,
            )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [(row["api_name"], row["api_signature"]) for row in result["rows"]],
            [("com.acme.Api.helper", "(int)")],
        )

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

            csv_path, md_path = step4.write_changed_dependencies(
                rows,
                output_dir,
                dependency_status_rows=[{
                    "coord": "com.acme:alpha",
                    "implementation_data_available": True,
                    "implementation_check_status": "changes_detected",
                }],
                business_reference_summary={
                    "scan_status": "complete",
                    "by_coord": {
                        "com.acme:alpha": {
                            "business_exact_referenced_api_count": 1,
                            "business_candidate_referenced_api_count": 0,
                            "business_exact_reference_occurrence_count": 2,
                            "business_candidate_reference_occurrence_count": 0,
                        }
                    },
                },
            )

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
            self.assertIn("精确直接引用的变更 API 数排序", md_text)
            self.assertIn("删除、签名变化等类型不获得额外权重", md_text)
            self.assertIn("依赖源码是否可用只表示分析条件，不参与影响排序", md_text)
            self.assertIn("不表示系统建议缩小范围", md_text)
            self.assertIn("| 排名 | Top 10 | 依赖包 |", md_text)
            self.assertIn("| 1 | 是 | `com.acme:alpha` | 1 | 0 | 2 |", md_text)
            self.assertIn("为什么先看", md_text)
            self.assertIn("业务最终制品直接引用 1 个变更 API", md_text)
            self.assertIn("`com.acme:alpha`", md_text)
            self.assertIn("完整 API 明细", md_text)

    def test_business_bytecode_priority_separates_exact_and_signature_incomplete_matches(self):
        api_rows = [
            {
                "coord": "com.acme:exact",
                "api_name": "com.acme.Api.call",
                "api_simple": "call",
                "api_signature": "(java.lang.String)",
                "symbol_kind": "method",
                "change_type": "BEHAVIOR_CHANGED",
            },
            {
                "coord": "com.acme:candidate",
                "api_name": "com.acme.Api.other",
                "api_simple": "other",
                "api_signature": "",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            },
        ]
        evidence = [
            {
                "caller_owner": "com.app.UseApi",
                "caller_name": "run",
                "caller_signature": "()",
                "callee_key": "com.acme.Api.call(java.lang.String)",
                "evidence_type": "bytecode_method_invocation",
                "instruction_offset": 4,
            },
            {
                "caller_owner": "com.app.UseApi",
                "caller_name": "run",
                "caller_signature": "()",
                "callee_key": "com.acme.Api.other(java.lang.Integer)",
                "evidence_type": "bytecode_method_invocation",
                "instruction_offset": 9,
            },
        ]

        result = step4.summarize_business_bytecode_changed_api_references(
            api_rows, evidence
        )

        self.assertEqual(
            result["by_coord"]["com.acme:exact"][
                "business_exact_referenced_api_count"
            ],
            1,
        )
        self.assertEqual(
            result["by_coord"]["com.acme:candidate"][
                "business_candidate_referenced_api_count"
            ],
            1,
        )
        self.assertEqual(
            [row["match_quality"] for row in result["evidence_rows"]],
            ["signature_incomplete_candidate", "exact"],
        )

    def test_business_bytecode_priority_writes_physical_evidence_and_reuses_step5_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            output_dir = report_dir / "evidence" / "api_changes"
            dependencies_dir = report_dir / "evidence" / "dependencies"
            output_dir.mkdir(parents=True)
            dependencies_dir.mkdir(parents=True)
            business_jar = dependencies_dir / "business-classes.jar"
            business_jar.write_bytes(b"business artifact")
            artifact_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            (dependencies_dir / "dependency_jars.json").write_text(
                json.dumps({
                    "business_artifacts": [{
                        "side": "current",
                        "kind": "business_content",
                        "retained_path": str(business_jar),
                        "sha256": artifact_sha,
                    }],
                }),
                encoding="utf-8",
            )
            edges = [{
                "caller_owner": "com.app.OrderService",
                "caller_name": "submit",
                "caller_signature": "()",
                "callee_key": "com.acme.Api.call(java.lang.String)",
                "evidence_type": "bytecode_method_invocation",
                "instruction_offset": 12,
                "class_file": "business-classes.jar!/com/app/OrderService.class",
            }]
            with patch(
                "business_bytecode_graph.collect_business_bytecode_edges",
                return_value=(edges, {"failures": [], "classes_scanned": 1}),
            ) as collect_edges:
                result = step4.collect_business_bytecode_priority_evidence(
                    [{
                        "coord": "com.acme:api",
                        "api_name": "com.acme.Api.call",
                        "api_simple": "call",
                        "api_signature": "(java.lang.String)",
                        "symbol_kind": "method",
                        "change_type": "BEHAVIOR_CHANGED",
                    }],
                    output_dir,
                )

            call_kwargs = collect_edges.call_args.kwargs
            expected_cache = (
                report_dir.resolve()
                / ".runtime"
                / "cache"
                / step4.STEP5_ARTIFACT_BYTECODE_INDEX_FILE
            )
            self.assertEqual(call_kwargs["cache_path"], expected_cache)
            with Path(result["evidence_file"]).open(
                encoding="utf-8-sig", newline=""
            ) as handle:
                evidence_rows = list(csv.DictReader(handle))
            summary_bytes = Path(result["summary_file"]).read_bytes()
            summary = json.loads(summary_bytes.decode("utf-8"))

        self.assertEqual(result["scan_status"], "complete")
        self.assertEqual(len(evidence_rows), 1)
        self.assertEqual(evidence_rows[0]["caller_class"], "com.app.OrderService")
        self.assertEqual(evidence_rows[0]["caller_method"], "submit")
        self.assertEqual(evidence_rows[0]["instruction_offset"], "12")
        self.assertEqual(
            evidence_rows[0]["callee_key"],
            "com.acme.Api.call(java.lang.String)",
        )
        self.assertFalse(summary_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(summary["exact_referenced_api_count"], 1)

    def test_changed_dependency_order_does_not_weight_change_kind_or_source_availability(self):
        rows = [
            {
                "coord": "com.acme:direct",
                "change_type": "BEHAVIOR_CHANGED",
                "severity": "P2",
                "api_name": "com.acme.Direct.call",
                "symbol_kind": "method",
            },
            *[
                {
                    "coord": "com.acme:removed",
                    "change_type": "REMOVED",
                    "severity": "P0",
                    "api_name": f"com.acme.Removed.call{index}",
                    "symbol_kind": "method",
                }
                for index in range(3)
            ],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            csv_path, _md_path = step4.write_changed_dependencies(
                rows,
                tmp,
                dependency_status_rows=[
                    {
                        "coord": "com.acme:direct",
                        "implementation_data_available": False,
                        "implementation_check_status": "not_configured",
                    },
                    {
                        "coord": "com.acme:removed",
                        "implementation_data_available": True,
                        "implementation_check_status": "changes_detected",
                    },
                ],
                business_reference_summary={
                    "scan_status": "complete",
                    "by_coord": {
                        "com.acme:direct": {
                            "business_exact_referenced_api_count": 1,
                            "business_exact_reference_occurrence_count": 1,
                        }
                    },
                },
            )
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                written = list(csv.DictReader(handle))

        self.assertEqual(
            [row["coord"] for row in written],
            ["com.acme:direct", "com.acme:removed"],
        )
        self.assertEqual(written[0]["dependency_source_status"], "unavailable")
        self.assertEqual(written[1]["dependency_source_status"], "available")

    def test_dependency_analysis_status_distinguishes_zero_change_from_failure(self):
        dep_rows = [
            {
                "coord": "com.acme:no-change",
                "old_version": "1.0",
                "new_version": "2.0",
                "change_type": "小版本升级",
            },
            {
                "coord": "com.acme:failed",
                "old_version": "1.0",
                "new_version": "2.0",
                "change_type": "小版本升级",
            },
        ]
        binary_runs = [
            {
                "coord": "com.acme:failed",
                "mode": "japicmp",
                "status": "failed",
                "reason_code": "JAPICMP_EXECUTION_FAILED",
                "error": "Unsupported class file major version",
                "evidence_path": "/tmp/failed_binary.txt",
            },
            {
                "coord": "com.acme:no-change",
                "mode": "japicmp",
                "status": "success",
                "api_count": 0,
                "evidence_path": "/tmp/no_change_binary.txt",
            },
        ]

        rows = step4.build_dependency_analysis_status_rows(dep_rows, binary_runs)
        by_coord = {row["coord"]: row for row in rows}

        self.assertEqual(
            by_coord["com.acme:no-change"]["comparison_status"],
            "no_api_change",
        )
        self.assertTrue(
            by_coord["com.acme:no-change"]["api_data_available"]
        )
        self.assertEqual(
            by_coord["com.acme:failed"]["comparison_status"],
            "failed",
        )
        self.assertFalse(by_coord["com.acme:failed"]["api_data_available"])
        self.assertIsNone(
            by_coord["com.acme:failed"]["changed_api_count"]
        )
        self.assertIn(
            "不能按无变化处理",
            by_coord["com.acme:failed"]["result_interpretation"],
        )

    def test_write_dependency_analysis_status_includes_failure_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, csv_path, json_path = step4.write_dependency_analysis_status(
                [
                    {
                        "coord": "com.acme:failed",
                        "old_version": "1.0",
                        "new_version": "2.0",
                        "change_type": "小版本升级",
                    }
                ],
                [
                    {
                        "coord": "com.acme:failed",
                        "mode": "japicmp",
                        "status": "failed",
                        "reason_code": "JAPICMP_EXECUTION_FAILED",
                        "error": "process exited with 1",
                        "evidence_path": "/tmp/failed_binary.txt",
                    }
                ],
                tmp,
            )
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            md_text = (
                Path(tmp) / step4.DEPENDENCY_ANALYSIS_STATUS_MD
            ).read_text(encoding="utf-8")
            with csv_path.open(encoding="utf-8-sig") as fh:
                csv_rows = list(csv.DictReader(fh))

        self.assertEqual(rows[0]["comparison_status"], "failed")
        self.assertEqual(csv_rows[0]["api_comparison_status"], "failed")
        self.assertEqual(csv_rows[0]["api_change_count"], "")
        self.assertEqual(
            payload["summary"]["dependencies_with_failed_api_comparison"],
            1,
        )
        self.assertEqual(
            payload["items"][0]["api_comparison_failure_reason"],
            "process exited with 1",
        )
        self.assertNotIn("comparison_status", payload["items"][0])
        self.assertNotIn("needs_fix", payload["items"][0])
        self.assertEqual(
            payload["diagnostic_guidance"][0]["reason_code"],
            "JAPICMP_EXECUTION_FAILED",
        )
        self.assertIn(
            "不能解释为该依赖确实没有 API 变化",
            payload["diagnostic_guidance"][0]["semantic_impact"],
        )
        self.assertIn("每个依赖的分析结果（先看这里）", md_text)
        self.assertIn("可按无变化处理", md_text)
        self.assertIn("分析不完整：API 对比失败", md_text)
        self.assertIn("修复后重跑", md_text)

    def test_dependency_status_uses_direct_source_diff_conclusions(self):
        dep_rows = [
            {
                "coord": coord,
                "old_version": "1.0",
                "new_version": "2.0",
                "change_type": "小版本升级",
            }
            for coord in (
                "com.acme:source-ok",
                "com.acme:jar-recovered",
                "com.acme:source-pending",
            )
        ]
        binary_runs = [
            {
                "coord": row["coord"],
                "mode": "japicmp",
                "status": "success",
                "api_count": 0,
            }
            for row in dep_rows
        ]

        rows = step4.build_dependency_analysis_status_rows(
            dep_rows,
            binary_runs,
            gitdiff_runs=[
                {
                    "coord": "com.acme:source-ok",
                    "api_changes": 0,
                    "promoted_to_step5": 0,
                    "out_file": "/tmp/source-ok.txt",
                }
            ],
            gitdiff_skipped=[
                {
                    "coord": "com.acme:jar-recovered",
                    "reason_code": "DEPENDENCY_SOURCE_DIFF_UNAVAILABLE",
                    "reason": "git diff failed",
                    "behavior_fallback_status": "complete",
                }
            ],
            gitdiff_pending=[
                {
                    "coord": "com.acme:source-pending",
                    "reason": "存在多个候选 ref",
                }
            ],
            bytecode_behavior_runs=[
                {
                    "coord": "com.acme:jar-recovered",
                    "status": "complete",
                    "api_changes": 0,
                    "evidence_path": "/tmp/behavior.json",
                }
            ],
        )
        by_coord = {row["coord"]: row for row in rows}

        self.assertEqual(
            by_coord["com.acme:source-ok"]["implementation_check_result_text"],
            "源码对比成功，未发现实现差异。",
        )
        self.assertTrue(
            by_coord["com.acme:source-ok"]["can_treat_as_no_change"]
        )
        self.assertIn(
            "已通过发布 JAR 的方法实现检查补齐",
            by_coord["com.acme:jar-recovered"][
                "implementation_check_result_text"
            ],
        )
        self.assertTrue(
            by_coord["com.acme:jar-recovered"]["analysis_complete"]
        )
        self.assertEqual(
            by_coord["com.acme:source-pending"][
                "implementation_check_result_text"
            ],
            "等待确认新旧源码版本，尚未执行实现变化检查。",
        )
        self.assertTrue(
            by_coord["com.acme:source-pending"][
                "requires_action_before_conclusion"
            ]
        )
        self.assertIn(
            "确认 old/new 源码版本",
            by_coord["com.acme:source-pending"]["next_action"],
        )

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
            with Path(alerts_path).open(encoding="utf-8-sig") as f:
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
        self.assertIn("确认 Step5 分析范围：", output)
        self.assertIn("全量分析：", output)
        self.assertIn("部分分析：", output)
        self.assertIn("changed_dependencies.md", output)
        self.assertIn("复核文件：", output)
        self.assertNotIn("人工抽查节点", output)
        self.assertNotIn("建议优先查看", output)

    def test_main_blocks_as_system_error_when_japicmp_auto_install_fails(self):
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

            self.assertEqual(rc, 2)
            install_mock.assert_called_once()
            output = stdout.getvalue()
            self.assertNotIn(step4.INTERACTION_PREFIX, output)
            self.assertIn("系统环境阻塞", stderr.getvalue())
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

    def test_parse_japicmp_xml_rejects_non_japicmp_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "error.xml"
            xml_path.write_text(
                "<error><message>tool failed</message></error>",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "JApiCmp XML structure"):
                step4.parse_japicmp_xml(
                    xml_path, "com.acme:api", "1", "2"
                )

    def test_parse_japicmp_xml_rejects_changed_class_without_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "broken.xml"
            xml_path.write_text(
                '<japicmp><classes><class changeStatus="REMOVED"/></classes></japicmp>',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "class identity missing"):
                step4.parse_japicmp_xml(
                    xml_path, "com.acme:api", "1", "2"
                )

    def test_parse_japicmp_xml_rejects_nested_changed_class_without_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "nested-broken.xml"
            xml_path.write_text(
                "<japicmp><classes><wrapper>"
                '<class changeStatus="REMOVED"/>'
                "</wrapper></classes></japicmp>",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "class identity missing"):
                step4.parse_japicmp_xml(
                    xml_path, "com.acme:api", "1", "2"
                )

    def test_parse_japicmp_xml_keeps_nested_class_members_with_nested_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "nested.xml"
            xml_path.write_text(
                "<japicmp><classes>"
                '<class name="com.acme.Outer" changeStatus="UNCHANGED">'
                '<class name="com.acme.Inner" changeStatus="MODIFIED">'
                '<method name="innerGone" changeStatus="REMOVED"/>'
                "</class></class></classes></japicmp>",
                encoding="utf-8",
            )

            rows = step4.parse_japicmp_xml(
                xml_path, "com.acme:api", "1", "2"
            )

        names = {row["api_name"] for row in rows}
        self.assertIn("com.acme.Inner.innerGone", names)
        self.assertNotIn("com.acme.Outer.innerGone", names)

    def test_java_runtime_identity_is_incomplete_when_explicit_java_home_has_no_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            java = root / "bin" / "java"
            java.parent.mkdir()
            java.write_bytes(b"java-launcher")
            missing_home = root / "missing-jdk"

            with patch.object(
                step4.shutil, "which", return_value=str(java)
            ), patch.dict(
                os.environ, {"JAVA_HOME": str(missing_home)}, clear=False
            ):
                identity = step4.effective_java_runtime_identity()

        self.assertFalse(identity["complete"])
        self.assertEqual(identity["release_sha256"], "")
        self.assertIn("java_release_file_missing", identity["failures"])

    def test_java_runtime_identity_resolves_literal_shell_launcher_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            launcher = root / "launcher" / "java"
            runtime_java = root / "jdk" / "bin" / "java"
            release = root / "jdk" / "release"
            launcher.parent.mkdir()
            runtime_java.parent.mkdir(parents=True)
            runtime_java.write_bytes(b"runtime-java")
            release.write_text('JAVA_VERSION="21"\n', encoding="utf-8")
            launcher.write_text(
                f'#!/bin/sh\nexec {runtime_java} "$@"\n', encoding="utf-8"
            )

            with patch.object(
                step4.shutil, "which", return_value=str(launcher)
            ), patch.dict(os.environ, {}, clear=True):
                identity = step4.effective_java_runtime_identity()

        self.assertTrue(identity["complete"])
        self.assertEqual(identity["runtime_java"], str(runtime_java.resolve()))
        self.assertEqual(identity["java_home"], str(runtime_java.parent.parent.resolve()))
        self.assertTrue(identity["runtime_java_sha256"])
        self.assertTrue(identity["release_sha256"])
        self.assertEqual(identity["failures"], [])

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

    def test_step4_git_default_timeouts_are_bounded(self):
        self.assertGreater(step4.DEFAULT_GIT_DIFF_TIMEOUT, 0)
        self.assertGreater(step4.DEFAULT_FETCH_TIMEOUT, 0)
        self.assertIsNone(step4.DEFAULT_JAPICMP_TIMEOUT)
        self.assertEqual(
            step4._bounded_git_timeout(900, step4.DEFAULT_FETCH_TIMEOUT),
            900,
        )

    def test_run_gitdiff_uses_bounded_defaults_and_disables_diff_hooks(self):
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
                "base_ref": "a" * 40,
                "cur_ref": "b" * 40,
                "old_match_reason": "preflight_remote_commit",
                "new_match_reason": "preflight_remote_commit",
            }
            captured = []

            def fake_run_cmd(cmd, cwd=None, timeout=None, **_kwargs):
                captured.append({"cmd": list(cmd), "cwd": cwd, "timeout": timeout})
                if "--is-inside-work-tree" in cmd:
                    return "true\n", "", 0
                return "", "", 0

            with patch.object(step4, "run_cmd", side_effect=fake_run_cmd):
                result = step4.run_gitdiff(lib_info, tmp)

        self.assertEqual(result["status"], "success")
        diff_call = next(item for item in captured if "diff" in item["cmd"])
        self.assertEqual(diff_call["timeout"], step4.DEFAULT_GIT_DIFF_TIMEOUT)
        self.assertIn("--no-ext-diff", diff_call["cmd"])
        self.assertIn("--no-textconv", diff_call["cmd"])
        self.assertIn("--no-color", diff_call["cmd"])

    def test_run_gitdiff_requires_zero_exit_code_and_preserves_explicit_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            repo_dir.mkdir(parents=True)
            lib_info = {
                "coord": "com.example:demo",
                "repo_path": str(repo_dir),
                "module_path": str(repo_dir),
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "base_ref": "a" * 40,
                "cur_ref": "b" * 40,
            }
            calls = []

            def failed_diff(cmd, cwd=None, timeout=None, **_kwargs):
                calls.append({"cmd": list(cmd), "timeout": timeout})
                return "partial output", "diff failed", 1

            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
                step4, "run_cmd", side_effect=failed_diff
            ):
                result = step4.run_gitdiff(lib_info, tmp, git_diff_timeout=900)

        self.assertEqual(result["status"], "error")
        self.assertEqual(len(calls), 2)
        self.assertEqual({item["timeout"] for item in calls}, {900})
        for item in calls:
            self.assertIn("--no-ext-diff", item["cmd"])
            self.assertIn("--no-textconv", item["cmd"])
            self.assertIn("--no-color", item["cmd"])

    def test_run_gitdiff_accepts_linked_worktree_with_gitfile(self):
        def git(repo, *args):
            stdout, stderr, rc = compat.run_cmd(
                compat.git_cmd() + list(args),
                cwd=str(repo),
                timeout=20,
            )
            self.assertEqual(rc, 0, stderr or stdout)
            return str(stdout or "").strip()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_dir = root / "repo"
            linked_dir = root / "linked"
            output_dir = root / "out"
            repo_dir.mkdir()
            output_dir.mkdir()
            git(repo_dir, "init")
            git(repo_dir, "config", "user.email", "tests@example.invalid")
            git(repo_dir, "config", "user.name", "Step4 Tests")
            (repo_dir / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
            git(repo_dir, "add", "Demo.java")
            git(repo_dir, "commit", "-m", "initial")
            commit = git(repo_dir, "rev-parse", "HEAD")
            git(repo_dir, "worktree", "add", "-b", "linked-test", str(linked_dir))

            self.assertTrue((linked_dir / ".git").is_file())
            result = step4.run_gitdiff(
                {
                    "coord": "com.example:demo",
                    "repo_path": str(linked_dir),
                    "module_path": str(linked_dir),
                    "old_version": "1.0.0",
                    "new_version": "1.0.0",
                    "base_ref": commit,
                    "cur_ref": commit,
                },
                str(output_dir),
            )

        self.assertEqual(result["status"], "success")

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

    def test_japicmp_tool_digest_detects_same_stat_byte_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "japicmp.jar"
            tool.write_bytes(b"first")
            step4.clear_japicmp_tool_digest_cache()
            original_stat = tool.stat()

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
                tool.write_bytes(b"other")
                os.utime(
                    tool,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
                mutated_stat = tool.stat()
                changed = step4.japicmp_tool_sha256(tool)

        self.assertEqual(original_stat.st_ino, mutated_stat.st_ino)
        self.assertEqual(original_stat.st_size, mutated_stat.st_size)
        self.assertEqual(original_stat.st_mtime_ns, mutated_stat.st_mtime_ns)
        self.assertNotEqual(first, changed)
        self.assertEqual(read_bytes.call_count, 2)

    def test_japicmp_tool_digest_rehashes_unchanged_tool_for_each_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "japicmp.jar"
            tool.write_bytes(b"stable-tool")
            step4.clear_japicmp_tool_digest_cache()

            original_read_bytes = Path.read_bytes
            with patch.object(
                step4.Path,
                "read_bytes",
                autospec=True,
                side_effect=lambda path: original_read_bytes(path),
            ) as read_bytes:
                first = step4.japicmp_tool_sha256(tool)
                second = step4.japicmp_tool_sha256(tool)

        self.assertEqual(first, second)
        self.assertEqual(read_bytes.call_count, 2)

    def test_japicmp_tool_digest_ignores_timestamp_change_during_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "japicmp.jar"
            payload = b"stable-tool"
            tool.write_bytes(payload)
            original_stat = tool.stat()
            original_read_bytes = Path.read_bytes

            def read_and_touch(path):
                content = original_read_bytes(path)
                os.utime(
                    path,
                    ns=(
                        original_stat.st_atime_ns,
                        original_stat.st_mtime_ns + 1_000_000_000,
                    ),
                )
                return content

            with patch.object(
                step4.Path,
                "read_bytes",
                autospec=True,
                side_effect=read_and_touch,
            ) as read_bytes:
                digest = step4.japicmp_tool_sha256(tool)

        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(read_bytes.call_count, 1)

    def test_japicmp_comparison_identity_includes_target_jdk_and_java_runtime(self):
        base = {
            "coord": "com.acme:api",
            "old_coord": "com.acme:api",
            "new_coord": "com.acme:api",
            "old_version": "1",
            "new_version": "2",
            "old_jar_sha256": "old",
            "new_jar_sha256": "new",
            "tool_sha256": "tool",
        }

        jdk_17 = step4._japicmp_comparison_cache_identity(
            **base, target_jdk="17", java_runtime_identity={"java": "/jdk/a/bin/java"}
        )
        jdk_21 = step4._japicmp_comparison_cache_identity(
            **base, target_jdk="21", java_runtime_identity={"java": "/jdk/a/bin/java"}
        )
        other_runtime = step4._japicmp_comparison_cache_identity(
            **base, target_jdk="17", java_runtime_identity={"java": "/jdk/b/bin/java"}
        )

        self.assertNotEqual(jdk_17, jdk_21)
        self.assertNotEqual(jdk_17, other_runtime)
        self.assertEqual(jdk_17["target_jdk"], "17")
        self.assertEqual(jdk_17["java_runtime_identity"]["java"], "/jdk/a/bin/java")

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

    def test_run_japicmp_invalidates_cache_when_effective_java_runtime_changes(self):
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
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                return "japicmp-output", "", 0

            with patch.object(
                step4,
                "effective_java_runtime_identity",
                side_effect=[
                    {"java": "/jdk/a/bin/java", "java_sha256": "a", "complete": True},
                    {"java": "/jdk/a/bin/java", "java_sha256": "a", "complete": True},
                    {"java": "/jdk/b/bin/java", "java_sha256": "b", "complete": True},
                    {"java": "/jdk/b/bin/java", "java_sha256": "b", "complete": True},
                ],
                create=True,
            ), patch.object(step4, "run_cmd", side_effect=successful_japicmp) as run_cmd:
                first = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir, jdk_current="17",
                )
                second = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir, jdk_current="17",
                )

        self.assertFalse(first[2]["comparison_cache_hit"])
        self.assertFalse(second[2]["comparison_cache_hit"])
        self.assertEqual(run_cmd.call_count, 2)

    def test_run_japicmp_recomputes_when_cached_xml_disagrees_with_rows(self):
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
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    '<japicmp><classes><class name="com.acme.Api" '
                    'changeStatus="MODIFIED"><methods><method name="gone" '
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
                cache_path = next(cache_dir.glob("*.json"))
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
                payload["rows"] = []
                payload["rows_sha256"] = hashlib.sha256(
                    step4._canonical_json_bytes(payload["rows"])
                ).hexdigest()
                cache_path.write_text(json.dumps(payload), encoding="utf-8")
                second = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertEqual(first[1], second[1])
        self.assertFalse(second[2]["comparison_cache_hit"])
        self.assertEqual(run_cmd.call_count, 2)

    def test_run_japicmp_removes_stale_xml_before_successful_process_without_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "japicmp.jar"
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            cache_dir = root / "cache"
            tool.write_bytes(b"tool")
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")
            stale_xml = root / "api_1_vs_2_binary.xml"
            stale_xml.write_text(
                '<japicmp><classes><class name="com.acme.Stale" '
                'changeStatus="REMOVED" binaryCompatible="false" '
                'sourceCompatible="false"/></classes></japicmp>',
                encoding="utf-8",
            )

            with patch.object(step4, "run_cmd", return_value=("", "", 0)):
                result = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertEqual(result[1], [])
        self.assertEqual(result[2]["parser_mode"], "text_fallback")
        self.assertEqual(result[2]["external_process_count"], 1)
        self.assertEqual(result[2]["reason_code"], "JAPICMP_FRESH_XML_MISSING")
        self.assertIsNotNone(result[3])
        self.assertFalse(stale_xml.exists())
        self.assertEqual(list(cache_dir.glob("*.json")), [])

    def test_run_japicmp_disables_cache_when_java_runtime_identity_is_incomplete(self):
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
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                return "japicmp-output", "", 0

            incomplete_runtime = {
                "java": "/jdk/bin/java",
                "java_sha256": "",
                "complete": False,
                "failures": ["java_sha256_unavailable"],
            }
            with patch.object(
                step4, "effective_java_runtime_identity",
                return_value=incomplete_runtime,
            ), patch.object(step4, "run_cmd", side_effect=successful_japicmp) as run_cmd:
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

        self.assertFalse(first[2]["comparison_cache_hit"])
        self.assertFalse(second[2]["comparison_cache_hit"])
        self.assertEqual(run_cmd.call_count, 2)
        self.assertEqual(list(cache_dir.glob("*.json")), [])

    def test_run_japicmp_rejects_result_when_input_jar_changes_during_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "japicmp.jar"
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            cache_dir = root / "cache"
            tool.write_bytes(b"tool")
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")

            def mutating_japicmp(cmd, **_kwargs):
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                old_jar.write_bytes(b"changed-during-comparison")
                return "japicmp-output", "", 0

            with patch.object(step4, "run_cmd", side_effect=mutating_japicmp):
                result = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertEqual(result[1], [])
        self.assertEqual(result[2]["reason_code"], "JAPICMP_INPUT_CHANGED_DURING_COMPARISON")
        self.assertIsNotNone(result[3])
        self.assertEqual(list(cache_dir.glob("*.json")), [])

    def test_run_japicmp_rejects_cache_hit_when_input_changes_during_load(self):
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
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                return "japicmp-output", "", 0

            with patch.object(step4, "run_cmd", side_effect=successful_japicmp):
                first = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )
            original_load = step4._load_japicmp_comparison_cache

            def mutating_load(path, identity):
                cached = original_load(path, identity)
                old_jar.write_bytes(b"changed-during-cache-load")
                return cached

            with patch.object(
                step4, "_load_japicmp_comparison_cache",
                side_effect=mutating_load,
            ), patch.object(step4, "run_cmd") as run_cmd:
                second = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertIsNone(first[3])
        self.assertEqual(second[1], [])
        self.assertEqual(second[2]["reason_code"], "JAPICMP_INPUT_CHANGED_DURING_CACHE_LOAD")
        self.assertIsNotNone(second[3])
        run_cmd.assert_not_called()

    def test_run_japicmp_external_process_count_tracks_actual_java_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "japicmp.jar"
            old_jar = root / "old.jar"
            new_jar = root / "new.jar"
            cache_dir = root / "cache"
            tool.write_bytes(b"tool")
            old_jar.write_bytes(b"old")
            new_jar.write_bytes(b"new")

            missing = step4.run_japicmp(
                "com.acme:api", "1", "2", root, str(tool),
                old_jar_path="", new_jar_path=str(new_jar),
                cache_dir=cache_dir,
            )

            def successful_japicmp(cmd, **_kwargs):
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                return "", "", 0

            with patch.object(step4, "run_cmd", side_effect=successful_japicmp):
                invoked = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )
                cached = step4.run_japicmp(
                    "com.acme:api", "1", "2", root, str(tool),
                    old_jar_path=str(old_jar), new_jar_path=str(new_jar),
                    old_jar_evidence={"source": "step1_final_artifact"},
                    new_jar_evidence={"source": "step1_final_artifact"},
                    cache_dir=cache_dir,
                )

        self.assertEqual(missing[2]["external_process_count"], 0)
        self.assertEqual(invoked[2]["external_process_count"], 1)
        self.assertEqual(cached[2]["external_process_count"], 0)

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
        self.assertEqual(
            jar_info["reason_code"],
            "JAPICMP_EXECUTION_FAILED",
        )
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

            def successful_japicmp(cmd, **_kwargs):
                Path(cmd[cmd.index("--xml-file") + 1]).write_text(
                    "<japicmp><classes/></japicmp>", encoding="utf-8"
                )
                return "", "", 0

            with patch.object(step4, "run_cmd", side_effect=successful_japicmp):
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

    def test_resolve_repo_ref_for_version_accepts_equal_commit_on_multiple_remotes(self):
        shared_commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "heads": [],
                "tags": [],
                "remotes": ["origin/release-1.0.0", "upstream/support-1.0.0"],
                "remote_records": [
                    {"ref": "origin/release-1.0.0", "commit": shared_commit, "canonical_ref": "refs/heads/release-1.0.0", "remote": "origin"},
                    {"ref": "upstream/support-1.0.0", "commit": shared_commit, "canonical_ref": "refs/heads/support-1.0.0", "remote": "upstream"},
                ],
            },
        ):
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "1.0.0")

        self.assertEqual(resolved, "origin/release-1.0.0")
        self.assertIn("matched_by_version", reason)
        self.assertEqual({item["commit"] for item in candidates}, {shared_commit})

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

    def test_resolve_repo_ref_for_version_accepts_explicit_live_remote_outside_version_heuristic(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            step4,
            "resolve_remote_source_ref",
            return_value={
                "status": "remote_source_resolved",
                "resolved_ref": "origin/production-stable",
                "resolved_commit": commit,
                "remote": "origin",
                "remote_ref": "refs/heads/production-stable",
                "candidates": [],
            },
        ):
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                tmp,
                "3.0.7",
                selected_ref="origin/production-stable",
            )

        self.assertEqual(resolved, "origin/production-stable")
        self.assertEqual(reason, "selected_by_user(kind=remote,score=-1,version=3.0.7)")
        self.assertEqual(candidates[0]["commit"], commit)

    def test_resolve_repo_ref_for_version_accepts_explicit_sha256_commit(self):
        commit = "a" * 64
        with patch.object(
            step4,
            "resolve_remote_source_ref",
            return_value={
                "status": "remote_source_resolved",
                "resolved_ref": commit,
                "resolved_commit": commit,
                "remote": "origin",
                "remote_ref": "",
                "candidates": [],
            },
        ):
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                "/repo",
                "3.0.7",
                selected_ref=commit,
            )

        self.assertEqual(resolved, commit)
        self.assertIn("kind=remote_commit", reason)
        self.assertEqual(candidates[0]["commit"], commit)

    def test_resolve_repo_ref_for_version_does_not_demote_non_dev_substring(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "tags": [],
                "heads": [],
                "remotes": ["origin/device-3.0.7"],
            },
        ):
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7")

        self.assertEqual(resolved, "origin/device-3.0.7")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.7)")
        self.assertEqual(candidates[0]["score"], 140)

    def test_git_ref_pair_options_deduplicate_remote_aliases_by_commit_pair(self):
        old_commit = "a" * 40
        new_commit = "b" * 40
        item = {
            "coord": "com.acme:demo",
            "repo_path": "/repo/demo",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "old_candidates": [
                {
                    "ref": "origin/release-1.0.0", "commit": old_commit,
                    "score": 140, "prefix": "release", "remote_name": "origin",
                    "branch_name": "release-1.0.0",
                },
                {
                    "ref": "upstream/release-1.0.0", "commit": old_commit,
                    "score": 140, "prefix": "release", "remote_name": "upstream",
                    "branch_name": "release-1.0.0",
                },
            ],
            "new_candidates": [
                {
                    "ref": "origin/release-2.0.0", "commit": new_commit,
                    "score": 140, "prefix": "release", "remote_name": "origin",
                    "branch_name": "release-2.0.0",
                },
                {
                    "ref": "upstream/release-2.0.0", "commit": new_commit,
                    "score": 140, "prefix": "release", "remote_name": "upstream",
                    "branch_name": "release-2.0.0",
                },
            ],
        }

        first = step4.build_git_ref_pair_options(item)
        second = step4.build_git_ref_pair_options(item)

        self.assertEqual(len(first), 1)
        self.assertEqual(first, second)
        self.assertEqual(first[0]["old_commit"], old_commit)
        self.assertEqual(first[0]["new_commit"], new_commit)
        self.assertEqual(
            first[0]["old_aliases"],
            ["origin/release-1.0.0", "upstream/release-1.0.0"],
        )

    def test_remote_materialization_cache_is_keyed_by_repo_and_commit(self):
        first_candidate = {
            "ref": "origin/release-1.0.0",
            "commit": "a" * 40,
            "canonical_ref": "refs/heads/release-1.0.0",
            "remote": "origin",
        }
        second_candidate = {
            "ref": "upstream/v1.0.0",
            "commit": "a" * 40,
            "canonical_ref": "refs/tags/v1.0.0",
            "remote": "upstream",
        }
        step4._REMOTE_SOURCE_MATERIALIZATION_CACHE.clear()
        with patch.object(
            step4,
            "materialize_remote_source_candidate",
            return_value={
                "status": "remote_source_resolved",
                "resolved_commit": "a" * 40,
                "attempts": [{
                    "attempt": 0,
                    "stage": "verify_local_commit",
                    "status": "success",
                }],
            },
        ) as materializer:
            first, first_error = step4._materialize_resolved_remote_ref(
                "/repo/demo", first_candidate["ref"], [first_candidate]
            )
            second, second_error = step4._materialize_resolved_remote_ref(
                "/repo/demo", second_candidate["ref"], [second_candidate]
            )

        self.assertEqual(first_error, "")
        self.assertEqual(second_error, "")
        self.assertEqual(first["resolved_commit"], second["resolved_commit"])
        self.assertEqual(second["resolved_ref"], second_candidate["ref"])
        self.assertEqual(second["remote_ref"], second_candidate["canonical_ref"])
        materializer.assert_called_once()

    def test_remote_snapshot_delegates_to_shared_materializer_with_total_timeout(self):
        commit = "a" * 40
        candidate = {
            "ref": "origin/release-1.0.0",
            "commit": commit,
            "canonical_ref": "refs/heads/release-1.0.0",
            "remote": "origin",
        }
        step4._REMOTE_SOURCE_MATERIALIZATION_CACHE.clear()
        with patch.object(
            step4,
            "materialize_remote_source_candidate",
            return_value={
                "status": "remote_source_resolved",
                "resolved_commit": commit,
                "attempts": [{
                    "attempt": 1,
                    "stage": "fetch_canonical_ref",
                    "status": "success",
                }],
            },
        ) as materializer:
            result, error = step4._materialize_resolved_remote_ref(
                "/repo/demo",
                candidate["ref"],
                [candidate],
                fetch_timeout=900,
            )

        self.assertEqual(error, "")
        self.assertEqual(result["resolved_commit"], commit)
        self.assertEqual(result["resolution_mode"], "live_remote")
        self.assertEqual(result["materialization_mode"], "live_remote_snapshot_fetch")
        materializer.assert_called_once_with(
            "/repo/demo",
            candidate,
            timeout=900,
            expected_commit=commit,
        )

    def test_remote_snapshot_materializes_pinned_commit_after_branch_moves(self):
        observed = "b" * 40
        expected = "a" * 40
        candidate = {
            "ref": "origin/release-1.0.0",
            "commit": observed,
            "canonical_ref": "refs/heads/release-1.0.0",
            "remote": "origin",
        }
        step4._REMOTE_SOURCE_MATERIALIZATION_CACHE.clear()
        with patch.object(
            step4,
            "materialize_remote_source_candidate",
            return_value={
                "status": "remote_source_resolved",
                "resolved_commit": expected,
                "attempts": [{
                    "attempt": 1,
                    "stage": "fetch_commit",
                    "status": "success",
                }],
            },
        ) as materializer:
            result, error = step4._materialize_resolved_remote_ref(
                "/repo/demo",
                candidate["ref"],
                [candidate],
                expected_commit=expected,
            )

        self.assertEqual(error, "")
        self.assertEqual(result["resolved_commit"], expected)
        self.assertEqual(result["observed_commit"], observed)
        passed_candidate = materializer.call_args.args[1]
        self.assertEqual(passed_candidate["commit"], expected)

    def test_remote_snapshot_commit_materializes_from_local_git_remote(self):
        def git(repo, *args):
            stdout, stderr, rc = compat.run_cmd(
                compat.git_cmd() + list(args),
                cwd=str(repo),
                timeout=20,
            )
            self.assertEqual(rc, 0, stderr or stdout)
            return str(stdout or "").strip()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            origin = root / "origin"
            consumer = root / "consumer"
            origin.mkdir()
            consumer.mkdir()
            git(origin, "init")
            git(origin, "config", "user.email", "tests@example.invalid")
            git(origin, "config", "user.name", "Step4 Tests")
            (origin / "Demo.java").write_text("public class Demo {}\n", encoding="utf-8")
            git(origin, "add", "Demo.java")
            git(origin, "commit", "-m", "initial")
            commit = git(origin, "rev-parse", "HEAD")
            branch = git(origin, "symbolic-ref", "--short", "HEAD")

            git(consumer, "init")
            git(consumer, "remote", "add", "origin", str(origin))
            candidate = {
                "ref": f"origin/{branch}",
                "commit": commit,
                "canonical_ref": f"refs/heads/{branch}",
                "remote": "origin",
            }
            step4._REMOTE_SOURCE_MATERIALIZATION_CACHE.clear()
            result, error = step4._materialize_resolved_remote_ref(
                str(consumer),
                candidate["ref"],
                [candidate],
            )

        self.assertEqual(error, "")
        self.assertEqual(result["resolved_commit"], commit)
        self.assertEqual(result["resolution_mode"], "live_remote")
        self.assertEqual(
            result["materialization_mode"],
            "live_remote_snapshot_fetch",
        )

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

            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
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

    def test_partition_git_ref_pending_only_prompts_for_distinct_commit_ranges(self):
        internal_item = {
            "coord": "com.acme:network-failure",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "pending_kind": "remote_query_failed",
            "reason": "remote_query_failed=timed out",
        }
        ambiguous_item = {
            "coord": "com.acme:ambiguous",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "pending_kind": "ambiguous",
            "old_candidates": [
                {"ref": "origin/release-1", "commit": "a" * 40, "score": 140},
                {"ref": "origin/support-1", "commit": "b" * 40, "score": 140},
            ],
            "new_candidates": [
                {"ref": "origin/release-2", "commit": "c" * 40, "score": 140},
                {"ref": "origin/support-2", "commit": "d" * 40, "score": 140},
            ],
        }

        user_confirmation, internally_skipped = step4.partition_git_ref_pending_items(
            [internal_item, ambiguous_item]
        )

        self.assertEqual([item["coord"] for item in user_confirmation], ["com.acme:ambiguous"])
        self.assertEqual([item["coord"] for item in internally_skipped], ["com.acme:network-failure"])
        self.assertEqual(
            internally_skipped[0]["reason_code"],
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
        )
        self.assertEqual("step4", internally_skipped[0]["origin_step"])
        self.assertEqual(
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
            internally_skipped[0]["diagnostic_guidance"]["reason_code"],
        )
        self.assertEqual(
            internally_skipped[0]["resolution"],
            "continue_with_final_artifact_analysis",
        )
        self.assertFalse(internally_skipped[0]["user_attention_required"])

    def test_partition_git_ref_pending_treats_operational_failures_as_internal(self):
        for pending_kind in (
            "fetch_failed",
            "remote_query_failed",
            "remote_ref_moved",
            "remote_unavailable",
            "not_found",
            "local_confirmation_required",
        ):
            with self.subTest(pending_kind=pending_kind):
                user_confirmation, internally_skipped = step4.partition_git_ref_pending_items([
                    {
                        "coord": f"com.acme:{pending_kind}",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "pending_kind": pending_kind,
                        "old_candidates": [
                            {"ref": "origin/old-a", "commit": "a" * 40, "score": 140},
                            {"ref": "origin/old-b", "commit": "b" * 40, "score": 140},
                        ],
                        "new_candidates": [
                            {"ref": "origin/new-a", "commit": "c" * 40, "score": 140},
                            {"ref": "origin/new-b", "commit": "d" * 40, "score": 140},
                        ],
                    }
                ])

                self.assertEqual(user_confirmation, [])
                self.assertEqual(len(internally_skipped), 1)
                self.assertFalse(internally_skipped[0]["user_attention_required"])

    def test_preflight_materializes_remote_refs_to_immutable_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            old_candidate = {
                "ref": "origin/release-1.0.0",
                "commit": "a" * 40,
                "canonical_ref": "refs/heads/release-1.0.0",
                "remote": "origin",
            }
            new_candidate = {
                "ref": "origin/release-2.0.0",
                "commit": "b" * 40,
                "canonical_ref": "refs/heads/release-2.0.0",
                "remote": "origin",
            }
            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    old_candidate["ref"],
                    new_candidate["ref"],
                    "old-match",
                    "new-match",
                    [old_candidate],
                    [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    ({"status": "remote_source_resolved", "resolved_commit": "a" * 40, "remote": "origin", "remote_ref": old_candidate["canonical_ref"]}, ""),
                    ({"status": "remote_source_resolved", "resolved_commit": "b" * 40, "remote": "origin", "remote_ref": new_candidate["canonical_ref"]}, ""),
                ],
            ):
                plan = step4.resolve_gitdiff_ref_plan_for_row(
                    {"coord": "com.acme:acct-sdk", "old_version": "1.0.0", "new_version": "2.0.0"},
                    {"repo_path": str(repo_dir), "module_path": str(repo_dir)},
                    {"mapping_mode": "explicit"},
                    {},
                )

        self.assertEqual(plan["status"], "matched")
        self.assertEqual(plan["base_ref"], "a" * 40)
        self.assertEqual(plan["cur_ref"], "b" * 40)
        self.assertEqual(plan["old_source"]["status"], "remote_source_resolved")

    def test_preflight_does_not_prompt_when_only_one_remote_pair_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            old_candidate = {
                "ref": "origin/release-1.0.0", "commit": "a" * 40,
                "canonical_ref": "refs/heads/release-1.0.0", "remote": "origin",
            }
            new_candidate = {
                "ref": "origin/release-2.0.0", "commit": "b" * 40,
                "canonical_ref": "refs/heads/release-2.0.0", "remote": "origin",
            }
            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(
                    old_candidate["ref"], new_candidate["ref"],
                    "unique-old", "unique-new", [old_candidate], [new_candidate],
                ),
            ), patch.object(
                step4,
                "_materialize_resolved_remote_ref",
                side_effect=[
                    ({"status": "remote_source_resolved", "resolved_commit": "a" * 40}, ""),
                    ({"status": "remote_source_resolved", "resolved_commit": "b" * 40}, ""),
                ],
            ):
                matched, pending = step4.preflight_gitdiff_refs(
                    [{
                        "coord": "com.acme:acct-sdk",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "小版本升级",
                    }],
                    {
                        "com.acme:acct-sdk": {
                            "repo_path": str(repo_dir),
                            "module_path": str(repo_dir),
                        }
                    },
                    {"com.acme:acct-sdk": {"mapping_mode": "explicit"}},
                    {},
                )

        self.assertEqual(len(matched), 1)
        self.assertEqual(pending, [])

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
            old_candidates = [
                {"ref": "origin/release-1", "commit": "a" * 40, "score": 140},
                {"ref": "origin/support-1", "commit": "b" * 40, "score": 140},
            ]
            new_candidates = [
                {"ref": "origin/release-2", "commit": "c" * 40, "score": 140},
                {"ref": "origin/support-2", "commit": "d" * 40, "score": 140},
            ]

            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
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
                return_value=(
                    None,
                    None,
                    "ambiguous_ref_matches=2",
                    "ambiguous_ref_matches=2",
                    old_candidates,
                    new_candidates,
                ),
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
            with (report_dir / ".runtime/observability" / step4.STEP4_TIMING_FILE).open(encoding="utf-8-sig") as fh:
                timing_rows = list(csv.DictReader(fh))

        self.assertEqual(exit_code, 2)
        self.assertEqual(len(pending["items"]), 1)
        self.assertEqual(pending["items"][0]["coord"], "com.acme:acct-sdk")
        self.assertTrue(matches["need_user_confirmation"])
        self.assertIn("Step4 依赖的新旧源码版本检查摘要", summary_text)
        self.assertIn("一、结论总览", summary_text)
        self.assertIn("preflight.git_refs", {row["phase"] for row in timing_rows})
        self.assertIn("step4.total", {row["phase"] for row in timing_rows})
        self.assertEqual(timing_rows[-1]["status"], "awaiting_git_ref_confirmation")

    def test_main_internal_source_ref_failure_continues_binary_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            repo_dir = report_dir / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            japicmp_jar = report_dir / "japicmp.jar"
            japicmp_jar.write_bytes(b"test")
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
            binary_output = output_dir / "acct-sdk_binary.txt"
            binary_info = {
                "old_jar": None,
                "new_jar": None,
                "external_process_count": 0,
                "parser_mode": "xml",
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
                    "--japicmp-jar",
                    str(japicmp_jar),
                    "--dependency-repo-mappings",
                    f"com.acme:acct-sdk={repo_dir}",
                    "--skip-changed-classes",
                ],
            ), patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(None, None, "remote_query_failed=timeout", "", [], []),
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(binary_output), [], binary_info, None),
            ) as run_japicmp:
                exit_code = step4.main()

            matches = json.loads((output_dir / "git_ref_matches.json").read_text(encoding="utf-8"))
            pending = json.loads((output_dir / "git_ref_pending.json").read_text(encoding="utf-8"))
            coverage = json.loads(
                (report_dir / ".runtime/coverage/s4_coverage.json").read_text(encoding="utf-8")
            )

        self.assertEqual(exit_code, 0)
        run_japicmp.assert_called_once()
        self.assertFalse(matches["need_user_confirmation"])
        self.assertEqual(matches["summary"]["pending"], 0)
        self.assertEqual(matches["summary"]["skipped"], 1)
        self.assertEqual(
            matches["skipped_items"][0]["reason_code"],
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
        )
        self.assertEqual(pending["items"], [])
        self.assertEqual(coverage["binary_api_diff"]["status"], "complete")
        self.assertEqual(coverage["behavior_diff"]["status"], "insufficient")
        self.assertIn(
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
            coverage["behavior_diff"]["reason_codes"],
        )
        self.assertEqual(
            "UPPER_SNAKE_CASE",
            coverage["diagnostic_contract"]["reason_code_style"],
        )
        self.assertEqual(
            ["DEPENDENCY_SOURCE_REF_UNAVAILABLE"],
            [
                item["reason_code"]
                for item in coverage["diagnostic_guidance"]
            ],
        )

    def test_main_recovers_source_ref_failure_with_final_jar_bytecode_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            repo_dir = report_dir / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            japicmp_jar = report_dir / "japicmp.jar"
            japicmp_jar.write_bytes(b"tool")
            old_jar = report_dir / "old.jar"
            new_jar = report_dir / "new.jar"
            for path, payload in ((old_jar, b"old"), (new_jar, b"new")):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("com/acme/Api.class", payload)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "com.acme:acct-sdk,1.0.0,2.0.0,小版本升级,compile\n",
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.acme:acct-sdk"}]}),
                encoding="utf-8",
            )
            evidence_path = output_dir / "acct-sdk_bytecode_behavior.json"
            behavior_row = {
                "coord": "com.acme:acct-sdk",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "BEHAVIOR_CHANGED",
                "api_name": "com.acme.Api.run",
                "api_simple": "run",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P2",
                "source": "jar_bytecode",
                "reason_code": "FINAL_JAR_METHOD_BODY_CHANGED",
                "evidence_path": str(evidence_path),
            }
            binary_info = {
                "old_jar": str(old_jar),
                "new_jar": str(new_jar),
                "external_process_count": 0,
                "parser_mode": "xml",
            }

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes", str(dep_changes),
                    "--context", str(context_json),
                    "--output-dir", str(output_dir),
                    "--japicmp-jar", str(japicmp_jar),
                    "--dependency-repo-mappings", f"com.acme:acct-sdk={repo_dir}",
                    "--skip-changed-classes",
                ],
            ), patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=(None, None, "remote_query_failed=timeout", "", [], []),
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(output_dir / "binary.txt"), [], binary_info, None),
            ), patch.object(
                step4,
                "collect_data_contract_changes",
                return_value=[],
            ), patch.object(
                step4,
                "compare_jar_method_bodies",
                return_value={
                    "status": "complete",
                    "reason_code": "",
                    "rows": [behavior_row],
                    "modified_classes": 1,
                    "scanned_classes": 1,
                    "javap_invocations": 2,
                    "evidence_path": str(evidence_path),
                    "errors": [],
                },
            ) as compare_behavior:
                exit_code = step4.main()

            coverage = json.loads(
                (report_dir / ".runtime/coverage/s4_coverage.json").read_text(encoding="utf-8")
            )
            with (output_dir / "all_changed_apis.csv").open(encoding="utf-8-sig") as api_file:
                api_rows = list(csv.DictReader(api_file))
            matches = json.loads((output_dir / "git_ref_matches.json").read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        compare_behavior.assert_called_once()
        self.assertEqual(coverage["behavior_diff"]["status"], "complete")
        self.assertEqual(coverage["behavior_diff"]["reason_codes"], [])
        self.assertEqual(
            coverage["behavior_diff"]["metrics"]["jar_bytecode_fallback_dependencies"],
            1,
        )
        self.assertEqual(len(api_rows), 1)
        self.assertEqual(api_rows[0]["source"], "jar_bytecode")
        self.assertEqual(
            matches["skipped_items"][0]["resolution"],
            "recovered_with_final_jar_method_bytecode_diff",
        )

    def test_main_recovers_source_ref_failure_that_occurs_after_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            repo_dir = report_dir / "acct-sdk"
            repo_dir.mkdir()
            (repo_dir / ".git").mkdir()
            japicmp_jar = report_dir / "japicmp.jar"
            japicmp_jar.write_bytes(b"tool")
            old_jar = report_dir / "old.jar"
            new_jar = report_dir / "new.jar"
            for path, payload in ((old_jar, b"old"), (new_jar, b"new")):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("com/acme/Api.class", payload)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "com.acme:acct-sdk,1.0.0,2.0.0,小版本升级,compile\n",
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.acme:acct-sdk"}]}),
                encoding="utf-8",
            )
            fixed_plan = {
                "coord": "com.acme:acct-sdk",
                "base_ref": "a" * 40,
                "cur_ref": "b" * 40,
                "old_source": {"status": "remote_verified"},
                "new_source": {"status": "remote_verified"},
            }
            binary_info = {
                "old_jar": str(old_jar),
                "new_jar": str(new_jar),
                "external_process_count": 0,
                "parser_mode": "xml",
            }
            evidence_path = output_dir / "late_bytecode_behavior.json"

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes", str(dep_changes),
                    "--context", str(context_json),
                    "--output-dir", str(output_dir),
                    "--japicmp-jar", str(japicmp_jar),
                    "--dependency-repo-mappings", f"com.acme:acct-sdk={repo_dir}",
                    "--skip-changed-classes",
                ],
            ), patch.object(
                step4,
                "preflight_gitdiff_refs",
                return_value=([fixed_plan], []),
            ), patch.object(
                step4,
                "run_gitdiff",
                return_value={
                    "status": "needs_user_confirmation",
                    "error": "remote_ref_moved=branch changed after preflight",
                    "out_file": str(output_dir / "late_gitdiff.txt"),
                    "apis": [],
                    "meta": {
                        "reason": "remote_ref_moved=branch changed after preflight",
                        "old_reason": "remote_ref_moved",
                        "new_reason": "remote_ref_moved",
                    },
                },
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(output_dir / "binary.txt"), [], binary_info, None),
            ), patch.object(
                step4,
                "collect_data_contract_changes",
                return_value=[],
            ), patch.object(
                step4,
                "compare_jar_method_bodies",
                return_value={
                    "status": "complete",
                    "reason_code": "",
                    "rows": [],
                    "modified_classes": 1,
                    "scanned_classes": 1,
                    "javap_invocations": 2,
                    "evidence_path": str(evidence_path),
                    "errors": [],
                },
            ) as compare_behavior:
                exit_code = step4.main()

            coverage = json.loads(
                (report_dir / ".runtime/coverage/s4_coverage.json").read_text(encoding="utf-8")
            )
            matches = json.loads((output_dir / "git_ref_matches.json").read_text(encoding="utf-8"))
            pending = json.loads((output_dir / "git_ref_pending.json").read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        compare_behavior.assert_called_once()
        self.assertEqual(pending["items"], [])
        self.assertFalse(matches["need_user_confirmation"])
        self.assertEqual(
            matches["skipped_items"][0]["reason_code"],
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
        )
        self.assertEqual(coverage["behavior_diff"]["status"], "complete")

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
            with timing_path.open(encoding="utf-8-sig") as fh:
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

    def test_list_repo_refs_uses_live_remote_inventory_not_tracking_refs(self):
        inventory = {
            "queried_at": "2026-07-17T00:00:00Z",
            "remotes": ["origin"],
            "failures": [],
            "refs": [
                {
                    "remote": "origin",
                    "ref": "origin/release-1.0.0",
                    "canonical_ref": "refs/heads/release-1.0.0",
                    "short_name": "release-1.0.0",
                    "kind": "branch",
                    "commit": "a" * 40,
                },
                {
                    "remote": "origin",
                    "ref": "origin/v1.0.0",
                    "canonical_ref": "refs/tags/v1.0.0",
                    "short_name": "v1.0.0",
                    "kind": "tag",
                    "commit": "b" * 40,
                }
            ],
        }
        step4._REPO_REFS_CACHE.clear()
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            step4, "query_live_remote_refs", return_value=inventory
        ) as query:
            refs = step4._list_repo_refs(tmp)

        self.assertEqual(refs["remotes"], ["origin/release-1.0.0"])
        self.assertEqual(refs["tags"], ["origin/v1.0.0"])
        self.assertEqual(refs["configured_remotes"], ["origin"])
        self.assertEqual(len(refs["remote_records"]), 2)
        self.assertEqual(refs["remote_records"][0]["commit"], "a" * 40)
        query.assert_called_once()

    def test_live_ref_resolution_uses_origin_before_failed_lower_tier(self):
        with patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "configured_remotes": ["origin", "backup"],
                "remote_records": [{
                    "remote": "origin",
                    "ref": "origin/release-1.2.3",
                    "canonical_ref": "refs/heads/release-1.2.3",
                    "kind": "branch",
                    "commit": "a" * 40,
                }],
                "remote_failures": [{"remote": "backup", "reason": "network timeout"}],
            },
        ):
            candidates, _version, error = step4.list_repo_ref_candidates_for_version(
                "/repo", "1.2.3"
            )

        self.assertIsNone(error)
        self.assertEqual([item["ref"] for item in candidates], ["origin/release-1.2.3"])

    def test_live_ref_resolution_does_not_fall_through_failed_origin(self):
        with patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "configured_remotes": ["origin", "backup"],
                "remote_records": [{
                    "remote": "backup",
                    "ref": "backup/release-1.2.3",
                    "canonical_ref": "refs/heads/release-1.2.3",
                    "kind": "branch",
                    "commit": "b" * 40,
                }],
                "remote_failures": [{"remote": "origin", "reason": "network timeout"}],
            },
        ):
            candidates, _version, error = step4.list_repo_ref_candidates_for_version(
                "/repo", "1.2.3"
            )

        self.assertEqual([item["ref"] for item in candidates], ["backup/release-1.2.3"])
        self.assertEqual(error, "remote_query_failed=network timeout")

    def test_live_peer_remote_failure_is_symmetric_and_blocks_selection(self):
        for healthy, failed in (("backup", "upstream"), ("upstream", "backup")):
            with self.subTest(healthy=healthy, failed=failed), patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "configured_remotes": ["backup", "upstream"],
                    "remote_records": [{
                        "remote": healthy,
                        "ref": f"{healthy}/release-1.2.3",
                        "canonical_ref": "refs/heads/release-1.2.3",
                        "kind": "branch",
                        "commit": "c" * 40,
                    }],
                    "remote_failures": [{"remote": failed, "reason": "network timeout"}],
                },
            ):
                candidates, _version, error = step4.list_repo_ref_candidates_for_version(
                    "/repo", "1.2.3"
                )

            self.assertEqual([item["remote"] for item in candidates], [healthy])
            self.assertEqual(error, "remote_query_failed=network timeout")

    def test_live_peer_tier_requires_all_peers_after_origin_has_no_match(self):
        with patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "configured_remotes": ["origin", "backup", "upstream"],
                "remote_records": [{
                    "remote": "backup",
                    "ref": "backup/release-1.2.3",
                    "canonical_ref": "refs/heads/release-1.2.3",
                    "kind": "branch",
                    "commit": "d" * 40,
                }],
                "remote_failures": [{"remote": "upstream", "reason": "network timeout"}],
            },
        ):
            candidates, _version, error = step4.list_repo_ref_candidates_for_version(
                "/repo", "1.2.3"
            )

        self.assertEqual([item["remote"] for item in candidates], ["backup"])
        self.assertEqual(error, "remote_query_failed=network timeout")

    def test_resolve_repo_ref_for_version_keeps_live_remote_tag_candidate(self):
        commit = "b" * 40
        with patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "heads": [],
                "remotes": [],
                "tags": ["origin/v1.2.3"],
                "remote_failures": [],
                "remote_records": [{
                    "remote": "origin",
                    "ref": "origin/v1.2.3",
                    "canonical_ref": "refs/tags/v1.2.3",
                    "short_name": "v1.2.3",
                    "kind": "tag",
                    "commit": commit,
                }],
            },
        ):
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                "/repo",
                "1.2.3",
            )

        self.assertEqual(resolved, "origin/v1.2.3")
        self.assertIn("kind=tag", reason)
        self.assertEqual(candidates[0]["kind"], "tag")
        self.assertEqual(candidates[0]["commit"], commit)

    def test_ref_pair_prefers_branch_family_but_retains_tag_candidates(self):
        records = [
            {
                "remote": "origin",
                "ref": "origin/release-1.0",
                "canonical_ref": "refs/heads/release-1.0",
                "kind": "branch",
                "commit": "a" * 40,
            },
            {
                "remote": "origin",
                "ref": "origin/v1.0",
                "canonical_ref": "refs/tags/v1.0",
                "kind": "tag",
                "commit": "c" * 40,
            },
            {
                "remote": "origin",
                "ref": "origin/release-2.0",
                "canonical_ref": "refs/heads/release-2.0",
                "kind": "branch",
                "commit": "b" * 40,
            },
            {
                "remote": "origin",
                "ref": "origin/v2.0",
                "canonical_ref": "refs/tags/v2.0",
                "kind": "tag",
                "commit": "d" * 40,
            },
        ]
        with patch.object(
            step4,
            "_list_repo_refs",
            return_value={
                "heads": [],
                "remotes": [item["ref"] for item in records if item["kind"] == "branch"],
                "tags": [item["ref"] for item in records if item["kind"] == "tag"],
                "remote_records": records,
                "remote_failures": [],
            },
        ):
            old_ref, new_ref, old_reason, new_reason, old_candidates, new_candidates = (
                step4.resolve_repo_ref_pair_for_versions("/repo", "1.0", "2.0")
            )

        self.assertEqual(old_ref, "origin/release-1.0")
        self.assertEqual(new_ref, "origin/release-2.0")
        self.assertIn("kind=remote", old_reason)
        self.assertIn("kind=remote", new_reason)
        self.assertEqual({item["kind"] for item in old_candidates}, {"remote", "tag"})
        self.assertEqual({item["kind"] for item in new_candidates}, {"remote", "tag"})

    def test_resolve_repo_ref_for_version_keeps_remote_failure_primary_with_unconfirmed_local_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "resolve_remote_source_ref",
                return_value={
                    "status": "remote_ref_not_found",
                    "candidates": [],
                    "failures": [],
                },
            ), patch.object(
                step4,
                "resolve_local_source_ref",
                return_value={
                    "status": "awaiting_local_source_confirmation",
                    "local_candidate_commit": "b" * 40,
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                    tmp,
                    "3.5.14",
                    selected_ref="mybatis-3.5.14",
                )

        self.assertIsNone(resolved)
        self.assertEqual(
            reason,
            f"remote_source_unavailable=mybatis-3.5.14;local_fallback_available={'b' * 40}",
        )
        self.assertEqual(candidates, [])

    def test_resolve_repo_ref_for_version_accepts_confirmed_local_override(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            step4,
            "resolve_remote_source_ref",
            return_value={
                "status": "remote_ref_not_found",
                "candidates": [],
                "failures": [],
            },
        ), patch.object(
            step4,
            "resolve_local_source_ref",
            return_value={
                "status": "user_confirmed_local_source",
                "resolved_commit": "c" * 40,
            },
        ) as local_resolver:
            resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                tmp,
                "3.5.14",
                selected_ref="mybatis-3.5.14",
                allow_local_source=True,
            )

        self.assertEqual(resolved, "c" * 40)
        self.assertIn("user_confirmed_local_source", reason)
        self.assertEqual(candidates, [])
        self.assertTrue(local_resolver.call_args.kwargs["allow_local_source"])

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

    def test_infer_maven_coord_locations_does_not_resolve_every_walked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            for branch in range(8):
                current = root / f"branch-{branch}"
                for depth in range(20):
                    current = current / f"depth-{depth}"
                    current.mkdir(parents=True, exist_ok=True)

            original_resolve = Path.resolve
            resolve_calls = []

            def counted_resolve(path, *args, **kwargs):
                resolve_calls.append(str(path))
                return original_resolve(path, *args, **kwargs)

            with patch.object(Path, "resolve", counted_resolve):
                locations = compat.infer_maven_coord_locations(str(root))

        self.assertEqual(locations, [])
        self.assertLess(
            len(resolve_calls),
            20,
            f"repository walk performed {len(resolve_calls)} realpath resolutions",
        )

    def test_step4_reuses_maven_coord_locations_for_the_same_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            inferred = [
                {
                    "coord": "com.example:demo",
                    "module_dir": str(repo),
                    "repo_root": str(repo),
                }
            ]
            cache = {}
            with patch.object(
                step4,
                "infer_maven_coord_locations",
                return_value=inferred,
            ) as infer_mock:
                first = step4._cached_maven_coord_locations(str(repo), cache)
                second = step4._cached_maven_coord_locations(str(repo / "."), cache)

        self.assertIs(first, second)
        infer_mock.assert_called_once_with(
            os.path.abspath(str(repo)),
            max_poms=120,
            max_depth=4,
        )

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

            with patch.object(step4, "_is_git_worktree", return_value=True), patch.object(
                step4, "resolve_repo_ref_for_version", side_effect=[(None, "miss-old", []), (None, "miss-new", [])]
            ):
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
        self.assertIn("Step4 依赖源码版本解析结果（无需用户确认）", text)
        self.assertIn("一、结论总览", text)
        self.assertNotIn("generated_at=", text)

    def test_cleanup_step4_generated_outputs_removes_stale_generated_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            stale_gitdiff = output_dir / "demo-lib_gitdiff_api_changes.txt"
            stale_summary = output_dir / "summary.txt"
            stale_changed_dependencies = (
                output_dir / step4.CHANGED_DEPENDENCIES_CSV
            )
            stale_priority_evidence = (
                output_dir / step4.BUSINESS_BYTECODE_PRIORITY_EVIDENCE_JSON
            )
            unrelated = output_dir / "keep.me"
            stale_gitdiff.write_text("old diff", encoding="utf-8")
            stale_summary.write_text("old summary", encoding="utf-8")
            stale_changed_dependencies.write_text("old rows", encoding="utf-8")
            stale_priority_evidence.write_text("{}", encoding="utf-8")
            unrelated.write_text("keep", encoding="utf-8")

            step4.cleanup_step4_generated_outputs(output_dir)

            self.assertFalse(stale_gitdiff.exists())
            self.assertFalse(stale_summary.exists())
            self.assertFalse(stale_changed_dependencies.exists())
            self.assertFalse(stale_priority_evidence.exists())
            self.assertTrue(unrelated.exists())

    def test_main_prefers_step1_packaged_jars_for_japicmp(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            base_artifact = report_dir / "base-app.jar"
            current_artifact = report_dir / "current-app.jar"
            base_entry = "BOOT-INF/lib/demo-1.0.0.jar"
            current_entry = "BOOT-INF/lib/demo-2.0.0.jar"
            nested_jar = io.BytesIO()
            with zipfile.ZipFile(nested_jar, "w") as zf:
                zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            nested_jar_bytes = nested_jar.getvalue()
            with zipfile.ZipFile(base_artifact, "w") as zf:
                zf.writestr(base_entry, nested_jar_bytes)
                zf.writestr("BOOT-INF/lib/stable-1.0.0.jar", nested_jar_bytes)
            with zipfile.ZipFile(current_artifact, "w") as zf:
                zf.writestr(current_entry, nested_jar_bytes)
                zf.writestr("BOOT-INF/lib/stable-1.0.0.jar", nested_jar_bytes)
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
            retained_base = dependencies_dir / "s1_dependency_jars/base/demo.jar"
            retained_current = dependencies_dir / "s1_dependency_jars/current/demo.jar"
            retained_base.parent.mkdir(parents=True)
            retained_current.parent.mkdir(parents=True)
            retained_base.write_bytes(nested_jar_bytes)
            retained_current.write_bytes(nested_jar_bytes)
            (dependencies_dir / "dependency_jars.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.step1-dependency-jars.v1",
                    "items": [
                        {
                            "side": "base",
                            "coord": "com.example:demo",
                            "version": "1.0.0",
                            "lib_entry": base_entry,
                            "retained_path": str(retained_base),
                            "nested_jar_sha256": hashlib.sha256(nested_jar_bytes).hexdigest(),
                            "outer_artifact_path": str(base_artifact),
                            "outer_artifact_sha256": "base-sha",
                        },
                        {
                            "side": "current",
                            "coord": "com.example:demo",
                            "version": "2.0.0",
                            "lib_entry": current_entry,
                            "retained_path": str(retained_current),
                            "nested_jar_sha256": hashlib.sha256(nested_jar_bytes).hexdigest(),
                            "outer_artifact_path": str(current_artifact),
                            "outer_artifact_sha256": "current-sha",
                        },
                    ],
                }),
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
                json.dumps(
                    {
                        "changed_dependencies": [{"coord": "com.example:demo"}],
                        "jdk_current": "21",
                    },
                    ensure_ascii=False,
                ),
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
            ), patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}):
                exit_code = step4.main()

            self.assertEqual(exit_code, 0)
            japicmp_mock.assert_called_once()
            kwargs = japicmp_mock.call_args.kwargs
            self.assertEqual(kwargs["old_jar_evidence"]["source"], "step1_retained_dependency_jar")
            self.assertEqual(kwargs["new_jar_evidence"]["source"], "step1_retained_dependency_jar")
            self.assertEqual(kwargs["jdk_current"], "21")
            self.assertTrue(Path(kwargs["old_jar_path"]).exists())
            self.assertTrue(Path(kwargs["new_jar_path"]).exists())
            self.assertEqual(Path(kwargs["old_jar_path"]).read_bytes(), nested_jar_bytes)
            self.assertEqual(Path(kwargs["new_jar_path"]).read_bytes(), nested_jar_bytes)
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

    def test_parallel_japicmp_failure_is_not_reported_as_zero_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output_dir = report_dir / "s4_jar_compare"
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "com.example:no-change,1.0.0,2.0.0,小版本升级,compile",
                        "com.example:failed,1.0.0,2.0.0,小版本升级,compile",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps(
                    {
                        "changed_dependencies": [
                            {"coord": "com.example:no-change"},
                            {"coord": "com.example:failed"},
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            barrier = threading.Barrier(2)

            def fake_run_japicmp(coord, *_args, **_kwargs):
                barrier.wait(timeout=2)
                out_file = output_dir / f"{coord.rsplit(':', 1)[-1]}_binary.txt"
                if coord == "com.example:failed":
                    return (
                        str(out_file),
                        [],
                        {
                            "old_jar": "",
                            "new_jar": "",
                            "reason_code": "JAPICMP_EXECUTION_FAILED",
                        },
                        "Unsupported class file major version",
                    )
                return (
                    str(out_file),
                    [],
                    {"old_jar": "", "new_jar": ""},
                    None,
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
                side_effect=fake_run_japicmp,
            ):
                exit_code = step4.main()

            status_payload = json.loads(
                (output_dir / step4.DEPENDENCY_ANALYSIS_STATUS_JSON).read_text(
                    encoding="utf-8"
                )
            )
            by_coord = {
                row["coord"]: row for row in status_payload["items"]
            }
            summary_text = (output_dir / "summary.txt").read_text(
                encoding="utf-8"
            )
            changed_dependencies = (
                output_dir / step4.CHANGED_DEPENDENCIES_MD
            ).read_text(encoding="utf-8")
            direct_status = (
                output_dir / step4.DEPENDENCY_ANALYSIS_STATUS_MD
            ).read_text(encoding="utf-8")
            coverage = json.loads(
                (
                    report_dir / ".runtime/coverage/s4_coverage.json"
                ).read_text(encoding="utf-8")
            )
            failed_summary = json.loads(
                (
                    step4.get_per_dependency_dir(
                        str(report_dir),
                        "com.example:failed",
                    )
                    / step4.PER_DEPENDENCY_SUMMARY_FILE
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            by_coord["com.example:no-change"]["api_comparison_status"],
            "no_api_change",
        )
        self.assertEqual(
            by_coord["com.example:failed"]["api_comparison_status"],
            "failed",
        )
        self.assertIsNone(
            by_coord["com.example:failed"]["api_change_count"]
        )
        self.assertIn(
            "com.example:failed",
            summary_text.split(
                "API 对比失败、没有数据", 1
            )[1],
        )
        self.assertNotIn(
            "com.example:failed",
            summary_text.split(
                "API 对比成功且未发现可见变化", 1
            )[1].split("高风险/需关注 API", 1)[0],
        )
        self.assertIn("API 对比失败、不能进入 Step5", changed_dependencies)
        self.assertIn(
            "未提供依赖源码，无法检查实现变化；当前证据不完整",
            direct_status,
        )
        self.assertIn("可以按无变化处理”为“是”时", direct_status)
        self.assertEqual(coverage["binary_api_diff"]["status"], "partial")
        self.assertIn(
            "JAPICMP_EXECUTION_FAILED",
            coverage["binary_api_diff"]["reason_codes"],
        )
        self.assertEqual(failed_summary["step4"]["status"], "incomplete")
        self.assertEqual(
            failed_summary["step4"]["binary_api_comparison"][
                "comparison_status"
            ],
            "failed",
        )

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
        self.assertIn("[进度][依赖 API 变化][准备]", output)
        self.assertIn("[进度][依赖 API 变化][处理依赖]", output)
        self.assertIn("[进度][依赖 API 变化][制品 API 对比]", output)
        self.assertIn("[进度][依赖 API 变化][完成]", output)

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

        confirmed_local = run_step.normalize_dependency_git_ref_overrides([
            {
                "coord": "com.foo:local",
                "old_ref": "local-v1",
                "new_ref": "local-v2",
                "allow_local_source": True,
                "allow_dirty_local_source": True,
            }
        ])
        self.assertTrue(confirmed_local[0]["allow_local_source"])
        self.assertTrue(confirmed_local[0]["allow_dirty_local_source"])

        with self.assertRaises(run_step.StepError):
            run_step.normalize_dependency_git_ref_overrides([
                {
                    "coord": "com.foo:invalid",
                    "old_ref": "v1",
                    "new_ref": "v2",
                    "allow_dirty_local_source": True,
                }
            ])

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

    def test_step4_rerun_requires_all_pending_git_refs_in_one_reply(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_git_refs_need_confirmation",
            "pending_git_ref_items": [
                {"coord": "com.foo:bar"},
                {"coord": "com.foo:baz"},
            ],
        }
        with self.assertRaisesRegex(run_step.StepError, "com.foo:baz"):
            run_step.validate_pending_interaction_response(
                pending_interaction,
                {
                    "action": "rerun_current_step",
                    "dependency_git_ref_overrides": [
                        {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"}
                    ],
                },
            )

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_git_ref_overrides": [
                    {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"},
                    {"coord": "com.foo:baz", "old_ref": "v3", "new_ref": "v4"},
                ],
            },
        )

    def test_step4_git_ref_decision_card_accepts_compact_pair_selections(self):
        pending_items = []
        for index, coord in enumerate(("com.foo:bar", "com.foo:baz"), start=1):
            pending_items.append({
                "coord": coord,
                "repo_path": f"/repo/{index}",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "reason": "无法定位唯一 ref pair",
                "old_candidates": [
                    {
                        "ref": f"origin/release-{index}-1.0.0", "commit": str(index) * 40,
                        "score": 140, "prefix": f"release-{index}", "remote_name": "origin",
                        "branch_name": f"release-{index}-1.0.0",
                    }
                ],
                "new_candidates": [
                    {
                        "ref": f"origin/release-{index}-2.0.0", "commit": str(index + 2) * 40,
                        "score": 140, "prefix": f"release-{index}", "remote_name": "origin",
                        "branch_name": f"release-{index}-2.0.0",
                    }
                ],
            })
        with tempfile.TemporaryDirectory() as tmp:
            interaction = step4.build_git_ref_confirmation_interaction(tmp, pending_items)

        selections = [
            {"coord": item["coord"], "option": 1}
            for item in interaction["git_ref_decision_items"]
        ]
        response = {
            "action": "rerun_current_step",
            "dependency_git_ref_selections": selections,
        }
        run_step.validate_pending_interaction_response(interaction, response)
        expanded = run_step.expand_dependency_git_ref_selections(interaction, response)
        card = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertEqual(len(expanded["dependency_git_ref_overrides"]), 2)
        self.assertIn("需要确认的依赖源码版本", card)
        self.assertIn("共 2 个，请一次答全", card)
        self.assertIn("升级前", card)
        self.assertIn("升级后", card)
        self.assertIn("com.foo:bar 选方案 1；com.foo:baz 选方案 1", card)
        self.assertNotIn("refpair:", card)

        with tempfile.TemporaryDirectory() as tmp:
            state = run_step.new_main_state(Path(tmp) / ".upgrade-report")
            updated_state, updated_context = run_step.apply_user_response_to_main_state(
                state,
                interaction,
                response,
                tmp,
                target_step_id="step4",
            )
        self.assertEqual(len(updated_context["dependency_git_ref_overrides"]), 2)
        self.assertEqual(
            updated_state["step4"]["input"]["dependency_git_ref_overrides"],
            updated_context["dependency_git_ref_overrides"],
        )

    def test_merge_user_response_preserves_previous_git_ref_overrides_by_coord(self):
        merged = run_step.merge_user_response_into_run_context(
            {
                "dependency_git_ref_overrides": [
                    {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"},
                    {"coord": "com.foo:baz", "old_ref": "v3", "new_ref": "v4"},
                ]
            },
            {
                "dependency_git_ref_overrides": [
                    {"coord": "com.foo:bar", "old_ref": "release-1", "new_ref": "release-2"}
                ]
            },
            "/tmp/project",
        )

        self.assertEqual(
            merged["dependency_git_ref_overrides"],
            [
                {"coord": "com.foo:bar", "old_ref": "release-1", "new_ref": "release-2"},
                {"coord": "com.foo:baz", "old_ref": "v3", "new_ref": "v4"},
            ],
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
