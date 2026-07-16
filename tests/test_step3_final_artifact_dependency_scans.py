import csv
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s3_scan  # noqa: E402


CLASSFILE_HEADERS = [
    "依赖坐标",
    "版本",
    "依赖范围",
    "最终制品内路径",
    "是否为多版本JAR",
    "基础区最高Class版本",
    "多版本区最高Class版本",
    "基础区所需Java版本",
    "多版本区所需Java版本",
    "最高所需Java版本",
    "目标JDK版本",
    "扫描结论",
]


class Step3FinalArtifactDependencyScansTest(unittest.TestCase):
    def setUp(self):
        self.old_report_dir = s3_scan.STEP3_REPORT_DIR
        self.old_target_jdk = s3_scan.TARGET_JDK
        s3_scan.TARGET_JDK = 17

    def tearDown(self):
        s3_scan.STEP3_REPORT_DIR = self.old_report_dir
        s3_scan.TARGET_JDK = self.old_target_jdk

    @staticmethod
    def _jar_bytes(entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)
        return buffer.getvalue()

    def _prepare_report(self, root, dependency_rows, nested_entries):
        report_dir = root / ".upgrade-report"
        dependencies_dir = report_dir / "evidence" / "dependencies"
        dependencies_dir.mkdir(parents=True)
        artifact_path = dependencies_dir / "s1_artifacts" / "current-app.jar"
        artifact_path.parent.mkdir()
        with zipfile.ZipFile(artifact_path, "w") as outer:
            for name, content in nested_entries:
                outer.writestr(name, content)
        (dependencies_dir / "build_provenance.json").write_text(
            json.dumps(
                {
                    "schema": "java-upgrade-analyzer.build-provenance.v1",
                    "sides": [
                        {
                            "side": "current",
                            "artifact_path": str(artifact_path),
                            "build_succeeded": True,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        current_path = dependencies_dir / "deps_current_resolved.csv"
        fieldnames = [
            "entry_id",
            "lib_entry",
            "lib_name",
            "coord",
            "version",
            "scope",
            "resolution_status",
        ]
        with current_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(dependency_rows)
        s3_scan.STEP3_REPORT_DIR = str(report_dir)
        return current_path

    def test_classfile_scan_uses_each_nested_jar_from_current_final_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry_a = "BOOT-INF/lib/demo-1.0.jar"
            entry_b = "BOOT-INF/lib/demo-copy-1.0.jar"
            class_bytes = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"
            current_path = self._prepare_report(
                root,
                [
                    {
                        "entry_id": entry_a,
                        "lib_entry": entry_a,
                        "lib_name": "demo-1.0.jar",
                        "coord": "org.example:demo",
                        "version": "1.0",
                        "scope": "runtime",
                        "resolution_status": "resolved",
                    },
                    {
                        "entry_id": entry_b,
                        "lib_entry": entry_b,
                        "lib_name": "demo-copy-1.0.jar",
                        "coord": "org.example:demo",
                        "version": "1.0",
                        "scope": "runtime",
                        "resolution_status": "resolved",
                    },
                ],
                [
                    (entry_a, self._jar_bytes([("org/example/A.class", class_bytes)])),
                    (entry_b, self._jar_bytes([("org/example/B.class", class_bytes)])),
                ],
            )
            output = root / "s3_dependency_classfile.csv"

            with patch.object(
                s3_scan,
                "find_maven_jar",
                side_effect=AssertionError("不得读取本地 Maven 仓库"),
                create=True,
            ):
                risk_count = s3_scan.scan_dependency_classfile_versions(
                    [], str(output), str(current_path)
                )

            self.assertEqual(risk_count, 0)
            with output.open(encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, CLASSFILE_HEADERS)
            self.assertEqual(len(rows), 2)
            self.assertEqual(
                {row["最终制品内路径"] for row in rows}, {entry_a, entry_b}
            )
            self.assertTrue(all(row["基础区最高Class版本"] == "61" for row in rows))
            self.assertTrue(all(row["扫描结论"] == "扫描完成，未发现字节码版本风险" for row in rows))

    def test_classfile_scan_keeps_coordinate_unresolved_physical_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = "BOOT-INF/lib/vendor-private.jar"
            current_path = self._prepare_report(
                root,
                [
                    {
                        "entry_id": entry,
                        "lib_entry": entry,
                        "lib_name": "vendor-private.jar",
                        "coord": "",
                        "version": "",
                        "scope": "runtime",
                        "resolution_status": "unresolved",
                    }
                ],
                [(entry, self._jar_bytes([("vendor/Private.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")]))],
            )
            output = root / "s3_dependency_classfile.csv"

            s3_scan.scan_dependency_classfile_versions([], str(output), str(current_path))

            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["依赖坐标"], "未解析")
            self.assertEqual(rows[0]["最终制品内路径"], entry)
            self.assertEqual(rows[0]["基础区所需Java版本"], "8")

    def test_missing_nested_entry_is_reported_as_final_artifact_contract_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = "BOOT-INF/lib/missing.jar"
            current_path = self._prepare_report(
                root,
                [
                    {
                        "entry_id": entry,
                        "lib_entry": entry,
                        "lib_name": "missing.jar",
                        "coord": "org.example:missing",
                        "version": "1.0",
                        "scope": "runtime",
                        "resolution_status": "resolved",
                    }
                ],
                [],
            )
            output = root / "s3_dependency_classfile.csv"

            risk_count = s3_scan.scan_dependency_classfile_versions([], str(output), str(current_path))

            self.assertEqual(risk_count, 1)
            with output.open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["扫描结论"], "未完成：current 最终制品内找不到该依赖条目")

    def test_dependency_compat_scans_nested_jar_instead_of_local_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = "BOOT-INF/lib/legacy-1.0.jar"
            current_path = self._prepare_report(
                root,
                [
                    {
                        "entry_id": entry,
                        "lib_entry": entry,
                        "lib_name": "legacy-1.0.jar",
                        "coord": "org.example:legacy",
                        "version": "1.0",
                        "scope": "runtime",
                        "resolution_status": "resolved",
                    }
                ],
                [
                    (
                        entry,
                        self._jar_bytes(
                            [
                                ("META-INF/spring.factories", b"example.Factory=example.Impl\n"),
                                ("example/Impl.class", b"\xca\xfe\xba\xbejavax/servlet/Servlet"),
                            ]
                        ),
                    )
                ],
            )
            output = root / "s3_dependency_compat.csv"

            with patch.object(
                s3_scan,
                "find_maven_jar",
                side_effect=AssertionError("不得读取本地 Maven 仓库"),
                create=True,
            ):
                count = s3_scan.scan_dependency_compat([], str(output), str(current_path))

            self.assertEqual(count, 2)
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(
                {row["风险类型"] for row in rows}, {"spring_factories", "javax_reference"}
            )
            self.assertTrue(all(row["最终制品内路径"] == entry for row in rows))

    def test_legacy_dep_changes_argument_prefers_sibling_current_artifact_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = "BOOT-INF/lib/demo-2.0.jar"
            current_path = self._prepare_report(
                root,
                [
                    {
                        "entry_id": entry,
                        "lib_entry": entry,
                        "lib_name": "demo-2.0.jar",
                        "coord": "org.example:demo",
                        "version": "2.0",
                        "scope": "runtime",
                        "resolution_status": "resolved",
                    }
                ],
                [(entry, self._jar_bytes([("org/example/Demo.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x3d")]))],
            )
            dep_changes_path = current_path.parent / "dep_changes.csv"
            dep_changes_path.write_text(
                "coord,old_version,new_version,change_type,scope\n"
                "org.example:demo,1.0,2.0,小版本升级,runtime\n",
                encoding="utf-8",
            )
            output = root / "s3_dependency_classfile.csv"

            s3_scan.scan_dependency_classfile_versions([], str(output), str(dep_changes_path))

            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["最终制品内路径"], entry)
            self.assertEqual(rows[0]["扫描结论"], "扫描完成，未发现字节码版本风险")


if __name__ == "__main__":
    unittest.main()
