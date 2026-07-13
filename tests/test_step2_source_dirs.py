import csv
import json
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s2_context_from_deps as step2  # noqa: E402
import gate  # noqa: E402


class Step2SourceDirsTest(unittest.TestCase):
    def test_dependency_graph_does_not_infer_edges_from_raw_dependency_poms(self):
        deps = {
            "org.example:parent": {
                "coord": "org.example:parent", "old_version": "1", "new_version": "2",
                "change_type": "升级", "scope": "packaged",
            },
            "org.example:excluded": {
                "coord": "org.example:excluded", "old_version": "1", "new_version": "2",
                "change_type": "升级", "scope": "packaged",
            },
        }

        with patch.object(
            step2,
            "get_pom_deps_from_m2",
            return_value=["org.example:excluded"],
        ) as raw_pom_lookup:
            graph = step2.build_dep_graph(deps)

        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["relationship_status"], "not_inferred_without_resolved_tree")
        raw_pom_lookup.assert_not_called()

    def test_explicit_source_dirs_override_auto_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            dep_changes = tmp_path / "s1_dep_changes.csv"
            output_json = tmp_path / "s2_context.json"
            explicit_a = tmp_path / "module-a" / "src" / "main" / "java"
            explicit_b = tmp_path / "module-b" / "src" / "main" / "java"
            explicit_a.mkdir(parents=True)
            explicit_b.mkdir(parents=True)

            with dep_changes.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["coord", "old_version", "new_version", "change_type", "scope"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "org.springframework.boot:spring-boot",
                        "old_version": "2.7.18",
                        "new_version": "3.2.5",
                        "change_type": "升级",
                        "scope": "compile",
                    }
                )

            argv = [
                "s2_context_from_deps.py",
                "--dep-changes",
                str(dep_changes),
                "--base",
                "origin/main",
                "--current",
                "feature/upgrade",
                "--work-dir",
                str(tmp_path),
                "--source-dirs",
                str(explicit_a),
                str(explicit_b),
                "--output",
                str(output_json),
            ]

            with patch.object(sys, "argv", argv):
                with patch.object(step2, "detect_build_tool", return_value="maven"):
                    with patch.object(step2, "auto_detect_source_dirs") as auto_detect:
                        with patch.object(step2, "detect_spring_boot_version", return_value=("2.7.18", "3.2.5", "step1_scope")):
                            with patch.object(step2, "detect_spring_cloud", return_value=(False, None)):
                                with patch.object(step2, "detect_jdk_versions", return_value=("8", "17")):
                                    with patch.object(step2, "detect_tech_flags", return_value={}):
                                        with patch.object(step2, "detect_jvm_param_changes", return_value=[]):
                                            step2.main()

            payload = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["source_dirs"],
                [str(explicit_a), str(explicit_b)],
            )
            auto_detect.assert_not_called()

    def test_detect_jdk_versions_returns_unknown_without_git_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pom.xml").write_text(
                "<project><properties><java.version>17</java.version></properties></project>",
                encoding="utf-8",
            )

            with patch.object(step2, "is_git_repo", return_value=False):
                jdk_base, jdk_current = step2.detect_jdk_versions(
                    "origin/main",
                    "feature/upgrade",
                    str(tmp_path),
                    "maven",
                )

        self.assertIsNone(jdk_base)
        self.assertIsNone(jdk_current)

    def test_parse_maven_help_evaluate_jdk_tolerates_noise(self):
        self.assertEqual(step2.parse_maven_help_evaluate_jdk("17"), "17")
        self.assertEqual(step2.parse_maven_help_evaluate_jdk("17%"), "17")
        self.assertEqual(
            step2.parse_maven_help_evaluate_jdk("null object or invalid expression"),
            None,
        )

    def test_detect_jdk_versions_falls_back_to_effective_maven_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "pom.xml").write_text(
                "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                encoding="utf-8",
            )

            with patch.object(step2, "is_git_repo", return_value=True):
                with patch.object(
                    step2,
                    "git_show_file",
                    side_effect=[
                        "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                        "<project><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
                    ],
                ):
                    with patch.object(
                        step2,
                        "resolve_maven_jdk_from_effective_model",
                        side_effect=["11", "17"],
                    ) as resolver:
                        jdk_base, jdk_current = step2.detect_jdk_versions(
                            "origin/main",
                            "feature/upgrade",
                            str(tmp_path),
                            "maven",
                        )

        self.assertEqual(jdk_base, "11")
        self.assertEqual(jdk_current, "17")
        self.assertEqual(resolver.call_count, 2)

    def test_gate_context_allows_unknown_jdk_for_checkpoint_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True)
            (context_dir / "context.json").write_text(
                json.dumps(
                    {
                        "build_tool": "maven",
                        "base_branch": "origin/main",
                        "current_branch": "feature/upgrade",
                        "jdk_base": "unknown",
                        "jdk_current": "unknown",
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            gate.gate_context(str(report_dir))


if __name__ == "__main__":
    unittest.main()
