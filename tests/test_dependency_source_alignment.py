import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import dependency_source_alignment as alignment  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


class DependencySourceAlignmentTest(unittest.TestCase):
    def _git(self, repo, *args):
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return result.stdout.strip()

    def _write_java(self, repo, class_name):
        path = Path(repo) / "src" / "main" / "java" / "com" / "example" / f"{class_name}.java"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"package com.example; public class {class_name} {{ public void call() {{}} }}\n",
            encoding="utf-8",
        )
        return path

    def _make_repo(self, root):
        repo = Path(root) / "dependency-repo"
        repo.mkdir()
        self._git(repo, "init")
        self._git(repo, "config", "user.email", "test@example.com")
        self._git(repo, "config", "user.name", "Test User")
        (repo / "README.md").write_text("base\n", encoding="utf-8")
        self._git(repo, "add", "README.md")
        self._git(repo, "commit", "-m", "base")

        self._git(repo, "switch", "-c", "jar-version")
        self._write_java(repo, "RightOnly")
        self._write_java(repo, "NotPackaged")
        self._git(repo, "add", "src")
        self._git(repo, "commit", "-m", "jar version")

        base_commit = self._git(repo, "rev-parse", "jar-version~1")
        self._git(repo, "switch", "-c", "wrong-local", base_commit)
        self._write_java(repo, "WrongOnly")
        self._git(repo, "add", "src")
        self._git(repo, "commit", "-m", "wrong local")
        (repo / "LOCAL_UNCOMMITTED.txt").write_text("do not touch\n", encoding="utf-8")
        return repo

    def _make_runtime_jar(self, root, class_names=("RightOnly",)):
        jar_path = Path(root) / "dep.jar"
        with zipfile.ZipFile(jar_path, "w") as jar:
            for class_name in class_names:
                jar.writestr(f"com/example/{class_name}.class", b"class-bytes")
        return jar_path

    def _write_ref_evidence(self, report_dir, repo, refs=("jar-version",)):
        path = Path(report_dir) / "evidence" / "api_changes" / "git_ref_matches.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        items = []
        for ref in refs:
            items.append({
                "status": "success",
                "meta": {
                    "coord": "com.example:dep",
                    "repo_path": str(repo),
                    "module_rel_path": ".",
                    "resolved_new_ref": ref,
                    "new_version": "2.0.0",
                },
            })
        path.write_text(json.dumps({"matched_items": items}), encoding="utf-8")
        return path

    def _catalog(self, jar_path):
        return {
            "by_coord": {
                "com.example:dep": {
                    "coord": "com.example:dep",
                    "version": "2.0.0",
                    "jar_path": str(jar_path),
                }
            }
        }

    def test_alignment_uses_selected_ref_without_touching_user_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            report_dir = Path(tmp) / ".upgrade-report"
            jar_path = self._make_runtime_jar(tmp)
            self._write_ref_evidence(report_dir, repo)
            before = {
                "branch": self._git(repo, "branch", "--show-current"),
                "head": self._git(repo, "rev-parse", "HEAD"),
                "status": self._git(repo, "status", "--porcelain"),
            }

            result = alignment.align_dependency_source_mappings(
                str(report_dir),
                [f"com.example:dep={repo}"],
                self._catalog(jar_path),
            )

            after = {
                "branch": self._git(repo, "branch", "--show-current"),
                "head": self._git(repo, "rev-parse", "HEAD"),
                "status": self._git(repo, "status", "--porcelain"),
            }
            self.assertEqual(after, before)
            self.assertNotIn(
                ".runtime/source_snapshots",
                self._git(repo, "worktree", "list", "--porcelain"),
            )
            self.assertEqual(len(result["mappings"]), 1)
            snapshot_source = Path(result["mappings"][0].split("=", 1)[1])
            self.assertIn(".runtime/source_snapshots", snapshot_source.as_posix())
            self.assertTrue((snapshot_source / "com" / "example" / "RightOnly.java").is_file())
            self.assertFalse((snapshot_source / "com" / "example" / "WrongOnly.java").exists())
            self.assertEqual(result["allowed_classes_by_coord"]["com.example:dep"], {"com.example.RightOnly"})
            self.assertEqual(result["records"][0]["status"], "aligned")
            self.assertFalse(result["records"][0]["snapshot_reused"])
            self.assertEqual(result["records"][0]["source_class_count"], 2)
            self.assertEqual(result["records"][0]["retained_source_class_count"], 1)
            self.assertEqual(result["records"][0]["skipped_source_class_count"], 1)
            evidence = json.loads(Path(result["evidence_path"]).read_text(encoding="utf-8"))
            self.assertEqual(evidence["items"][0]["selected_ref"], "jar-version")
            self.assertEqual(evidence["items"][0]["skipped_source_class_count"], 1)

    def test_alignment_reuses_snapshot_for_same_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            report_dir = Path(tmp) / ".upgrade-report"
            jar_path = self._make_runtime_jar(tmp)
            self._write_ref_evidence(report_dir, repo)

            first = alignment.align_dependency_source_mappings(
                str(report_dir), [f"com.example:dep={repo}"], self._catalog(jar_path)
            )
            second = alignment.align_dependency_source_mappings(
                str(report_dir), [f"com.example:dep={repo}"], self._catalog(jar_path)
            )

            self.assertEqual(first["mappings"], second["mappings"])
            self.assertTrue(second["records"][0]["snapshot_reused"])

    def test_alignment_collapses_duplicate_paths_for_same_coord_module_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            report_dir = Path(tmp) / ".upgrade-report"
            jar_path = self._make_runtime_jar(tmp)
            self._write_ref_evidence(report_dir, repo)

            result = alignment.align_dependency_source_mappings(
                str(report_dir),
                [
                    f"com.example:dep={repo}",
                    f"com.example:dep={repo / 'src'}",
                    f"com.example:dep={repo / 'src' / 'main' / 'java'}",
                ],
                self._catalog(jar_path),
            )

            self.assertEqual(len(result["mappings"]), 1)
            self.assertEqual(len(result["records"]), 1)

    def test_alignment_rejects_missing_or_conflicting_ref_without_local_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            jar_path = self._make_runtime_jar(tmp)
            mapping = f"com.example:dep={repo}"

            missing_report = Path(tmp) / "missing-report"
            missing = alignment.align_dependency_source_mappings(
                str(missing_report), [mapping], self._catalog(jar_path)
            )
            self.assertEqual(missing["mappings"], [])
            self.assertEqual(missing["records"][0]["reason_code"], "step4_current_ref_missing")
            self.assertNotIn(str(repo), missing["mappings"])

            conflict_report = Path(tmp) / "conflict-report"
            self._write_ref_evidence(conflict_report, repo, refs=("jar-version", "wrong-local"))
            conflict = alignment.align_dependency_source_mappings(
                str(conflict_report), [mapping], self._catalog(jar_path)
            )
            self.assertEqual(conflict["mappings"], [])
            self.assertEqual(conflict["records"][0]["reason_code"], "step4_current_ref_conflict")

    def test_real_multibranch_snapshot_graph_uses_selected_ref_and_jar_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            report_dir = Path(tmp) / ".upgrade-report"
            jar_path = self._make_runtime_jar(tmp, class_names=("RightOnly",))
            self._write_ref_evidence(report_dir, repo)
            original_head = self._git(repo, "rev-parse", "HEAD")
            original_status = self._git(repo, "status", "--porcelain")

            aligned = alignment.align_dependency_source_mappings(
                str(report_dir), [f"com.example:dep={repo}"], self._catalog(jar_path)
            )
            roots = step5.build_source_roots([], aligned["mappings"])
            graph_result = step5.build_enhanced_source_graph(
                roots,
                allowed_dependency_classes_by_coord=aligned["allowed_classes_by_coord"],
            )
            methods = list(graph_result["graph"].methods_by_id.values())

            self.assertTrue(any(method.class_fqcn == "com.example.RightOnly" for method in methods))
            self.assertFalse(any(method.class_fqcn == "com.example.NotPackaged" for method in methods))
            self.assertFalse(any(method.class_fqcn == "com.example.WrongOnly" for method in methods))
            self.assertEqual(self._git(repo, "rev-parse", "HEAD"), original_head)
            self.assertEqual(self._git(repo, "status", "--porcelain"), original_status)

    def test_alignment_rejects_invalid_ref_repo_mismatch_and_escaping_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._make_repo(tmp)
            jar_path = self._make_runtime_jar(tmp)
            catalog = self._catalog(jar_path)

            invalid_report = Path(tmp) / "invalid-ref-report"
            self._write_ref_evidence(invalid_report, repo, refs=("does-not-exist",))
            invalid = alignment.align_dependency_source_mappings(
                str(invalid_report), [f"com.example:dep={repo}"], catalog
            )
            self.assertEqual(invalid["mappings"], [])
            self.assertEqual(invalid["records"][0]["reason_code"], "dependency_source_ref_not_found")

            other_repo = Path(tmp) / "other-repo"
            other_repo.mkdir()
            self._git(other_repo, "init")
            mismatch_report = Path(tmp) / "mismatch-report"
            self._write_ref_evidence(mismatch_report, repo)
            mismatch = alignment.align_dependency_source_mappings(
                str(mismatch_report), [f"com.example:dep={other_repo}"], catalog
            )
            self.assertEqual(mismatch["mappings"], [])
            self.assertEqual(mismatch["records"][0]["reason_code"], "dependency_source_repo_mismatch")

            escape_report = Path(tmp) / "escape-report"
            evidence_path = self._write_ref_evidence(escape_report, repo)
            payload = json.loads(evidence_path.read_text(encoding="utf-8"))
            payload["matched_items"][0]["meta"]["module_rel_path"] = "../../outside"
            evidence_path.write_text(json.dumps(payload), encoding="utf-8")
            escaping = alignment.align_dependency_source_mappings(
                str(escape_report), [f"com.example:dep={repo}"], catalog
            )
            self.assertEqual(escaping["mappings"], [])
            self.assertEqual(
                escaping["records"][0]["reason_code"],
                "dependency_source_module_path_escapes_snapshot",
            )


if __name__ == "__main__":
    unittest.main()
