import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s1_dep_diff  # noqa: E402
import s2_context_from_deps  # noqa: E402
import s3_scan  # noqa: E402
import s4_jar_compare  # noqa: E402
import s5_call_chain_engine_integrated  # noqa: E402


class OrchestratedStepInputTest(unittest.TestCase):
    def _write_main_state(self, report_dir, payload):
        state = {"step1": {"input": {}}, "step2": {"input": {}}, "step3": {"input": {}}, "step4": {"input": {}}, "step5": {"input": {}}}
        state.update(payload)
        state_dir = report_dir / ".runtime" / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        (state_dir / "main_state.json").write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

    def test_step1_reads_orchestrated_input_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            self._write_main_state(report_dir, {"step1": {"input": {"base_branch": "main", "modules": ["app"]}}})
            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": str(report_dir)}, clear=False):
                loaded = s1_dep_diff.load_orchestrated_step1_input()
        self.assertEqual(loaded["base_branch"], "main")
        self.assertEqual(loaded["modules"], ["app"])

    def test_step2_reads_orchestrated_input_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            self._write_main_state(report_dir, {"step2": {"input": {"base_branch": "main", "current_branch": "feat", "source_dirs": ["src/main/java"]}}})
            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": str(report_dir)}, clear=False):
                loaded = s2_context_from_deps.load_orchestrated_step2_input(str(report_dir / "s2_context.json"))
        self.assertEqual(loaded["base_branch"], "main")
        self.assertEqual(loaded["current_branch"], "feat")
        self.assertEqual(loaded["source_dirs"], ["src/main/java"])

    def test_step3_reads_orchestrated_input_and_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            self._write_main_state(report_dir, {"step3": {"input": {"source_dirs": ["src/main/java"], "include_test_scope": True}}})
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True, exist_ok=True)
            (context_dir / "context.json").write_text(
                json.dumps({"jdk_upgraded": True, "springboot_major_upgrade": True, "jdk_current": "17"}, ensure_ascii=False),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}, clear=False):
                loaded_input, loaded_context = s3_scan.load_orchestrated_step3_input(str(report_dir))
        self.assertEqual(loaded_input["source_dirs"], ["src/main/java"])
        self.assertTrue(loaded_input["include_test_scope"])
        self.assertTrue(loaded_context["jdk_upgraded"])
        self.assertEqual(loaded_context["jdk_current"], "17")

    def test_step4_reads_orchestrated_input_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            self._write_main_state(
                report_dir,
                {"step4": {"input": {"dependency_repo_mappings": ["com.example:demo=/repo"], "step4_git_diff_timeout": 600}}},
            )
            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1", "UPGRADE_REPORT_DIR": str(report_dir)}, clear=False):
                loaded = s4_jar_compare.load_orchestrated_step4_input(str(report_dir / "evidence" / "api_changes"))
        self.assertEqual(loaded["dependency_repo_mappings"], ["com.example:demo=/repo"])
        self.assertEqual(loaded["step4_git_diff_timeout"], 600)

    def test_step5_reads_orchestrated_input_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            self._write_main_state(
                report_dir,
                {"step5": {"input": {"source_dirs": ["src/main/java"], "max_depth": 5, "allow_degraded": True}}},
            )
            with patch.dict(os.environ, {"JUA_ORCHESTRATED": "1"}, clear=False):
                loaded = s5_call_chain_engine_integrated.load_orchestrated_step5_input(str(report_dir))
        self.assertEqual(loaded["source_dirs"], ["src/main/java"])
        self.assertEqual(loaded["max_depth"], 5)
        self.assertTrue(loaded["allow_degraded"])


if __name__ == "__main__":
    unittest.main()
