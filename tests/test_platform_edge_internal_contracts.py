from __future__ import annotations

import ctypes
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_performance_gate
import binary_pipeline
import compat
import database_contract_scan
import final_artifact_edge_oracle
import path_runtime
import remote_source_refs


class WindowsCheckpointContractTest(unittest.TestCase):
    def test_posix_checkpoint_leaf_cleanup_is_idempotent(self):
        with patch.object(binary_pipeline.os, "unlink") as unlink:
            binary_pipeline._unlink_checkpoint_name_missing_ok("owned.tmp", 17)
            unlink.assert_called_once_with("owned.tmp", dir_fd=17)

        with patch.object(
            binary_pipeline.os, "unlink", side_effect=FileNotFoundError,
        ) as unlink:
            binary_pipeline._unlink_checkpoint_name_missing_ok("missing.tmp", 23)
            unlink.assert_called_once_with("missing.tmp", dir_fd=23)

    def test_windows_checkpoint_writer_replaces_atomically_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            destination = parent / "resume.json"
            destination.write_text("old", encoding="utf-8")
            with patch.object(binary_pipeline, "fsync_directory") as fsync:
                result = binary_pipeline._write_resume_checkpoint_windows_compat(
                    destination, '{"state":"new"}\n',
                )
            self.assertEqual(result, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"state":"new"}\n')
            self.assertEqual(list(parent.glob(".resume.json.*.tmp")), [])
            fsync.assert_called_once_with(parent)

            other = parent / "observation.txt"
            self.assertEqual(
                binary_pipeline._write_observability_text_windows_compat(
                    other, "observation", durable=False,
                ),
                other,
            )
            self.assertEqual(other.read_text(encoding="utf-8"), "observation")

    def test_windows_checkpoint_delete_is_idempotent_and_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "resume.json"
            checkpoint.write_text("{}", encoding="utf-8")
            with patch.object(binary_pipeline, "fsync_directory") as fsync:
                self.assertTrue(
                    binary_pipeline._delete_resume_checkpoint_windows_compat(checkpoint)
                )
            fsync.assert_called_once_with(checkpoint.parent)
            self.assertFalse(
                binary_pipeline._delete_resume_checkpoint_windows_compat(checkpoint)
            )


class WindowsProcessContractTest(unittest.TestCase):
    @staticmethod
    def _kernel(wait_result=0x00000102, handle=123):
        return SimpleNamespace(
            OpenProcess=MagicMock(return_value=handle),
            WaitForSingleObject=MagicMock(return_value=wait_result),
            CloseHandle=MagicMock(return_value=1),
        )

    def test_path_runtime_windows_process_probe_closes_every_open_handle(self):
        kernel = self._kernel()
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertTrue(path_runtime._windows_process_is_alive(99))
        kernel.CloseHandle.assert_called_once_with(123)

        kernel = self._kernel(wait_result=0)
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertFalse(path_runtime._windows_process_is_alive(99))
        kernel.CloseHandle.assert_called_once_with(123)

        kernel = self._kernel(handle=0)
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True), patch.object(
            ctypes, "get_last_error", return_value=87, create=True,
        ):
            self.assertFalse(path_runtime._windows_process_is_alive(99))
        kernel.CloseHandle.assert_not_called()

        kernel = self._kernel(handle=0)
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True), patch.object(
            ctypes, "get_last_error", return_value=5, create=True,
        ):
            self.assertTrue(path_runtime._windows_process_is_alive(99))
        kernel.CloseHandle.assert_not_called()

    def test_generic_process_probe_dispatches_to_native_windows_probe(self):
        kernel = self._kernel()
        with patch.object(path_runtime, "IS_WINDOWS", True), patch.object(
            ctypes, "WinDLL", return_value=kernel, create=True,
        ):
            self.assertTrue(path_runtime._process_is_alive(99))
        kernel.OpenProcess.assert_called_once()
        kernel.CloseHandle.assert_called_once_with(123)

    def test_streaming_command_timeout_terminates_tree_only_once(self):
        process = SimpleNamespace(
            stdout=BytesIO(b"partial stdout\n"),
            stderr=BytesIO(b"partial stderr\n"),
            stdin=None,
            returncode=None,
        )
        process.wait = MagicMock(
            side_effect=subprocess.TimeoutExpired(["tool"], 0.01),
        )
        terminated = MagicMock()
        with patch.object(compat, "resolve_command", side_effect=lambda value: value), patch.object(
            compat, "managed_foreground_process_kwargs", return_value={},
        ), patch.object(compat, "managed_popen", return_value=process), patch.object(
            compat, "_terminate_subprocess", terminated,
        ), patch.object(compat.sys, "stderr", StringIO()):
            stdout, stderr, rc = compat.run_cmd(
                ["tool"], timeout=0.01, stream_output=True,
            )
        self.assertEqual(stdout, "")
        self.assertIn("命令超时", stderr)
        self.assertEqual(rc, -1)
        terminated.assert_called_once_with(process, process_group=True)


class RemoteRefMatchingContractTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.inventory = {
            "queried_at": "now",
            "remotes": ["origin", "upstream"],
            "failures": [],
            "refs": [
                {
                    "remote": "origin", "ref": "origin/release-1.2.3",
                    "canonical_ref": "refs/heads/release-1.2.3",
                    "short_name": "release-1.2.3", "kind": "branch", "commit": self.commit,
                },
                {
                    "remote": "upstream", "ref": "upstream/v1.2.3",
                    "canonical_ref": "refs/tags/v1.2.3",
                    "short_name": "v1.2.3", "kind": "tag", "commit": self.commit,
                },
            ],
        }

    def test_version_boundary_does_not_match_version_substrings(self):
        self.assertEqual(remote_source_refs._version_boundary_score("release-1.2.3", "1.2.3"), 120)
        self.assertEqual(remote_source_refs._version_boundary_score("release-11.2.3", "1.2.3"), 0)
        self.assertEqual(remote_source_refs._version_boundary_score("release-1.2.30", "1.2.3"), 0)
        self.assertEqual(remote_source_refs._version_boundary_score("release", "not-version"), 0)

    def test_remote_matching_respects_explicit_remote_and_highest_score(self):
        matches = remote_source_refs._matching_remote_candidates(
            self.inventory, "origin/release-1.2.3",
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["remote"], "origin")
        self.assertEqual(matches[0]["score"], 240)
        self.assertEqual(remote_source_refs._matching_remote_candidates(self.inventory, ""), [])

    def test_version_match_deduplicates_aliases_by_commit_and_reports_failures(self):
        with patch.object(remote_source_refs, "query_live_remote_refs", return_value=self.inventory):
            result = remote_source_refs.match_remote_refs_by_version("/repo", "1.2.3")
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(len(result["candidates"][0]["aliases"]), 2)

        failed_inventory = {**self.inventory, "refs": [], "failures": [{"reason": "network"}]}
        with patch.object(remote_source_refs, "query_live_remote_refs", return_value=failed_inventory):
            self.assertEqual(
                remote_source_refs.match_remote_refs_by_version("/repo", "1.2.3")["status"],
                "query_failed",
            )
        self.assertEqual(
            remote_source_refs.match_remote_refs_by_version("/repo", "")["status"],
            "version_missing",
        )

    def test_compat_advertised_inventory_binds_only_requested_commit(self):
        other = "b" * 40
        stdout = (
            f"{self.commit}\trefs/heads/release\n"
            f"{other}\trefs/heads/other\n"
            f"{self.commit}\trefs/tags/v1.2.3\n"
            f"{self.commit}\trefs/tags/v1.2.3^{{}}\n"
        )
        with patch.object(remote_source_refs, "_git", return_value=(stdout, "", 0)):
            result = remote_source_refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit[:12], retry_attempts=1,
            )
        self.assertEqual(result["failures"], [])
        self.assertEqual({item["short_name"] for item in result["refs"]}, {"release", "v1.2.3"})
        self.assertTrue(all(item["commit"] == self.commit for item in result["refs"]))

        with patch.object(
            remote_source_refs, "_git", return_value=("", "repository not found", 128),
        ):
            failed = remote_source_refs._compat_advertised_commit_inventory(
                "/repo", "origin", self.commit, retry_attempts=1,
            )
        self.assertEqual(failed["refs"], [])
        self.assertEqual(len(failed["failures"]), 1)


class FinalArtifactJavapAdapterContractTest(unittest.TestCase):
    def setUp(self):
        self.entries = [
            final_artifact_edge_oracle.PackagedClass(
                artifact_entry=f"BOOT-INF/classes/p/C{index}.class",
                extracted_path=Path(f"/tmp/C{index}.class"),
            )
            for index in range(2)
        ]
        self.result = {
            "rows": [{"edge": "one"}], "failures": [],
            "completed": True, "parsed": True,
        }

    def test_legacy_entry_adapter_accumulates_rows_and_failures(self):
        with patch.object(
            final_artifact_edge_oracle, "_parse_entry_with_javap",
            side_effect=[self.result, {**self.result, "rows": [], "failures": ["bad"]}],
        ):
            rows, failures = final_artifact_edge_oracle._parse_entries_with_javap(
                self.entries, "sha", "javap", "17",
            )
        self.assertEqual(rows, [{"edge": "one"}])
        self.assertEqual(failures, ["bad"])

    def test_group_parser_falls_back_individually_on_materialization_error(self):
        with patch.object(
            final_artifact_edge_oracle, "_materialize_packaged_class", return_value="cannot stage",
        ), patch.object(
            final_artifact_edge_oracle, "_parse_entry_with_javap", return_value=self.result,
        ) as parse:
            results = final_artifact_edge_oracle._parse_entry_group_with_javap(
                self.entries, "sha", "javap", "17", threading.Event(), None,
                force_verbose=False,
            )
        self.assertEqual(results, [self.result, self.result])
        self.assertEqual(parse.call_count, 2)

    def test_group_parser_bisects_failed_batch_before_individual_parse(self):
        process = SimpleNamespace(returncode=1)
        process.communicate = MagicMock(return_value=("", "bad batch"))
        with patch.object(
            final_artifact_edge_oracle, "_materialize_packaged_class", return_value="",
        ), patch.object(
            final_artifact_edge_oracle, "managed_popen", return_value=process,
        ), patch.object(
            final_artifact_edge_oracle, "release_process_tree",
        ), patch.object(
            final_artifact_edge_oracle, "_parse_entry_with_javap", return_value=self.result,
        ) as parse:
            results = final_artifact_edge_oracle._parse_entry_group_with_javap(
                self.entries, "sha", "javap", "17", threading.Event(), None,
                force_verbose=False,
            )
        self.assertEqual(results, [self.result, self.result])
        self.assertEqual(parse.call_count, 2)


class AuxiliaryEntrypointContractTest(unittest.TestCase):
    def test_database_hash_and_cli_delegate_to_scanner(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bytes"
            path.write_bytes(b"abc")
            self.assertEqual(
                database_contract_scan._sha256_path(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
        argv = [
            "database_contract_scan.py", "--report-dir", "report",
            "--output-dir", "out", "--jdk-home", "jdk",
        ]
        stdout = StringIO()
        with patch.object(sys, "argv", argv), patch.object(
            sys, "stdout", stdout,
        ), patch.object(
            database_contract_scan, "scan_database_contracts", return_value={"coverage_status": "complete"},
        ) as scan:
            self.assertIsNone(database_contract_scan.main())
        scan.assert_called_once_with("report", "out", jdk_home="jdk")
        self.assertEqual(json.loads(stdout.getvalue())["coverage_status"], "complete")

    def test_legacy_javap_probe_counts_classes_and_surfaces_tool_failure(self):
        artifacts = [{"first_class_index": 0, "path": "a.jar"}]
        completed = SimpleNamespace(returncode=0, stderr=b"")
        with patch.object(binary_performance_gate, "run_managed_subprocess", return_value=completed), patch.object(
            binary_performance_gate, "_timing_metrics", return_value={"wall_seconds": 1.0},
        ), patch.object(binary_performance_gate, "_rss_bytes", return_value=42):
            result = binary_performance_gate._legacy_javap(artifacts, 3)
        self.assertEqual(result["class_count"], 3)
        self.assertEqual(result["peak_rss_bytes"], 42)

        failed = SimpleNamespace(returncode=1, stderr=b"javap failed")
        with patch.object(binary_performance_gate, "run_managed_subprocess", return_value=failed):
            with self.assertRaises(binary_performance_gate.PerformanceGateError):
                binary_performance_gate._legacy_javap(artifacts, 1)


if __name__ == "__main__":
    unittest.main()
