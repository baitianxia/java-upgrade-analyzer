import hashlib
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_pipeline import (  # noqa: E402
    BinaryPipelineError,
    _ArtifactDigestSession,
    _PhaseTimingRecorder,
    _artifact_descriptors,
    _artifact_instances,
)


class BinaryPipelineInputPerformanceTest(unittest.TestCase):
    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _artifacts(inner_paths: list[Path], outer: Path, outer_sha: str):
        return [
            {
                "path": str(path),
                "outer_artifact_path": str(outer),
                "outer_artifact_sha256": outer_sha,
                "container_entry": f"BOOT-INF/lib/{path.name}",
                "logical_location": f"dependencies/{index:05d}-{path.name}",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": index,
                "coord": f"example:dependency-{index}:1",
                "lineage": f"example:dependency-{index}",
                "runtime_code_source_origin_identity": (
                    f"sha256:{outer_sha}#BOOT-INF/lib/{path.name}"
                ),
            }
            for index, path in enumerate(inner_paths)
        ]

    def test_shared_outer_container_is_hashed_twice_not_once_per_entry(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            outer = root / "application.jar"
            outer.write_bytes(b"outer-container" * 100)
            inner_paths = [root / "first.jar", root / "second.jar"]
            for index, path in enumerate(inner_paths):
                path.write_bytes(f"nested-{index}".encode("utf-8"))
            outer_sha = self._sha256(outer)
            raw = self._artifacts(inner_paths, outer, outer_sha)
            session = _ArtifactDigestSession()

            base, _base_paths = _artifact_descriptors(
                raw, digest_session=session
            )
            current, _current_paths = _artifact_descriptors(
                raw, digest_session=session
            )
            base_instances = _artifact_instances(
                base,
                SimpleNamespace(identity="base-runtime-profile"),
                digest_session=session,
            )
            current_instances = _artifact_instances(
                current,
                SimpleNamespace(identity="current-runtime-profile"),
                digest_session=session,
            )
            session.revalidate_marked()

        metrics = session.metrics()
        self.assertEqual(metrics["artifact_hash_request_count"], 8)
        # Two unique nested JARs, then the shared outer JAR at the beginning and
        # end of the profile phase. The old implementation read the outer once
        # for every one of the four ArtifactInstances.
        self.assertEqual(metrics["artifact_hash_execution_count"], 4)
        self.assertEqual(metrics["artifact_hash_reuse_count"], 5)
        self.assertEqual(metrics["outer_artifact_unique_count"], 1)
        self.assertEqual(
            metrics["outer_artifact_final_verification_hash_count"], 1
        )
        self.assertTrue(all(
            instance.outer_artifact_sha256 == outer_sha
            for _raw, instance in (*base_instances, *current_instances)
        ))

    def test_declared_outer_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            outer = root / "application.jar"
            inner = root / "dependency.jar"
            outer.write_bytes(b"outer")
            inner.write_bytes(b"inner")
            raw = self._artifacts([inner], outer, "0" * 64)
            artifacts, _paths = _artifact_descriptors(raw)

            with self.assertRaises(BinaryPipelineError) as raised:
                _artifact_instances(
                    artifacts, SimpleNamespace(identity="runtime-profile")
                )

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_ARTIFACT_SHA256_MISMATCH",
        )

    def test_outer_container_change_before_final_verification_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            outer = root / "application.jar"
            outer.write_bytes(b"before")
            session = _ArtifactDigestSession()
            session.digest(outer, revalidate_at_end=True)
            outer.write_bytes(b"after")

            with self.assertRaises(BinaryPipelineError) as raised:
                session.revalidate_marked()

        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_PIPELINE_OUTER_ARTIFACT_CHANGED_DURING_PROFILE",
        )

    def test_phase_metrics_have_portable_zeroes_without_resource_module(self):
        with tempfile.TemporaryDirectory() as temp_text, patch(
            "binary_pipeline._resource_usage_snapshot", return_value=None
        ):
            recorder = _PhaseTimingRecorder(Path(temp_text), 0.0)
            recorder.append({"phase": "portable", "elapsed_seconds": 1.0})

        self.assertEqual(recorder[0]["peak_rss_bytes"], 0)
        self.assertEqual(recorder[0]["completed_child_peak_rss_bytes"], 0)
        self.assertEqual(recorder[0]["process_tree_cpu_seconds"], 0.0)
        self.assertEqual(recorder[0]["average_cpu_cores"], 0.0)


if __name__ == "__main__":
    unittest.main()
