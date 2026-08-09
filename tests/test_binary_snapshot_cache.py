import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
from binary_snapshot_cache import cached_snapshot_archive  # noqa: E402


class BinarySnapshotCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("javac"):
            raise unittest.SkipTest("javac required")
        cls.asm_jar = binary_asm_helper.resolve_asm_jar()

    def test_content_cache_rebinds_instance_and_rebuilds_corruption(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            source = root / "src" / "demo" / "A.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class A { public int value(){ return 1; } }",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-g", "-d", str(classes), str(source)],
                check=True,
                capture_output=True,
            )
            artifact = root / "a.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.write(classes / "demo" / "A.class", "demo/A.class")
            sha = binary_artifact_diff._sha256_file(artifact)
            cache = root / "cache"
            first = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-one",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
            )
            second = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-two",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
            )
            cache_file = next(cache.rglob("*.json.zlib"))
            cache_file.write_bytes(b"corrupt")
            rebuilt = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-three",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(first.cache_status, "miss")
        self.assertEqual(first.parser_invocation_count, 1)
        self.assertEqual(second.cache_status, "hit")
        self.assertEqual(second.parser_invocation_count, 0)
        self.assertEqual(rebuilt.cache_status, "corrupt_rebuilt")
        self.assertEqual(rebuilt.parser_invocation_count, 1)
        self.assertEqual(
            second.snapshot.class_records[0]["artifact_instance_identity"],
            "instance-two",
        )
        self.assertNotEqual(
            first.snapshot.entries[0].physical_entry_identity,
            second.snapshot.entries[0].physical_entry_identity,
        )
        self.assertEqual(
            first.snapshot.class_records[0]["class_bytes_sha256"],
            second.snapshot.class_records[0]["class_bytes_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
