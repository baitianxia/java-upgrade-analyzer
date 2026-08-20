import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import zipfile
import json


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_snapshot_cache  # noqa: E402
from binary_snapshot_cache import (  # noqa: E402
    SnapshotTemplateMemo,
    cached_snapshot_archive,
)


class BinarySnapshotCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("javac"):
            raise unittest.SkipTest("javac required")
        cls.asm_jar = binary_asm_helper.resolve_asm_jar()

    def test_cache_json_bytes_preserve_unpaired_surrogate_without_collision(self):
        raw_surrogate = json.loads('"\\ud800"')
        raw_payload = binary_snapshot_cache._json_bytes({"value": raw_surrogate})
        literal_payload = binary_snapshot_cache._json_bytes({"value": "\\ud800"})

        self.assertNotEqual(raw_payload, literal_payload)
        self.assertEqual(
            json.loads(raw_payload.decode("utf-8")),
            {"value": raw_surrogate},
        )

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
            memo = SnapshotTemplateMemo()
            first = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-one",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
                template_memo=memo,
            )
            second = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-two",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
                template_memo=memo,
            )
            memo.clear()
            disk_rebound = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="instance-two",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
                template_memo=memo,
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
        self.assertEqual(second.cache_tier, "memory")
        self.assertEqual(disk_rebound.cache_tier, "disk")
        self.assertEqual(second.snapshot, disk_rebound.snapshot)
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
        self.assertIs(
            first.snapshot.class_payloads[0][1],
            second.snapshot.class_payloads[0][1],
        )

    def test_cold_miss_relies_on_snapshot_before_and_after_hashes(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            artifact = root / "empty.jar"
            with zipfile.ZipFile(artifact, "w"):
                pass
            expected = binary_artifact_diff._sha256_file(artifact)
            cache = root / "cache"

            # A cold miss must not perform the cache layer's former third full
            # file hash. snapshot_archive still performs independent before and
            # after hashes and rejects changes at either boundary.
            with patch.object(
                binary_snapshot_cache,
                "_sha256_file",
                side_effect=AssertionError("redundant cold-cache hash"),
            ):
                cold = cached_snapshot_archive(
                    artifact,
                    artifact_instance_identity="cold",
                    expected_sha256=expected,
                    cache_root=cache,
                    asm_jar=self.asm_jar,
                )

            verifier = binary_snapshot_cache._sha256_file
            with patch.object(
                binary_snapshot_cache, "_sha256_file", wraps=verifier
            ) as verified_hash:
                warm = cached_snapshot_archive(
                    artifact,
                    artifact_instance_identity="warm",
                    expected_sha256=expected,
                    cache_root=cache,
                    asm_jar=self.asm_jar,
                )

        self.assertEqual(cold.cache_status, "miss")
        self.assertEqual(warm.cache_status, "hit")
        self.assertEqual(warm.cache_tier, "disk")
        self.assertEqual(verified_hash.call_count, 1)

    def test_target_jvm_major_is_part_of_multi_release_cache_identity(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            base_source = root / "base" / "demo" / "A.java"
            version_source = root / "version" / "demo" / "A.java"
            base_source.parent.mkdir(parents=True)
            version_source.parent.mkdir(parents=True)
            base_source.write_text(
                "package demo; public class A { public int value(){ return 8; } }",
                encoding="utf-8",
            )
            version_source.write_text(
                "package demo; public class A { public int value(){ return 21; } }",
                encoding="utf-8",
            )
            base_classes = root / "base-classes"
            version_classes = root / "version-classes"
            base_classes.mkdir()
            version_classes.mkdir()
            for source, classes in (
                (base_source, base_classes), (version_source, version_classes)
            ):
                subprocess.run(
                    ["javac", "-g:none", "-d", str(classes), str(source)],
                    check=True, capture_output=True,
                )
            artifact = root / "mr.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nMulti-Release: true\n\n",
                )
                archive.write(base_classes / "demo" / "A.class", "demo/A.class")
                archive.write(
                    version_classes / "demo" / "A.class",
                    "META-INF/versions/21/demo/A.class",
                )
                archive.writestr("config/application.properties", "mode=base\n")
                archive.writestr(
                    "META-INF/versions/21/config/application.properties",
                    "mode=versioned\n",
                )
            sha = binary_artifact_diff._sha256_file(artifact)
            cache = root / "cache"
            jdk8 = cached_snapshot_archive(
                artifact, artifact_instance_identity="jdk8", expected_sha256=sha,
                cache_root=cache, asm_jar=self.asm_jar, target_jvm_major=8,
            )
            jdk21 = cached_snapshot_archive(
                artifact, artifact_instance_identity="jdk21", expected_sha256=sha,
                cache_root=cache, asm_jar=self.asm_jar, target_jvm_major=21,
            )
            jdk21_repeat = cached_snapshot_archive(
                artifact, artifact_instance_identity="jdk21-repeat",
                expected_sha256=sha, cache_root=cache, asm_jar=self.asm_jar,
                target_jvm_major=21,
            )

        self.assertEqual(jdk8.cache_status, "miss")
        self.assertEqual(jdk21.cache_status, "miss")
        self.assertEqual(jdk21_repeat.cache_status, "hit")
        self.assertNotEqual(jdk8.cache_key, jdk21.cache_key)
        self.assertEqual(
            jdk8.snapshot.class_records[0]["class_entry"],
            "demo/A.class#occurrence=0",
        )
        self.assertEqual(
            jdk21.snapshot.class_records[0]["class_entry"],
            "META-INF/versions/21/demo/A.class#occurrence=0",
        )
        selected_jdk8 = next(
            item for item in jdk8.snapshot.entries
            if item.kind == "resource"
            and item.logical_resource_entry == "config/application.properties"
            and item.runtime_effective
        )
        selected_jdk21 = next(
            item for item in jdk21.snapshot.entries
            if item.kind == "resource"
            and item.logical_resource_entry == "config/application.properties"
            and item.runtime_effective
        )
        selected_jdk21_repeat = next(
            item for item in jdk21_repeat.snapshot.entries
            if item.kind == "resource"
            and item.logical_resource_entry == "config/application.properties"
            and item.runtime_effective
        )
        self.assertEqual(selected_jdk8.name, "config/application.properties")
        self.assertEqual(
            selected_jdk21.name,
            "META-INF/versions/21/config/application.properties",
        )
        self.assertEqual(
            selected_jdk21_repeat.logical_resource_entry,
            selected_jdk21.logical_resource_entry,
        )
        self.assertEqual(
            selected_jdk21_repeat.content_sha256,
            selected_jdk21.content_sha256,
        )
        self.assertEqual(
            selected_jdk21_repeat.runtime_effective,
            selected_jdk21.runtime_effective,
        )

    def test_snapshot_semantics_policy_change_invalidates_warm_disk_cache(self):
        with tempfile.TemporaryDirectory() as temp_text:
            root = Path(temp_text)
            artifact = root / "resource.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("config/runtime.xml", "<beans/>")
            sha = binary_artifact_diff._sha256_file(artifact)
            cache = root / "cache"
            current_policy = binary_snapshot_cache.CACHE_POLICY_VERSION
            with patch.object(
                binary_snapshot_cache,
                "CACHE_POLICY_VERSION",
                "artifact-content-parser-target-release-safety-rebind-v3",
            ):
                legacy = cached_snapshot_archive(
                    artifact,
                    artifact_instance_identity="legacy",
                    expected_sha256=sha,
                    cache_root=cache,
                    asm_jar=self.asm_jar,
                )
            current = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="current",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
            )
            repeat = cached_snapshot_archive(
                artifact,
                artifact_instance_identity="repeat",
                expected_sha256=sha,
                cache_root=cache,
                asm_jar=self.asm_jar,
            )

        self.assertEqual(
            current_policy,
            "artifact-content-parser-target-release-safety-rebind-v5",
        )
        self.assertEqual(legacy.cache_status, "miss")
        self.assertEqual(current.cache_status, "miss")
        self.assertEqual(repeat.cache_status, "hit")
        self.assertNotEqual(legacy.cache_key, current.cache_key)


if __name__ == "__main__":
    unittest.main()
