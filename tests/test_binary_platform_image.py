import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_platform_image import JdkPlatformImage, PlatformImageError  # noqa: E402


def write_archive(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def create_jdk8(root: Path) -> Path:
    home = root / "jdk8"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "java").write_bytes(b"synthetic-java-8-launcher")
    (home / "release").write_text(
        'JAVA_VERSION="1.8.0_402"\n'
        'IMPLEMENTOR="Fixture JDK"\n'
        'OS_ARCH="fixture-arch"\n',
        encoding="utf-8",
    )
    write_archive(home / "jre" / "lib" / "rt.jar", {
        "java/lang/Object.class": b"object-class",
        "java/util/List.class": b"list-class",
        "META-INF/versions/9/ignored/Type.class": b"ignored",
    })
    write_archive(home / "jre" / "lib" / "ext" / "fixture-ext.jar", {
        "fixture/ext/Api.class": b"extension-class",
    })
    return home


class BinaryPlatformImageTest(unittest.TestCase):
    def test_jdk8_archives_are_content_bound_indexed_and_exported(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = create_jdk8(Path(temporary))
            image = JdkPlatformImage(home)

            self.assertEqual(image.java_major, 8)
            self.assertEqual(image.platform_image_format, "jdk8-classpath")
            self.assertEqual(len(image.module_image_sha256), 64)
            self.assertEqual(
                image.class_names(),
                frozenset({"java/lang/Object", "java/util/List", "fixture/ext/Api"}),
            )
            module_name, content = image._read_class("fixture/ext/Api")
            self.assertEqual(module_name, "jdk8-extension.fixture-ext")
            self.assertEqual(content, b"extension-class")
            self.assertIn("java/lang", image.module_exports()["jdk8-bootstrap"])
            self.assertIn("fixture/ext", image.module_exports()[module_name])
            self.assertEqual(
                image.manifest()["platform_image_format"], "jdk8-classpath"
            )

    def test_jdk8_identity_is_path_independent_and_changes_with_archive_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = JdkPlatformImage(create_jdk8(root / "first"))
            second_home = create_jdk8(root / "second")
            second = JdkPlatformImage(second_home)
            self.assertEqual(first.identity, second.identity)

            write_archive(second_home / "jre" / "lib" / "ext" / "fixture-ext.jar", {
                "fixture/ext/Api.class": b"changed-extension-class",
            })
            changed = JdkPlatformImage(second_home)
            self.assertNotEqual(first.identity, changed.identity)

    def test_jdk8_requires_the_runtime_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "jdk8"
            (home / "bin").mkdir(parents=True)
            (home / "bin" / "java").write_bytes(b"java")
            (home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(home)
            self.assertEqual(
                raised.exception.reason_code, "PLATFORM_IMAGE_FILE_MISSING"
            )


if __name__ == "__main__":
    unittest.main()
