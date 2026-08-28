import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_platform_image as platform_image  # noqa: E402
from binary_platform_image import (  # noqa: E402
    JdkPlatformImage,
    PlatformClassFact,
    PlatformImageError,
    _PlatformClassLocation,
)


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


def create_modular_jdk(root: Path, modules=None) -> Path:
    home = root / "jdk17"
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "java").write_bytes(b"synthetic-java-17-launcher")
    (home / "lib").mkdir()
    (home / "lib" / "modules").write_bytes(b"module-image")
    (home / "jmods").mkdir()
    (home / "release").write_text(
        'JAVA_VERSION="17.0.10"\nIMPLEMENTOR="Fixture JDK"\n',
        encoding="utf-8",
    )
    modules = modules or {
        "java.base": {
            "classes/java/lang/Object.class": b"object",
            "classes/module-info.class": b"module-info",
        }
    }
    for module_name, entries in modules.items():
        write_archive(home / "jmods" / f"{module_name}.jmod", entries)
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


class BinaryPlatformImageBoundaryTest(unittest.TestCase):
    def test_release_less_jdk_metadata_is_bound_and_probe_errors_are_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = create_jdk8(Path(tmp))
            (home / "release").unlink()
            fallback = {
                "values": {
                    "JAVA_VERSION": "1.8.0_504",
                    "IMPLEMENTOR": "Fixture Vendor",
                    "OS_ARCH": "fixture-arch",
                },
                "source": "java-properties-probe",
                "identity": "a" * 64,
            }
            with patch.object(
                platform_image, "resolve_jdk_release", return_value=fallback
            ):
                image = JdkPlatformImage(home)
            self.assertEqual(image.java_major, 8)
            self.assertEqual(
                image.release_metadata_source, "java-properties-probe"
            )

            failures = (
                platform_image.JdkPreflightError("PROBE_FAILED", "probe failed"),
                OSError("metadata unreadable"),
            )
            for failure in failures:
                with self.subTest(failure=type(failure).__name__), patch.object(
                    platform_image,
                    "resolve_jdk_release",
                    side_effect=failure,
                ), self.assertRaises(PlatformImageError) as raised:
                    JdkPlatformImage(home)
                self.assertEqual(
                    raised.exception.reason_code,
                    "PLATFORM_JDK_METADATA_INVALID",
                )
                self.assertIs(raised.exception.__cause__, failure)

    def test_release_and_version_parsing_cover_valid_and_invalid_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "release"
            release.write_text(
                ' JAVA_VERSION = "21.0.2"\nIGNORED\nEMPTY=\n',
                encoding="utf-8",
            )
            self.assertEqual(
                platform_image._parse_release(release),
                {"JAVA_VERSION": "21.0.2", "EMPTY": ""},
            )
        for value, expected in (
            ("1.8.0_402", 8),
            ("8u402", 8),
            ("17.0.10", 17),
            (21, 21),
        ):
            with self.subTest(value=value):
                self.assertEqual(platform_image._java_major(value), expected)
        for value in (None, "", "1", "1.", "invalid"):
            with self.subTest(value=value), self.assertRaises(
                PlatformImageError
            ) as raised:
                platform_image._java_major(value)
            self.assertEqual(
                raised.exception.reason_code, "PLATFORM_JAVA_VERSION_INVALID"
            )

    def test_constructor_failures_distinguish_required_runtime_and_module_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing"
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(missing)
            self.assertEqual(raised.exception.reason_code, "PLATFORM_IMAGE_FILE_MISSING")

            unsupported = root / "jdk7"
            (unsupported / "bin").mkdir(parents=True)
            (unsupported / "bin" / "java").write_bytes(b"java")
            (unsupported / "release").write_text(
                'JAVA_VERSION="1.7.0"\n', encoding="utf-8"
            )
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(unsupported)
            self.assertEqual(
                raised.exception.reason_code, "PLATFORM_JAVA_VERSION_UNSUPPORTED"
            )

            no_modules = create_modular_jdk(root / "no-modules")
            (no_modules / "lib" / "modules").unlink()
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(no_modules)
            self.assertEqual(raised.exception.reason_code, "PLATFORM_IMAGE_FILE_MISSING")

            no_jmods = create_modular_jdk(root / "no-jmods")
            for path in (no_jmods / "jmods").iterdir():
                path.unlink()
            (no_jmods / "jmods").rmdir()
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(no_jmods)
            self.assertEqual(raised.exception.reason_code, "PLATFORM_JMODS_MISSING")

    def test_minimal_jdk8_without_optional_archives_or_classes_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "jdk8"
            (home / "bin").mkdir(parents=True)
            (home / "bin" / "java").write_bytes(b"java")
            (home / "release").write_text(
                'JAVA_VERSION="1.8.0_402"\n', encoding="utf-8"
            )
            write_archive(home / "jre" / "lib" / "rt.jar", {})

            image = JdkPlatformImage(home)
            self.assertEqual(image.legacy_extension_archives, ())
            self.assertIsNone(image.legacy_classes_dir)
            self.assertEqual(image.class_names(), frozenset())
            self.assertEqual(image.module_exports(), {})

    def test_jdk8_optional_archive_filter_and_directory_classes_are_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = create_jdk8(Path(tmp))
            extension = home / "jre" / "lib" / "ext"
            (extension / "not-a-jar.txt").write_bytes(b"ignored")
            (extension / "directory.jar").mkdir()
            write_archive(extension / "upper.JAR", {
                "fixture/upper/Api.class": b"upper",
            })
            classes = home / "jre" / "classes" / "loose"
            classes.mkdir(parents=True)
            (classes / "Direct.class").write_bytes(b"direct")
            image = JdkPlatformImage(home)

            names = image.class_names()
            module_name, content = image._read_class("loose/Direct")

        self.assertIn("fixture/upper/Api", names)
        self.assertIn("loose/Direct", names)
        self.assertEqual(module_name, "jdk8-bootstrap")
        self.assertEqual(content, b"direct")

    def test_index_filters_nonclasses_metadata_and_reuses_cached_index(self):
        modules = {
            "java.base": {
                "classes/java/lang/Object.class": b"object",
                "classes/module-info.class": b"module",
                "classes/META-INF/versions/9/Hidden.class": b"hidden",
                "classes/readme.txt": b"text",
                "native/Native.class": b"native",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            image = JdkPlatformImage(create_modular_jdk(Path(tmp), modules))
            self.assertEqual(image.class_names(), frozenset({"java/lang/Object"}))
            cached = image._class_index
            with patch.object(platform_image.zipfile, "ZipFile") as opener:
                image._build_index()
            opener.assert_not_called()
            self.assertIs(image._class_index, cached)

    def test_duplicate_and_corrupt_archives_fail_with_platform_specific_taxonomy(self):
        duplicate_modules = {
            "first": {"classes/shared/Type.class": b"one"},
            "second": {"classes/shared/Type.class": b"two"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = JdkPlatformImage(create_modular_jdk(root / "duplicate", duplicate_modules))
            with self.assertRaises(PlatformImageError) as raised:
                image.class_names()
            self.assertEqual(raised.exception.reason_code, "PLATFORM_CLASS_DUPLICATE")

            modern = create_modular_jdk(root / "corrupt-modern")
            (modern / "jmods" / "java.base.jmod").write_bytes(b"not a zip")
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(modern).class_names()
            self.assertEqual(raised.exception.reason_code, "PLATFORM_JMOD_INVALID")

            legacy = create_jdk8(root / "corrupt-legacy")
            (legacy / "jre" / "lib" / "rt.jar").write_bytes(b"not a zip")
            with self.assertRaises(PlatformImageError) as raised:
                JdkPlatformImage(legacy).class_names()
            self.assertEqual(raised.exception.reason_code, "PLATFORM_ARCHIVE_INVALID")

    def test_duplicate_between_archive_and_loose_class_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = create_jdk8(Path(tmp))
            loose = home / "jre" / "classes" / "java" / "lang"
            loose.mkdir(parents=True)
            (loose / "Object.class").write_bytes(b"duplicate")
            image = JdkPlatformImage(home)
            with self.assertRaises(PlatformImageError) as raised:
                image.class_names()
        self.assertEqual(raised.exception.reason_code, "PLATFORM_CLASS_DUPLICATE")

    def test_read_class_covers_missing_archive_file_and_read_failures(self):
        image = object.__new__(JdkPlatformImage)
        image._class_index = {}
        image._build_index = Mock()
        self.assertIsNone(image._read_class("missing/Type"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct = root / "Direct.class"
            direct.write_bytes(b"direct")
            archive = root / "classes.jar"
            write_archive(archive, {"inside/Type.class": b"inside"})
            image._class_index = {
                "direct/Type": _PlatformClassLocation("direct", direct, None),
                "inside/Type": _PlatformClassLocation(
                    "archive", archive, "inside/Type.class"
                ),
            }
            self.assertEqual(
                image._read_class("direct/Type"), ("direct", b"direct")
            )
            self.assertEqual(
                image._read_class("inside/Type"), ("archive", b"inside")
            )
            direct.unlink()
            with self.assertRaises(PlatformImageError) as raised:
                image._read_class("direct/Type")
            self.assertEqual(
                raised.exception.reason_code, "PLATFORM_CLASS_READ_FAILED"
            )
            image._class_index["inside/Type"] = _PlatformClassLocation(
                "archive", archive, "missing.class"
            )
            with self.assertRaises(PlatformImageError):
                image._read_class("inside/Type")

    @staticmethod
    def _blank_image():
        image = object.__new__(JdkPlatformImage)
        image.identity = "platform-id"
        image.asm_jar = None
        image.jdk_home = Path("/jdk")
        image._facts = {}
        image._failures = {}
        image.parser_identity = ""
        return image

    def test_ensure_classes_handles_missing_failure_binding_and_dependency_closure(self):
        image = self._blank_image()
        content = {
            "demo/Root": ("module.root", b"root"),
            "demo/Super": ("module.root", b"super"),
            "demo/Api": ("module.api", b"api"),
        }
        image._read_class = Mock(side_effect=lambda name: content.get(name))
        runs = 0

        def extract(inputs, **_kwargs):
            nonlocal runs
            runs += 1
            names = [item.class_entry.removeprefix("classes/").removesuffix(".class") for item in inputs]
            records = []
            for name in names:
                if name == "demo/Root":
                    records.append({
                        "frame_type": "class_fact",
                        "class_name": name,
                        "class_bytes_sha256": "a" * 64,
                        "super_name": "demo/Super",
                        "interfaces": ["demo/Api", "demo/Missing"],
                    })
                else:
                    records.append({
                        "frame_type": "class_fact",
                        "class_name": name,
                        "class_bytes_sha256": "b" * 64,
                        "super_name": "",
                        "interfaces": [],
                    })
            return SimpleNamespace(parser_identity=f"parser-{runs}", records=records)

        with patch.object(
            platform_image, "extract_class_facts", side_effect=extract
        ) as extractor:
            facts = image.ensure_classes(
                (None, "", "  ", " demo.Root ", "demo/Root")
            )
            cached = image.ensure_classes(("demo.Root", "demo.Missing"))

        self.assertEqual(set(facts), {"demo/Root", "demo/Super", "demo/Api"})
        self.assertEqual(set(cached), {"demo/Root"})
        self.assertEqual(
            image._failures["demo/Missing"]["failure_kind"],
            "platform_class_missing",
        )
        self.assertEqual(image.parser_identity, "parser-2")
        self.assertTrue(all(
            call.kwargs["persistent_session"]
            for call in extractor.call_args_list
        ))

        all_missing = self._blank_image()
        all_missing._read_class = Mock(return_value=None)
        with patch.object(platform_image, "extract_class_facts") as extractor:
            self.assertEqual(all_missing.ensure_classes(("missing.Type",)), {})
        extractor.assert_not_called()
        self.assertIn("missing/Type", all_missing._failures)

        image = self._blank_image()
        image._read_class = Mock(return_value=("module", b"content"))
        failure_records = (
            {"frame_type": "class_failure", "class_entry": "classes/demo/Bad.class"},
            {"frame_type": "class_failure", "class_entry": None},
            {
                "frame_type": "class_fact",
                "class_name": "demo/Unbound",
                "class_bytes_sha256": "c" * 64,
            },
        )
        with patch.object(
            platform_image,
            "extract_class_facts",
            return_value=SimpleNamespace(
                parser_identity="parser", records=failure_records
            ),
        ):
            result = image.ensure_classes(("demo/Bad",))
        self.assertEqual(result, {})
        self.assertIn("demo/Bad", image._failures)
        self.assertIn("", image._failures)
        self.assertEqual(
            image._failures["demo/Unbound"]["failure_kind"],
            "platform_module_binding_missing",
        )

    def test_get_class_failure_and_manifest_normalize_names_and_empty_state(self):
        image = self._blank_image()
        fact = PlatformClassFact("demo/Type", "module", "variant", "a" * 64, {})
        image._facts["demo/Type"] = fact
        image._failures[""] = {"failure_kind": "empty"}
        image.ensure_classes = Mock()
        self.assertIs(image.get_class("demo.Type"), fact)
        self.assertIsNone(image.get_class(None))
        self.assertEqual(image.failure(None), {"failure_kind": "empty"})
        image.ensure_classes.assert_not_called()

        image.get_class("demo.Missing")
        image.ensure_classes.assert_called_once_with(("demo/Missing",))
        image.ensure_classes.reset_mock()
        self.assertIsNone(image.failure("demo.Unknown"))
        image.ensure_classes.assert_called_once_with(("demo/Unknown",))
        image.ensure_classes.reset_mock()
        self.assertIsNone(image.failure("demo.Type"))
        image.ensure_classes.assert_not_called()

        image._build_index = Mock()
        image._class_index = None
        image.release = {}
        image.java_major = 17
        image.platform_image_format = "jimage-jmods"
        image.module_image_sha256 = "module-id"
        manifest = image.manifest()
        self.assertEqual(manifest["indexed_class_count"], 0)
        self.assertIsNone(manifest["java_version"])

    def test_jdk8_and_modular_exports_cover_directive_and_failure_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy = JdkPlatformImage(create_jdk8(Path(tmp) / "legacy"))
            first = legacy.module_exports()
            self.assertIs(legacy.module_exports(), first)

            modules = {
                "good": {"classes/module-info.class": b"good"},
                "fallback": {"classes/module-info.class": b"fallback"},
                "broken": {"classes/not-module.class": b"x"},
            }
            modern = JdkPlatformImage(
                create_modular_jdk(Path(tmp) / "modern", modules)
            )
            records = (
                {
                    "class_entry": "good/module-info.class",
                    "module": {
                        "name": "named.good",
                        "directives": [
                            None,
                            ["requires", "java.base"],
                            ["exports", "too-short"],
                            ["exports", "qualified", None, ["friend"]],
                            ["exports", "public/pkg", None, []],
                        ],
                    },
                },
                {
                    "class_entry": "fallback/module-info.class",
                    "module": {"directives": [["exports", "fallback/pkg", None, None]]},
                },
                {"class_entry": "unknown", "module": {}},
            )
            with patch.object(
                platform_image,
                "extract_class_facts",
                return_value=SimpleNamespace(
                    parser_identity="parser-exports", records=records
                ),
            ) as extractor:
                exports = modern.module_exports()
                cached = modern.module_exports()

        self.assertEqual(exports["named.good"], frozenset({"public/pkg"}))
        self.assertEqual(exports["fallback"], frozenset({"fallback/pkg"}))
        self.assertNotIn("", exports)
        self.assertIs(cached, exports)
        self.assertEqual(modern.parser_identity, "parser-exports")
        extractor.assert_called_once()
        self.assertTrue(extractor.call_args.kwargs["persistent_session"])

    def test_modular_exports_without_readable_descriptors_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            modules = {"broken": {"classes/Type.class": b"type"}}
            image = JdkPlatformImage(create_modular_jdk(Path(tmp), modules))
            with patch.object(platform_image, "extract_class_facts") as extractor:
                self.assertEqual(image.module_exports(), {})
            extractor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
