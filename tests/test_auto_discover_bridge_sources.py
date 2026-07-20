import sys
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import auto_discover_bridge_sources as bridges  # noqa: E402


class AutoDiscoverBridgeSourcesTest(unittest.TestCase):
    def test_iter_repo_modules_does_not_resolve_every_walked_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".git").mkdir()
            for branch in range(8):
                current = repo / f"branch-{branch}"
                for depth in range(20):
                    current = current / f"depth-{depth}"
                    current.mkdir(parents=True, exist_ok=True)

            original_resolve = Path.resolve
            resolve_calls = []

            def counted_resolve(path, *args, **kwargs):
                resolve_calls.append(str(path))
                return original_resolve(path, *args, **kwargs)

            with patch.object(Path, "resolve", counted_resolve):
                modules = list(bridges._iter_repo_modules(str(repo)))

        self.assertEqual(modules, [])
        self.assertLess(
            len(resolve_calls),
            20,
            f"bridge repository walk performed {len(resolve_calls)} realpath resolutions",
        )

    def test_load_source_mapping_inputs_reads_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            state_dir = report_dir / ".runtime" / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            (state_dir / "main_state.json").write_text(
                json.dumps(
                    {
                        "state": {"current_step": "step5"},
                        "step5": {
                            "input": {
                                "dependency_source_dirs": ["/tmp/repo-a"],
                            }
                        },
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            inputs = bridges.load_source_mapping_inputs(report_dir)

        self.assertEqual(
            inputs["dependency_source_dirs"],
            [str(Path("/tmp/repo-a").resolve())],
        )

    def test_update_main_state_dependency_source_dirs_writes_back_to_current_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            state_dir = report_dir / ".runtime" / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            (state_dir / "main_state.json").write_text(
                json.dumps(
                    {
                        "state": {"current_step": "step4"},
                        "step4": {"input": {"dependency_repo_mappings": ["com.example:demo=/tmp/old"]}},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            bridges.update_main_state_dependency_source_dirs(report_dir, ["/tmp/repo-b"])
            updated = json.loads((state_dir / "main_state.json").read_text(encoding="utf-8"))

        self.assertEqual(
            updated["step4"]["input"]["dependency_source_dirs"],
            ["/tmp/repo-b"],
        )
        self.assertNotIn("dependency_repo_mappings", updated["step4"]["input"])

    def test_discover_bridge_source_mappings_infers_gradle_submodule_group_from_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module = repo / "spring-core"
            module.mkdir(parents=True)
            (module / "build.gradle").write_text('description = "Spring Core"\n', encoding="utf-8")
            source_dir = module / "src/main/java/org/springframework/core"
            source_dir.mkdir(parents=True)
            (source_dir / "Core.java").write_text(
                "\n".join(
                    [
                        "package org.springframework.core;",
                        "public class Core {}",
                    ]
                ),
                encoding="utf-8",
            )

            mappings = bridges.discover_bridge_source_mappings("", str(repo))

        self.assertIn(
            ("org.springframework:spring-core", str((module / "src/main/java").resolve())),
            mappings,
        )

    def test_discover_bridge_source_mappings_does_not_bind_root_coord_to_child_module_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build.gradle").write_text('group = "org.springframework.boot"\n', encoding="utf-8")

            boot_module = repo / "core/spring-boot"
            (boot_module / "build.gradle").parent.mkdir(parents=True)
            (boot_module / "build.gradle").write_text('description = "Spring Boot"\n', encoding="utf-8")
            boot_source = boot_module / "src/main/java/org/springframework/boot"
            boot_source.mkdir(parents=True)
            (boot_source / "SpringBoot.java").write_text(
                "\n".join(
                    [
                        "package org.springframework.boot;",
                        "public class SpringBoot {}",
                    ]
                ),
                encoding="utf-8",
            )

            autoconfigure_module = repo / "core/spring-boot-autoconfigure"
            (autoconfigure_module / "build.gradle").parent.mkdir(parents=True)
            (autoconfigure_module / "build.gradle").write_text(
                'description = "Spring Boot AutoConfigure"\n',
                encoding="utf-8",
            )
            autoconfigure_source = (
                autoconfigure_module
                / "src/main/java/org/springframework/boot/autoconfigure/condition"
            )
            autoconfigure_source.mkdir(parents=True)
            (autoconfigure_source / "Condition.java").write_text(
                "\n".join(
                    [
                        "package org.springframework.boot.autoconfigure.condition;",
                        "public class Condition {}",
                    ]
                ),
                encoding="utf-8",
            )

            mappings = bridges.discover_bridge_source_mappings("", str(repo))

        self.assertIn(
            ("org.springframework.boot:spring-boot", str((boot_module / "src/main/java").resolve())),
            mappings,
        )
        self.assertIn(
            (
                "org.springframework.boot:spring-boot-autoconfigure",
                str((autoconfigure_module / "src/main/java").resolve()),
            ),
            mappings,
        )
        self.assertNotIn(
            (
                "org.springframework.boot:spring-boot",
                str((autoconfigure_module / "src/main/java").resolve()),
            ),
            mappings,
        )

    def test_discover_bridge_source_mappings_supports_named_gradle_module_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            core_dir = repo / "core"
            core_dir.mkdir(parents=True)
            (core_dir / "spring-security-core.gradle").write_text(
                "description = 'Core'\n",
                encoding="utf-8",
            )
            core_source = core_dir / "src/main/java/org/springframework/security/core"
            core_source.mkdir(parents=True)
            (core_source / "Core.java").write_text(
                "package org.springframework.security.core;\npublic class Core {}\n",
                encoding="utf-8",
            )

            mappings = bridges.discover_bridge_source_mappings("", str(repo))

        self.assertIn(
            (
                "org.springframework.security:spring-security-core",
                str((core_dir / "src/main/java").resolve()),
            ),
            mappings,
        )

    def test_discover_bridge_source_mappings_ignores_task_group_assignment_when_inferring_group_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            web_dir = repo / "web"
            web_dir.mkdir(parents=True)
            (web_dir / "spring-security-web.gradle").write_text(
                "\n".join(
                    [
                        "tasks.register('syncJavascript') {",
                        "    group = 'Build'",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            web_source = web_dir / "src/main/java/org/springframework/security/web"
            web_source.mkdir(parents=True)
            (web_source / "Web.java").write_text(
                "package org.springframework.security.web;\npublic class Web {}\n",
                encoding="utf-8",
            )

            mappings = bridges.discover_bridge_source_mappings("", str(repo))

        self.assertIn(
            (
                "org.springframework.security:spring-security-web",
                str((web_dir / "src/main/java").resolve()),
            ),
            mappings,
        )

    def test_iter_repo_modules_prioritizes_main_modules_before_test_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "build.gradle").write_text('group = "org.springframework.boot"\n', encoding="utf-8")

            boot_dir = repo / "spring-boot-project" / "spring-boot"
            boot_dir.mkdir(parents=True)
            (boot_dir / "build.gradle").write_text("description = 'Spring Boot'\n", encoding="utf-8")
            (boot_dir / "src/main/java/org/springframework/boot").mkdir(parents=True)

            auto_dir = repo / "spring-boot-project" / "spring-boot-autoconfigure"
            auto_dir.mkdir(parents=True)
            (auto_dir / "build.gradle").write_text(
                "description = 'Spring Boot AutoConfigure'\n",
                encoding="utf-8",
            )
            (auto_dir / "src/main/java/org/springframework/boot/autoconfigure").mkdir(parents=True)

            for index in range(20):
                smoke_dir = repo / "spring-boot-tests" / "spring-boot-smoke-tests" / f"spring-boot-smoke-test-{index:02d}"
                smoke_dir.mkdir(parents=True)
                (smoke_dir / "build.gradle").write_text(
                    f"description = 'Smoke {index}'\n",
                    encoding="utf-8",
                )
                (smoke_dir / "src/main/java/com/example").mkdir(parents=True)

            modules = list(bridges._iter_repo_modules(str(repo), max_manifests=2))
            coords = [coord for coord, _root in modules]

        self.assertEqual(
            coords,
            [
                "org.springframework.boot:spring-boot",
                "org.springframework.boot:spring-boot-autoconfigure",
            ],
        )


if __name__ == "__main__":
    unittest.main()
