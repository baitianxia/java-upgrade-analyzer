import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "runtime_dispatch_v1.json"
).read_text(encoding="utf-8"))
SOURCE_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "source_overlay_v1.json"
).read_text(encoding="utf-8"))


def execute(command: list[str], *, cwd: Path | None = None, expected: int = 0):
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
    )
    if completed.returncode != expected:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout={completed.stdout[-3000:]}\nstderr={completed.stderr[-3000:]}"
        )
    return completed


def jdk_home(java: str) -> Path:
    completed = subprocess.run(
        [java, "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            candidate = Path(line.split("=", 1)[1].strip()).resolve()
            if (candidate / "jmods").is_dir():
                return candidate
    raise AssertionError("full JDK home required")


def compile_jar(
    root: Path,
    label: str,
    sources: dict[str, str],
    javac: str,
    *,
    classpath: tuple[Path, ...] = (),
) -> Path:
    source_root = root / label / "src"
    source_paths = []
    for relative, content in sources.items():
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.strip() + "\n", encoding="utf-8")
        source_paths.append(path)
    classes = root / label / "classes"
    classes.mkdir(parents=True)
    command = [javac, "-g:none", "-encoding", "UTF-8"]
    if classpath:
        command.extend(["-classpath", os.pathsep.join(map(str, classpath))])
    execute([*command, "-d", str(classes), *map(str, source_paths)])
    jar = root / label / f"{label}.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted(classes.rglob("*.class")):
            archive.write(class_file, class_file.relative_to(classes).as_posix())
    return jar


def runtime_profile(entrypoint: tuple[str, str, str]) -> dict:
    return {
        "container_and_launcher_kind": "java-classpath",
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [
                {
                    "identity": "platform-loader", "kind": "platform",
                    "delegation": "parent_first", "module_mode": "named-platform",
                },
                {
                    "identity": "application-loader", "kind": "application",
                    "parent": "platform-loader", "delegation": "parent_first",
                    "module_mode": "unnamed",
                },
            ],
        },
        "runtime_security_and_package_sealing_policy_identity": (
            "standard-unsealed-unsigned-v1"
        ),
        "active_profile_identities": ["default"],
        "external_config_snapshot_identities": [],
        "agent_transformer_plugin_profile_identities": [],
        "business_entrypoint_profile": {
            "coverage_status": "complete",
            "methods": [{
                "initiating_loader_realm_identity": "application-loader",
                "class_name": entrypoint[0],
                "member_name": entrypoint[1],
                "descriptor": entrypoint[2],
            }],
        },
        "runtime_class_closure_coverage_status": "complete",
        "resource_selection_coverage_status": "complete",
    }


def side(
    home: Path, business: Path, dependency: Path, version: str,
    entrypoint: tuple[str, str, str],
) -> dict:
    return {
        "jdk_home": str(home),
        "artifacts": [
            {
                "path": str(business), "logical_location": "app/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "blackbox:business:1",
                "lineage": "blackbox:business",
                "runtime_code_source_origin_identity": "runtime-dispatch-business",
            },
            {
                "path": str(dependency), "logical_location": "lib/dependency.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"blackbox:runtime-api:{version}",
                "lineage": "blackbox:runtime-api",
                "runtime_code_source_origin_identity": "runtime-dispatch-api",
            },
        ],
        "runtime_profile": runtime_profile(entrypoint),
    }


def public_pipeline(root: Path, config: dict) -> tuple[dict, dict, dict]:
    root.mkdir(parents=True, exist_ok=True)
    config_path = root / "config.json"
    result_path = root / "result.json"
    output = root / "output"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    completed = execute([
        sys.executable, str(ROOT / "scripts" / "binary_pipeline.py"),
        "--config", str(config_path), "--output-root", str(output),
        "--result-json", str(result_path),
    ], cwd=ROOT)
    result = json.loads(completed.stdout)
    if result != json.loads(result_path.read_text(encoding="utf-8")):
        raise AssertionError("stdout and result-json differ")
    generation = Path(result["generation_directory"])
    formal = json.loads((generation / "binary_formal_results.json").read_text())
    overlay = json.loads((
        generation / "binary_runtime_semantic_overlay.json"
    ).read_text())
    return result, formal, overlay


class PublicRuntimeDispatchBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which("java") or ""
        cls.javac = shutil.which("javac") or ""
        cls.javap = shutil.which("javap") or ""
        if not all((cls.java, cls.javac, cls.javap)):
            raise AssertionError("OpenJDK java, javac, and javap are required")
        cls.home = jdk_home(cls.java)

    def assert_case(
        self,
        root: Path,
        name: str,
        base: Path,
        current: Path,
        business: Path,
        entrypoint: tuple[str, str, str],
        oracle_main: str,
        bytecode_tokens: tuple[str, ...],
    ) -> None:
        truth = TRUTH["cases"][name]
        classpath_base = os.pathsep.join((str(business), str(base)))
        classpath_current = os.pathsep.join((str(business), str(current)))
        base_run = execute([self.java, "-cp", classpath_base, oracle_main])
        current_run = execute([self.java, "-cp", classpath_current, oracle_main])
        self.assertEqual(base_run.stdout, truth["expected_base_stdout"])
        self.assertEqual(current_run.stdout, truth["expected_current_stdout"])

        bytecode = execute([
            self.javap, "-classpath", str(business), "-c", "-p", entrypoint[0]
        ]).stdout
        for token in bytecode_tokens:
            self.assertIn(token, bytecode)

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "base": side(self.home, business, base, "1", entrypoint),
            "current": side(self.home, business, current, "2", entrypoint),
            "runtime_comparison": {
                "comparison_intent": "same_deployment_profile",
                "profile_correspondence_policy_version": "v1",
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
                "changed_or_unknown_profile_fields": [],
            },
        }
        result, formal, overlay = public_pipeline(root / f"run-{name}", config)
        self.assertEqual(result["validation_status"], "passed")
        target_identity = tuple(truth["target"])
        target_rows = [
            item for item in formal["by_api"]
            if (
                item.get("display_owner"), item.get("display_member"),
                item.get("display_descriptor"), item.get("display_member_kind"),
            ) == target_identity
        ]
        self.assertEqual(len(target_rows), 1, formal["by_api"])
        target = target_rows[0]
        for field, value in TRUTH["expected_state"].items():
            self.assertEqual(target[field], value, (name, field, target))
        semantic_rows = [
            row for row in overlay["rows"]
            if row["semantic_edge_kind"] == truth["semantic_edge_kind"]
        ]
        self.assertTrue(semantic_rows, overlay["rows"])
        self.assertTrue(all(row["path_certainty"] == "exact" for row in semantic_rows))

    def test_reflection_and_method_handle_dispatch_match_real_jvm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 2; } }"
                ),
            }, self.javac)
            reflection = compile_jar(root, "reflection", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public int run() throws Exception {
                            Class<?> type = Class.forName("lib.Target");
                            java.lang.reflect.Method method =
                                type.getDeclaredMethod("changed");
                            Object target = type.getDeclaredConstructor().newInstance();
                            return ((Integer) method.invoke(target)).intValue();
                        }
                        public static void main(String[] args) throws Exception {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac)
            self.assert_case(
                root, "reflection", base, current, reflection,
                ("biz/Entry", "run", "()I"), "biz.Entry",
                ("Class.forName", "Class.getDeclaredMethod", "Method.invoke"),
            )

            method_handle = compile_jar(root, "method-handle", {
                "biz/HandleEntry.java": """
                    package biz;
                    public class HandleEntry {
                        public int run() throws Throwable {
                            java.lang.invoke.MethodHandle handle =
                                java.lang.invoke.MethodHandles.lookup().findVirtual(
                                    lib.Target.class, "changed",
                                    java.lang.invoke.MethodType.methodType(int.class));
                            return (int) handle.invokeExact(new lib.Target());
                        }
                        public static void main(String[] args) throws Throwable {
                            System.out.print(new HandleEntry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            self.assert_case(
                root, "method_handle", base, current, method_handle,
                ("biz/HandleEntry", "run", "()I"), "biz.HandleEntry",
                ("MethodHandles.lookup", "MethodHandles$Lookup.findVirtual"),
            )

    def test_dynamic_proxy_dispatch_matches_real_jvm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "proxy-base", {
                "api/Api.java": (
                    "package api; public class Api { public int value() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "proxy-current", {
                "api/Api.java": (
                    "package api; public class Api { public int value() { return 2; } }"
                ),
            }, self.javac)
            business = compile_jar(root, "proxy-business", {
                "biz/Action.java": "package biz; public interface Action { int run(); }",
                "biz/Handler.java": """
                    package biz;
                    public class Handler implements java.lang.reflect.InvocationHandler {
                        public Object invoke(
                            Object proxy, java.lang.reflect.Method method, Object[] args
                        ) { return Integer.valueOf(new api.Api().value()); }
                    }
                """,
                "biz/ProxyEntry.java": """
                    package biz;
                    public class ProxyEntry {
                        public int run() {
                            Action action = (Action) java.lang.reflect.Proxy.newProxyInstance(
                                Action.class.getClassLoader(),
                                new Class<?>[]{Action.class}, new Handler());
                            return action.run();
                        }
                        public static void main(String[] args) {
                            System.out.print(new ProxyEntry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            self.assert_case(
                root, "dynamic_proxy", base, current, business,
                ("biz/ProxyEntry", "run", "()I"), "biz.ProxyEntry",
                ("Proxy.newProxyInstance", "biz/Action.run"),
            )

    def test_invokedynamic_lambda_handle_is_never_reported_not_found(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "lambda-base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "lambda-current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 2; } }"
                ),
            }, self.javac)
            business = compile_jar(root, "lambda-business", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public int run() {
                            java.util.function.IntSupplier supplier =
                                new lib.Target()::changed;
                            return supplier.getAsInt();
                        }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            truth = TRUTH["cases"]["invokedynamic_lambda"]
            base_run = execute([
                self.java, "-cp", os.pathsep.join((str(business), str(base))),
                "biz.Entry",
            ])
            current_run = execute([
                self.java, "-cp", os.pathsep.join((str(business), str(current))),
                "biz.Entry",
            ])
            self.assertEqual(base_run.stdout, truth["expected_base_stdout"])
            self.assertEqual(current_run.stdout, truth["expected_current_stdout"])

            bytecode = execute([
                self.javap, "-classpath", str(business), "-c", "-v", "biz.Entry",
            ]).stdout
            for token in truth["javap_tokens"]:
                self.assertIn(token, bytecode)

            entrypoint = ("biz/Entry", "run", "()I")
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": side(self.home, business, base, "1", entrypoint),
                "current": side(self.home, business, current, "2", entrypoint),
                "runtime_comparison": {
                    "comparison_intent": "same_deployment_profile",
                    "profile_correspondence_policy_version": "v1",
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                    "changed_or_unknown_profile_fields": [],
                },
            }
            result, formal, _overlay = public_pipeline(root / "run-lambda", config)
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertEqual(
                sorted(
                    (path["path_certainty"], path["path_text"])
                    for path in target["paths"]
                ),
                sorted(tuple(path) for path in truth["expected_paths"]),
            )
            self.assertTrue(all(
                path["mechanism_kinds"][-1] == "invokedynamic_handle"
                for path in target["paths"]
            ))

    def test_source_presence_absence_mismatch_and_non_authority_are_public(self):
        truth = SOURCE_TRUTH
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "source-base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "source-current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 2; } }"
                ),
            }, self.javac)
            business = compile_jar(root, "source-business", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public int run() { return new lib.Target().changed(); }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            for dependency, expected in (
                (base, truth["expected_base_stdout"]),
                (current, truth["expected_current_stdout"]),
            ):
                observed = execute([
                    self.java, "-cp",
                    os.pathsep.join((str(business), str(dependency))),
                    "biz.Entry",
                ])
                self.assertEqual(observed.stdout, expected)
            javap = execute([
                self.javap, "-classpath", str(current), "-s", "-p", "lib.Target",
            ]).stdout
            self.assertIn(
                f"descriptor: {truth['expected_binary_descriptor']}", javap
            )

            dependency_source = root / "source-current" / "src" / "lib" / "Target.java"
            dependency_source.write_text(
                "package lib; public class Target { "
                "public int changed(long ignored) { return 99; } }\n",
                encoding="utf-8",
            )
            self.assertIn("changed(long", dependency_source.read_text(encoding="utf-8"))
            entrypoint = ("biz/Entry", "run", "()I")
            common = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": side(self.home, business, base, "1", entrypoint),
                "current": side(self.home, business, current, "2", entrypoint),
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            with_source = {
                **common,
                "source_usage": {
                    "decision": "use_source", "decision_source": "explicit_config",
                },
                "source_inputs": {
                    "business": {"status": "available", "origin": "provided"},
                    "dependencies": {"status": "available", "origin": "provided"},
                },
                "source_overlay": {
                    "source_sets": [
                        {
                            "source_dirs": [str(root / "source-business" / "src")],
                            "source_root": str(root / "source-business" / "src"),
                            "owner_type": "business",
                            "owner_coord": "blackbox:business:1",
                            "module": "business",
                        },
                        {
                            "source_dirs": [str(root / "source-current" / "src")],
                            "source_root": str(root / "source-current" / "src"),
                            "owner_type": "dependency",
                            "owner_coord": "blackbox:runtime-api:2",
                            "module": "runtime-api",
                        },
                    ],
                },
            }
            source_result, source_formal, _ = public_pipeline(
                root / "run-with-source", with_source
            )
            generation = Path(source_result["generation_directory"])
            coverage = json.loads((
                generation / "binary_coverage.json"
            ).read_text(encoding="utf-8"))
            explanations = json.loads((
                generation / "binary_source_explanations.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    key: source_result["source_inputs"][key]["status"]
                    for key in ("business", "dependencies")
                },
                truth["present_source_inputs"],
            )
            conflict = next(
                row for row in coverage["source_overlay"]["rows"]
                if row["binary_member"]["class_name"] == "lib/Target"
                and row["binary_member"]["member_name"] == "changed"
            )
            self.assertEqual(conflict["mapping_status"], "source_conflict")
            self.assertEqual(
                conflict["conflict"]["reason_code"],
                truth["conflict_reason_code"],
            )
            self.assertEqual(
                conflict["conflict"]["binary_descriptor"],
                truth["expected_binary_descriptor"],
            )
            self.assertEqual(
                conflict["conflict"]["source_descriptors"],
                [truth["mismatched_source_descriptor"]],
            )
            self.assertEqual(
                explanations["authority"], truth["explanation_authority"]
            )
            self.assertTrue(explanations["candidate_relationships"])
            self.assertTrue(all(
                row["authority"] == truth["candidate_authority"]
                for row in explanations["candidate_relationships"]
            ))

            without_source = {
                **common,
                "source_usage": {
                    "decision": "skip_source", "decision_source": "explicit_config",
                },
            }
            absent_result, absent_formal, _ = public_pipeline(
                root / "run-without-source", without_source
            )
            self.assertEqual(
                {
                    key: absent_result["source_inputs"][key]["status"]
                    for key in ("business", "dependencies")
                },
                truth["absent_source_inputs"],
            )
            absent_coverage = json.loads((
                Path(absent_result["generation_directory"])
                / "binary_coverage.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                absent_coverage["source_overlay"]["coverage_status"],
                "not_provided",
            )

            def target_projection(formal: dict) -> dict:
                row = next(
                    item for item in formal["by_api"]
                    if (
                        item["display_owner"], item["display_member"],
                        item["display_descriptor"], item["display_member_kind"],
                    ) == tuple(truth["target"])
                )
                return {
                    key: row[key] for key in (
                        "reachability_status", "static_linkage_status",
                        "impact_conclusion", "runtime_verification_status",
                        "exact_path_exists", "possible_path_exists",
                        "path_set_complete",
                    )
                } | {
                    "paths": sorted(
                        (path["path_certainty"], path["path_text"])
                        for path in row["paths"]
                    )
                }

            self.assertEqual(
                target_projection(source_formal),
                target_projection(absent_formal),
                "source overlay changed binary-authoritative public semantics",
            )

    def test_incomplete_entrypoint_inventory_yields_not_analyzed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "incomplete-base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "incomplete-current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 2; } }"
                ),
            }, self.javac)
            business = compile_jar(root, "incomplete-business", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public int run() { return 0; }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac)
            truth = TRUTH["cases"]["not_analyzed_incomplete_entrypoints"]
            for dependency in (base, current):
                observed = execute([
                    self.java, "-cp",
                    os.pathsep.join((str(business), str(dependency))),
                    "biz.Entry",
                ])
                self.assertEqual(observed.stdout, truth["expected_stdout"])
            bytecode = execute([
                self.javap, "-classpath", str(business), "-c", "-p", "biz.Entry",
            ]).stdout
            self.assertNotIn("lib/Target.changed", bytecode)

            entrypoint = ("biz/Entry", "run", "()I")
            base_side = side(self.home, business, base, "1", entrypoint)
            current_side = side(self.home, business, current, "2", entrypoint)
            for item in (base_side, current_side):
                item["runtime_profile"]["business_entrypoint_profile"][
                    "coverage_status"
                ] = "partial"
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": base_side,
                "current": current_side,
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            result, formal, _overlay = public_pipeline(
                root / "run-incomplete", config
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if row["display_owner"] == "lib/Target"
                and row["display_member"] == "changed"
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertTrue(any(
                "declared_entrypoint_coverage_incomplete"
                in row["trace_coverage_gaps"]
                for row in formal["results"]
                if row["reachability_status"] == "not_analyzed"
            ))

    def test_path_limit_reports_incomplete_set_instead_of_silent_truncation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "limit-base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 1; } }"
                ),
            }, self.javac)
            current = compile_jar(root, "limit-current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public int changed() { return 2; } }"
                ),
            }, self.javac)
            business = compile_jar(root, "limit-business", {
                "biz/RootA.java": (
                    "package biz; public class RootA { "
                    "public int run() { return new lib.Target().changed(); } }"
                ),
                "biz/RootB.java": (
                    "package biz; public class RootB { "
                    "public int run() { return new lib.Target().changed(); } }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "limit-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                        public static void main(String[] args) {
                            System.out.print(
                                new biz.RootA().run() + "" + new biz.RootB().run()
                            );
                        }
                    }
                """,
            }, self.javac, classpath=(business, base))
            truth = TRUTH["cases"]["path_enumeration_limit"]
            for dependency, expected in (
                (base, truth["expected_base_stdout"]),
                (current, truth["expected_current_stdout"]),
            ):
                observed = execute([
                    self.java, "-cp", os.pathsep.join((
                        str(oracle), str(business), str(dependency),
                    )), "oracle.Main",
                ])
                self.assertEqual(observed.stdout, expected)
            for class_name in ("biz.RootA", "biz.RootB"):
                bytecode = execute([
                    self.javap, "-classpath", str(business), "-c", class_name,
                ]).stdout
                self.assertIn("lib/Target.changed:()I", bytecode)

            entrypoints = [
                {
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": owner,
                    "member_name": "run",
                    "descriptor": "()I",
                }
                for owner in ("biz/RootA", "biz/RootB")
            ]
            base_side = side(
                self.home, business, base, "1", ("biz/RootA", "run", "()I")
            )
            current_side = side(
                self.home, business, current, "2", ("biz/RootA", "run", "()I")
            )
            for item in (base_side, current_side):
                item["runtime_profile"]["business_entrypoint_profile"][
                    "methods"
                ] = entrypoints
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": base_side,
                "current": current_side,
                "max_paths_per_target": 1,
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            result, formal, _overlay = public_pipeline(root / "run-limit", config)
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if row["display_owner"] == "lib/Target"
                and row["display_member"] == "changed"
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertEqual(len(target["paths"]), 1)
            observed_path = (
                target["paths"][0]["path_certainty"],
                target["paths"][0]["path_text"],
            )
            self.assertIn(
                observed_path,
                {tuple(path) for path in truth["allowed_single_paths"]},
            )
            self.assertTrue(any(
                "trace_path_enumeration_limit_exceeded"
                in row["trace_coverage_gaps"]
                for row in formal["results"]
            ))

    def test_javac_constant_inline_requires_changed_consumer_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_vendor = compile_jar(root, "constant-base", {
                "vendor/Constants.java": (
                    "package vendor; public class Constants { "
                    "public static final int VALUE = 11; }"
                ),
            }, self.javac)
            current_vendor = compile_jar(root, "constant-current", {
                "vendor/Constants.java": (
                    "package vendor; public class Constants { "
                    "public static final int VALUE = 29; }"
                ),
            }, self.javac)
            consumer_source = {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public int run() { return vendor.Constants.VALUE; }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }
            base_business = compile_jar(
                root, "constant-base-business", consumer_source, self.javac,
                classpath=(base_vendor,),
            )
            current_business = compile_jar(
                root, "constant-current-business", consumer_source, self.javac,
                classpath=(current_vendor,),
            )
            truth = TRUTH["cases"]["javac_constant_inline"]
            for business, dependency, expected in (
                (base_business, base_vendor, truth["expected_base_stdout"]),
                (
                    current_business, current_vendor,
                    truth["expected_rebuilt_current_stdout"],
                ),
                (
                    base_business, current_vendor,
                    truth["expected_retained_current_stdout"],
                ),
            ):
                observed = execute([
                    self.java, "-cp", os.pathsep.join((
                        str(business), str(dependency),
                    )), "biz.Entry",
                ])
                self.assertEqual(observed.stdout, expected)

            base_bytecode = execute([
                self.javap, "-classpath", str(base_business), "-c", "biz.Entry",
            ]).stdout
            current_bytecode = execute([
                self.javap, "-classpath", str(current_business), "-c", "biz.Entry",
            ]).stdout
            self.assertRegex(base_bytecode, r"\bbipush\s+11\b")
            self.assertRegex(current_bytecode, r"\bbipush\s+29\b")
            self.assertNotIn("vendor/Constants.VALUE", base_bytecode)
            self.assertNotIn("vendor/Constants.VALUE", current_bytecode)

            entrypoint = ("biz/Entry", "run", "()I")

            def analyze(label: str, current_consumer: Path):
                config = {
                    "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                    "source_usage": {
                        "decision": "use_source",
                        "decision_source": "explicit_config",
                    },
                    "base": side(
                        self.home, base_business, base_vendor, "1", entrypoint
                    ),
                    "current": side(
                        self.home, current_consumer, current_vendor, "2", entrypoint
                    ),
                    "runtime_comparison": {
                        "controlled_profile_fields": ["loader_topology"],
                        "declared_upgrade_payload_scope": ["artifact-bytes"],
                    },
                    "source_overlay": {
                        "source_sets": [{
                            "source_dirs": [str(
                                root / "constant-current-business" / "src"
                            )],
                            "source_root": str(
                                root / "constant-current-business" / "src"
                            ),
                            "owner_type": "business",
                            "owner_coord": "blackbox:business:1",
                        }],
                    },
                }
                result, formal, _overlay = public_pipeline(
                    root / f"run-{label}", config
                )
                target = next(
                    row for row in formal["by_api"]
                    if (
                        row["display_owner"], row["display_member"],
                        row["display_descriptor"], row["display_member_kind"],
                    ) == tuple(truth["target"])
                )
                inline = json.loads((
                    Path(result["generation_directory"])
                    / "binary_inline_overlay.json"
                ).read_text(encoding="utf-8"))
                return result, target, inline

            rebuilt_result, rebuilt_target, rebuilt_inline = analyze(
                "rebuilt", current_business
            )
            self.assertEqual(rebuilt_result["validation_status"], "passed")
            for field, value in truth["rebuilt_expected_state"].items():
                self.assertEqual(rebuilt_target[field], value, (field, rebuilt_target))
            self.assertEqual(rebuilt_inline["proven_count"], 1)
            proven = next(
                row for row in rebuilt_inline["rows"]
                if row["binding_certainty"] == "proven"
            )
            self.assertTrue(proven["bytecode_constant_transition_proven"])
            self.assertEqual(
                (proven["base_constant"], proven["current_constant"]), (11, 29)
            )

            retained_result, retained_target, retained_inline = analyze(
                "retained", base_business
            )
            self.assertEqual(retained_result["validation_status"], "passed")
            for field, value in truth["retained_expected_state"].items():
                self.assertEqual(
                    retained_target[field], value, (field, retained_target)
                )
            self.assertEqual(retained_inline["proven_count"], 0)
            self.assertTrue(all(
                row["binding_certainty"] == "none"
                and row["consumption_state"] == "retained_base_or_unchanged"
                for row in retained_inline["rows"]
            ))

    def test_bridge_synthetic_and_covariant_descriptors_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "bridge-base", {
                "lib/Generic.java": (
                    "package lib; public interface Generic<T> { T value(); }"
                ),
                "lib/Provider.java": """
                    package lib;
                    public class Provider implements Generic<String> {
                        public String value() { return "base"; }
                    }
                """,
            }, self.javac)
            current = compile_jar(root, "bridge-current", {
                "lib/Generic.java": (
                    "package lib; public interface Generic<T> { T value(); }"
                ),
                "lib/Provider.java": "package lib; public class Provider {}",
            }, self.javac)
            compiled_business = compile_jar(root, "bridge-business", {
                "biz/DirectEntry.java": """
                    package biz;
                    public class DirectEntry {
                        public String run() { return new lib.Provider().value(); }
                    }
                """,
                "biz/BridgeEntry.java": """
                    package biz;
                    public class BridgeEntry {
                        public Object run() { return new lib.Provider().value(); }
                    }
                """,
            }, self.javac, classpath=(base,))

            # javac cannot express a direct invokevirtual of a compiler bridge.
            # The two UTF-8 descriptors have equal byte length, so replacing
            # the sole call-site descriptor creates a valid, minimal classfile
            # without using any analyzer or bytecode-rewrite dependency.
            business = root / "bridge-business-patched.jar"
            old_descriptor = b"()Ljava/lang/String;"
            bridge_descriptor = b"()Ljava/lang/Object;"
            replacement_count = 0
            with zipfile.ZipFile(compiled_business) as source_archive:
                with zipfile.ZipFile(
                    business, "w", zipfile.ZIP_DEFLATED
                ) as target_archive:
                    for info in source_archive.infolist():
                        content = source_archive.read(info)
                        if info.filename == "biz/BridgeEntry.class":
                            replacement_count = content.count(old_descriptor)
                            content = content.replace(
                                old_descriptor, bridge_descriptor
                            )
                        target_archive.writestr(info.filename, content)
            self.assertEqual(replacement_count, 1)

            oracle = compile_jar(root, "bridge-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                        public static void main(String[] args) {
                            if (args[0].equals("direct")) {
                                System.out.print(new biz.DirectEntry().run());
                            } else {
                                System.out.print(new biz.BridgeEntry().run());
                            }
                        }
                    }
                """,
            }, self.javac, classpath=(business, base))
            truth = TRUTH["cases"]["bridge_covariant"]
            for mode in ("direct", "bridge"):
                base_run = execute([
                    self.java, "-cp", os.pathsep.join((
                        str(oracle), str(business), str(base),
                    )), "oracle.Main", mode,
                ])
                self.assertEqual(base_run.stdout, truth["expected_base_stdout"])
                current_run = execute([
                    self.java, "-cp", os.pathsep.join((
                        str(oracle), str(business), str(current),
                    )), "oracle.Main", mode,
                ], expected=1)
                diagnostic = current_run.stdout + current_run.stderr
                self.assertIn("NoSuchMethodError", diagnostic)
                self.assertIn(
                    truth["current_error_symbols"][mode], diagnostic
                )

            base_contract = execute([
                self.javap, "-classpath", str(base), "-public", "-s", "-v",
                "lib.Provider",
            ]).stdout
            current_contract = execute([
                self.javap, "-classpath", str(current), "-public", "-s",
                "lib.Provider",
            ]).stdout
            self.assertIn("ACC_BRIDGE", base_contract)
            self.assertIn("ACC_SYNTHETIC", base_contract)
            for descriptor in (
                "()Ljava/lang/String;", "()Ljava/lang/Object;",
            ):
                self.assertIn(f"descriptor: {descriptor}", base_contract)
                self.assertNotIn(f"descriptor: {descriptor}", current_contract)
            patched_call = execute([
                self.javap, "-classpath", str(business), "-c", "biz.BridgeEntry",
            ]).stdout
            self.assertIn(
                "lib/Provider.value:()Ljava/lang/Object;", patched_call
            )

            entrypoints = [
                {
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": owner,
                    "member_name": "run",
                    "descriptor": descriptor,
                }
                for owner, descriptor in (
                    ("biz/DirectEntry", "()Ljava/lang/String;"),
                    ("biz/BridgeEntry", "()Ljava/lang/Object;"),
                )
            ]
            base_side = side(
                self.home, business, base, "1",
                ("biz/DirectEntry", "run", "()Ljava/lang/String;"),
            )
            current_side = side(
                self.home, business, current, "2",
                ("biz/DirectEntry", "run", "()Ljava/lang/String;"),
            )
            for item in (base_side, current_side):
                item["runtime_profile"]["business_entrypoint_profile"][
                    "methods"
                ] = entrypoints
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": base_side,
                "current": current_side,
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            result, formal, _overlay = public_pipeline(root / "run-bridge", config)
            self.assertEqual(result["validation_status"], "passed")
            actual = {
                (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ): row
                for row in formal["by_api"]
            }
            expected_identities = {
                tuple(row["identity"]) for row in truth["expected_results"]
            }
            self.assertEqual(set(actual), expected_identities)
            for expected in truth["expected_results"]:
                row = actual[tuple(expected["identity"])]
                for field, value in expected["state"].items():
                    self.assertEqual(row[field], value, (field, row))
                self.assertEqual(
                    [
                        [path["path_certainty"], path["path_text"]]
                        for path in row["paths"]
                    ],
                    expected["paths"],
                )

    def test_override_removal_rebinds_to_inherited_method_without_linkage_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "override-base", {
                "lib/Parent.java": """
                    package lib;
                    public class Parent {
                        public String value() { return "parent"; }
                    }
                """,
                "lib/Child.java": """
                    package lib;
                    public class Child extends Parent {
                        public String value() { return "child"; }
                    }
                """,
            }, self.javac)
            current = compile_jar(root, "override-current", {
                "lib/Parent.java": """
                    package lib;
                    public class Parent {
                        public String value() { return "parent"; }
                    }
                """,
                "lib/Child.java": (
                    "package lib; public class Child extends Parent {}"
                ),
            }, self.javac)
            business = compile_jar(root, "override-business", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public String run() { return new lib.Child().value(); }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            truth = TRUTH["cases"]["override_removal_inherited_rebind"]
            for dependency, expected in (
                (base, truth["expected_base_stdout"]),
                (current, truth["expected_current_stdout"]),
            ):
                observed = execute([
                    self.java, "-cp", os.pathsep.join((
                        str(business), str(dependency),
                    )), "biz.Entry",
                ])
                self.assertEqual(observed.stdout, expected)
            bytecode = execute([
                self.javap, "-classpath", str(business), "-c", "biz.Entry",
            ]).stdout
            self.assertIn("lib/Child.value:()Ljava/lang/String;", bytecode)
            base_child = execute([
                self.javap, "-classpath", str(base), "-public", "-s", "lib.Child",
            ]).stdout
            current_child = execute([
                self.javap, "-classpath", str(current), "-public", "-s", "lib.Child",
            ]).stdout
            self.assertIn("descriptor: ()Ljava/lang/String;", base_child)
            self.assertNotIn("descriptor: ()Ljava/lang/String;", current_child)

            entrypoint = ("biz/Entry", "run", "()Ljava/lang/String;")
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": side(self.home, business, base, "1", entrypoint),
                "current": side(self.home, business, current, "2", entrypoint),
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            result, formal, _overlay = public_pipeline(
                root / "run-override", config
            )
            self.assertEqual(result["validation_status"], "passed")
            actual = {
                (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ): row
                for row in formal["by_api"]
            }
            target = actual[tuple(truth["target"])]
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertEqual(
                sorted(
                    [path["path_certainty"], path["path_text"]]
                    for path in target["paths"]
                ),
                sorted(truth["expected_paths"]),
            )
            self.assertNotIn(tuple(truth["forbidden_parent_result"]), actual)

    def test_superclass_replacement_exposes_lost_inherited_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "lib/ParentA.java": """
                    package lib;
                    public class ParentA {
                        public String legacy() { return "legacy"; }
                    }
                """,
                "lib/ParentB.java": """
                    package lib;
                    public class ParentB {
                        public String stable() { return "stable"; }
                    }
                """,
            }
            base = compile_jar(root, "super-base", {
                **common,
                "lib/Child.java": (
                    "package lib; public class Child extends ParentA {}"
                ),
            }, self.javac)
            current = compile_jar(root, "super-current", {
                **common,
                "lib/Child.java": (
                    "package lib; public class Child extends ParentB {}"
                ),
            }, self.javac)
            business = compile_jar(root, "super-business", {
                "biz/Entry.java": """
                    package biz;
                    public class Entry {
                        public String run() { return new lib.Child().legacy(); }
                        public static void main(String[] args) {
                            System.out.print(new Entry().run());
                        }
                    }
                """,
            }, self.javac, classpath=(base,))
            truth = TRUTH["cases"]["superclass_replacement"]
            base_run = execute([
                self.java, "-cp", os.pathsep.join((str(business), str(base))),
                "biz.Entry",
            ])
            self.assertEqual(base_run.stdout, truth["expected_base_stdout"])
            current_run = execute([
                self.java, "-cp", os.pathsep.join((str(business), str(current))),
                "biz.Entry",
            ], expected=1)
            diagnostic = current_run.stdout + current_run.stderr
            self.assertIn("NoSuchMethodError", diagnostic)
            self.assertIn("lib.Child.legacy()", diagnostic)
            base_hierarchy = execute([
                self.javap, "-classpath", str(base), "-v", "lib.Child",
            ]).stdout
            current_hierarchy = execute([
                self.javap, "-classpath", str(current), "-v", "lib.Child",
            ]).stdout
            self.assertIn("super_class:", base_hierarchy)
            self.assertIn("// lib/ParentA", base_hierarchy)
            self.assertIn("// lib/ParentB", current_hierarchy)

            entrypoint = ("biz/Entry", "run", "()Ljava/lang/String;")
            config = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "source_usage": {
                    "decision": "skip_source",
                    "decision_source": "explicit_config",
                },
                "base": side(self.home, business, base, "1", entrypoint),
                "current": side(self.home, business, current, "2", entrypoint),
                "runtime_comparison": {
                    "controlled_profile_fields": ["loader_topology"],
                    "declared_upgrade_payload_scope": ["artifact-bytes"],
                },
            }
            result, formal, _overlay = public_pipeline(
                root / "run-superclass", config
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertEqual(
                [
                    [path["path_certainty"], path["path_text"]]
                    for path in target["paths"]
                ],
                truth["expected_paths"],
            )


if __name__ == "__main__":
    unittest.main()
