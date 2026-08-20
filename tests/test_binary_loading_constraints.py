import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_artifact_diff  # noqa: E402
import binary_asm_helper  # noqa: E402
import binary_runtime_reconciler  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import ArtifactInstance, RuntimeProfile  # noqa: E402
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import (  # noqa: E402
    RuntimeCapabilityPolicy,
    RuntimeReconciler,
)


def current_jdk_home():
    try:
        completed = subprocess.run(
            ["java", "-XshowSettings:properties", "-version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "target JDK property probe timed out after 15 seconds"
        ) from error
    match = re.search(
        r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE
    )
    return Path(match.group(1).strip()) if match else None


class _DiagnosticTopologyReconciler(RuntimeReconciler):
    """Exercise provider/constraint semantics beyond the release topology.

    The production definition verifier deliberately certifies parent-first
    realms only. A separate real-JVM test below proves the child-first failure;
    this test double marks already parsed provider selections definition-ready
    solely so the reconciler's loading-constraint model can be inspected.
    """

    def _build_definitions(self, universe, accumulator):
        for realm, name in universe:
            provider = self._provider(realm, name)
            provider_status = provider["class_provider_status"]
            status = (
                "definition_ready"
                if provider_status == "resolved"
                else ("ambiguous" if provider_status == "ambiguous" else "unsupported")
            )
            evidence = {
                "verification": "test_only_provider_identity_model",
                "provider_binding_identity": provider["provider_binding_identity"],
            }
            identity = binary_runtime_reconciler._identity(
                "test_class_definition_resolution_identity",
                {
                    "realm": realm,
                    "class_name": name,
                    "status": status,
                    "provider_binding_identity": provider[
                        "provider_binding_identity"
                    ],
                },
            )
            record = {
                "initiating_loader_realm_identity": realm,
                "class_name": name,
                "class_definition_status": status,
                "class_load_status": (
                    "ready" if status == "definition_ready" else "failed"
                ),
                "class_definition_resolution_identity": identity,
                "provider_binding_identity": provider[
                    "provider_binding_identity"
                ],
                "evidence": evidence,
            }
            accumulator.add("class_definition", record)
            self.definition_records[(realm, name)] = record


class BinaryLoadingConstraintTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        jdk_home = current_jdk_home()
        if not jdk_home or not (jdk_home / "jmods").is_dir():
            raise unittest.SkipTest("target JDK jmods are required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
            cls.platform = JdkPlatformImage(jdk_home, asm_jar=cls.asm_jar)
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.provider_classes = cls.root / "provider-classes"
        cls.caller_classes = cls.root / "caller-classes"
        cls.harness_classes = cls.root / "harness-classes"
        for path in (
            cls.provider_classes, cls.caller_classes, cls.harness_classes
        ):
            path.mkdir()

        provider_sources = {
            "api/Param.java": "package api; public class Param {}",
            "provider/Api.java": (
                "package provider; import api.Param; "
                "public interface Api { void accept(Param value); }"
            ),
            "provider/ParentTarget.java": (
                "package provider; import api.Param; "
                "public class ParentTarget { "
                "public static void accept(Param[] values) {} }"
            ),
            "provider/ChildTarget.java": (
                "package provider; public class ChildTarget "
                "extends ParentTarget {}"
            ),
            "provider/Fields.java": (
                "package provider; import api.Param; "
                "public class Fields { public static Param VALUE; }"
            ),
            "provider/Target.java": (
                "package provider; import api.Param; "
                "public class Target { public static void accept(Param value) {} }"
            ),
        }
        caller_sources = {
            "api/Param.java": "package api; public class Param {}",
            "caller/LazyCaller.java": (
                "package caller; import provider.Target; "
                "public class LazyCaller { "
                "public static void call() { Target.accept(null); } }"
            ),
            "caller/Caller.java": """
                package caller;
                import api.Param;
                import java.util.function.BiConsumer;
                import java.util.function.Consumer;
                import provider.Api;
                import provider.ChildTarget;
                import provider.Fields;
                import provider.Target;
                public class Caller {
                  public static void method(Param[] values) {
                    ChildTarget.accept(values);
                  }
                  public static Param field() { return Fields.VALUE; }
                  public static void iface(Api api, Param value) {
                    api.accept(value);
                  }
                  public static Consumer<Param> staticHandle() {
                    return Target::accept;
                  }
                  public static BiConsumer<Api, Param> interfaceHandle() {
                    return Api::accept;
                  }
                }
            """,
        }
        provider_paths = cls._write_sources("provider-src", provider_sources)
        caller_paths = cls._write_sources("caller-src", caller_sources)
        cls._javac(["-g", "-d", str(cls.provider_classes), *provider_paths])
        cls._javac([
            "-g", "-cp", str(cls.provider_classes),
            "-d", str(cls.caller_classes), *caller_paths,
        ])

        cls.provider_jar = cls.root / "provider.jar"
        cls.caller_jar = cls.root / "caller.jar"
        cls._jar(cls.provider_jar, cls.provider_classes)
        cls._jar(cls.caller_jar, cls.caller_classes)
        cls.provider_sha = binary_artifact_diff._sha256_file(cls.provider_jar)
        cls.caller_sha = binary_artifact_diff._sha256_file(cls.caller_jar)

        harness_source = cls.root / "harness-src" / "ConstraintHarness.java"
        harness_source.parent.mkdir(parents=True)
        harness_source.write_text("""
            import java.lang.reflect.InvocationTargetException;
            import java.net.URL;
            import java.net.URLClassLoader;
            import java.nio.file.Path;

            public class ConstraintHarness {
              static final class ChildFirstLoader extends URLClassLoader {
                ChildFirstLoader(URL[] urls, ClassLoader parent) {
                  super(urls, parent);
                }
                @Override
                protected Class<?> loadClass(String name, boolean resolve)
                    throws ClassNotFoundException {
                  synchronized (getClassLoadingLock(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null &&
                        (name.equals("api.Param") || name.startsWith("caller."))) {
                      try { loaded = findClass(name); }
                      catch (ClassNotFoundException ignored) { }
                    }
                    if (loaded == null) loaded = super.loadClass(name, false);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                  }
                }
              }

              static void invokeLazyCaller(ClassLoader caller) throws Throwable {
                try {
                  Class<?> type = Class.forName("caller.LazyCaller", true, caller);
                  type.getMethod("call").invoke(null);
                } catch (InvocationTargetException error) {
                  throw error.getCause();
                }
              }

              static LinkageError requireConstraintViolation(Throwable observed) {
                while (observed != null && !(observed instanceof LinkageError)) {
                  observed = observed.getCause();
                }
                if (!(observed instanceof LinkageError)) {
                  throw new AssertionError(
                      "expected LinkageError, observed=" + observed);
                }
                String message = String.valueOf(observed.getMessage());
                if (!message.contains("loader constraint violation")) {
                  throw new AssertionError("unexpected LinkageError: " + observed);
                }
                return (LinkageError) observed;
              }

              public static void main(String[] args) throws Exception {
                URL providerUrl = Path.of(args[0]).toUri().toURL();
                URL callerUrl = Path.of(args[1]).toUri().toURL();
                String mode = args[2];
                try (URLClassLoader provider = new URLClassLoader(
                         new URL[] {providerUrl}, ClassLoader.getPlatformClassLoader());
                     ChildFirstLoader caller = new ChildFirstLoader(
                         new URL[] {callerUrl}, provider)) {
                  if (mode.equals("preloaded")) {
                    Class<?> providerParam =
                        Class.forName("api.Param", true, provider);
                    Class<?> callerParam =
                        Class.forName("api.Param", true, caller);
                    if (providerParam == callerParam) {
                      throw new AssertionError(
                          "loaders selected the same Param class");
                    }
                    Throwable observed = null;
                    try { invokeLazyCaller(caller); }
                    catch (Throwable error) { observed = error; }
                    requireConstraintViolation(observed);
                    System.out.println("PRELOADED_CONSTRAINT_VIOLATION");
                    return;
                  }
                  if (mode.equals("deferred")) {
                    try { invokeLazyCaller(caller); }
                    catch (Throwable error) {
                      throw new AssertionError(
                          "constraint establishment should not eagerly fail", error);
                    }
                    Class.forName("api.Param", true, caller);
                    Throwable observed = null;
                    try { Class.forName("api.Param", true, provider); }
                    catch (Throwable error) { observed = error; }
                    requireConstraintViolation(observed);
                    System.out.println(
                        "CALL_SUCCEEDED_THEN_DEFERRED_CONSTRAINT_VIOLATION");
                    return;
                  }
                  throw new IllegalArgumentException("unknown mode: " + mode);
                }
              }
            }
        """, encoding="utf-8")
        cls._javac([
            "-d", str(cls.harness_classes), str(harness_source),
        ])

    @classmethod
    def _write_sources(cls, directory, sources):
        paths = []
        for relative, content in sources.items():
            path = cls.root / directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(str(path))
        return paths

    @classmethod
    def _javac(cls, arguments):
        try:
            completed = subprocess.run(
                ["javac", *arguments],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                "loading-constraint fixture javac timed out after 30 seconds: "
                + " ".join(map(str, arguments))
            ) from error
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr)

    @staticmethod
    def _jar(path, classes):
        with zipfile.ZipFile(path, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(
                    class_file, class_file.relative_to(classes).as_posix()
                )

    def profile(self, caller_delegation):
        required = RuntimeProfile.REQUIRED_FIELDS
        return RuntimeProfile({
            "target_jvm": {
                "vendor": self.platform.release.get("IMPLEMENTOR"),
                "major": self.platform.java_major,
                "version": self.platform.release.get("JAVA_VERSION"),
            },
            "runtime_platform_image_identity": self.platform.identity,
            "target_os": "test-os",
            "target_arch": self.platform.release.get("OS_ARCH", "unknown"),
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [
                {
                    "logical_location": "lib/provider.jar",
                    "content_sha256": self.provider_sha,
                    "path_kind": "classpath",
                    "slot": 0,
                    "loader_realm": "provider-loader",
                },
                {
                    "logical_location": "lib/caller.jar",
                    "content_sha256": self.caller_sha,
                    "path_kind": "classpath",
                    "slot": 1,
                    "loader_realm": "caller-loader",
                },
            ],
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["caller-loader"],
                "realms": [
                    {
                        "identity": "platform-loader",
                        "kind": "platform",
                        "delegation": "parent_first",
                        "module_mode": "named-platform",
                    },
                    {
                        "identity": "provider-loader",
                        "kind": "application",
                        "parent": "platform-loader",
                        "delegation": "parent_first",
                        "module_mode": "unnamed",
                    },
                    {
                        "identity": "caller-loader",
                        "kind": "application",
                        "parent": "provider-loader",
                        "delegation": caller_delegation,
                        "module_mode": "unnamed",
                    },
                ],
            },
            "runtime_code_source_origin_mapping_identity": "dual-loader-origins-v1",
            "runtime_security_and_package_sealing_policy_identity": (
                "standard-unsealed-unsigned-v1"
            ),
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {"classes": ["caller/Caller"]},
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def build_store(self, profile):
        store = BinaryFactStore()
        artifacts = (
            (self.provider_jar, self.provider_sha, "provider-loader", 0),
            (self.caller_jar, self.caller_sha, "caller-loader", 1),
        )
        try:
            for path, digest, realm, slot in artifacts:
                instance = ArtifactInstance(
                    outer_artifact_sha256=digest,
                    container_entry="<artifact>",
                    content_sha256=digest,
                    runtime_profile_identity=profile.identity,
                    path_owner_loader_realm_identity=realm,
                    runtime_path_kind="classpath",
                    runtime_classpath_index=slot,
                    container_loader_policy_version="flat-parent-first-v1",
                    runtime_code_source_origin_identity=f"origin-{realm}",
                    coord=f"test:{path.stem}:1",
                )
                snapshot = binary_artifact_diff.snapshot_archive(
                    path,
                    artifact_instance_identity=instance.identity,
                    expected_sha256=digest,
                    asm_jar=self.asm_jar,
                )
                store.add_artifact_snapshot(instance, snapshot)
        except BaseException:
            store.close()
            raise
        return store

    def reconcile(self, caller_delegation):
        profile = self.profile(caller_delegation)
        capability = RuntimeCapabilityPolicy(
            supported_delegation_modes=("parent_first", "child_first")
        )
        store = self.build_store(profile)
        reconciler = _DiagnosticTopologyReconciler(
            store,
            profile,
            self.platform,
            analysis_context_identity=(
                f"loading-constraint-{caller_delegation}"
            ),
            capability_policy=capability,
        )
        return store, reconciler.reconcile()

    @staticmethod
    def caller_edges(store):
        return {
            (row["caller_method"], row["edge_kind"], row["symbolic_owner"],
             row["symbolic_name"]): dict(row)
            for row in store.connection.execute("""
                SELECT m.member_name AS caller_method,e.*
                FROM direct_edges AS e
                JOIN members AS m
                  ON m.member_identity=e.caller_member_identity
                WHERE m.class_name='caller/Caller'
            """)
        }

    def test_compact_loading_constraint_owner_list_is_canonical_and_fail_closed(self):
        key = "loading_constraint_type_owners"
        self.assertEqual(
            binary_runtime_reconciler._loading_constraint_type_owners({}),
            (),
        )
        self.assertEqual(
            binary_runtime_reconciler._loading_constraint_type_owners({
                key: ["api/A", "api/B"],
            }),
            ("api/A", "api/B"),
        )

        invalid_values = (
            "api/A",
            [],
            [""],
            [1],
            ["api/B", "api/A"],
            ["api/A", "api/A"],
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(
                    binary_runtime_reconciler.RuntimeReconciliationError
                ) as raised:
                    binary_runtime_reconciler._loading_constraint_type_owners({
                        key: value,
                    })
                self.assertEqual(
                    raised.exception.reason_code,
                    "RUNTIME_LOADING_CONSTRAINT_FACT_INVALID",
                )

    def test_constraint_universe_is_isolated_to_the_selected_runtime_profile(self):
        selected_profile = self.profile("parent_first")
        foreign_profile = self.profile("child_first")
        store = self.build_store(selected_profile)
        try:
            foreign_instance = ArtifactInstance(
                outer_artifact_sha256=self.caller_sha,
                container_entry="<artifact>",
                content_sha256=self.caller_sha,
                runtime_profile_identity=foreign_profile.identity,
                path_owner_loader_realm_identity="caller-loader",
                runtime_path_kind="classpath",
                runtime_classpath_index=1,
                container_loader_policy_version="flat-parent-first-v1",
                runtime_code_source_origin_identity="foreign-caller-origin",
                coord="test:foreign-caller:1",
            )
            foreign_snapshot = binary_artifact_diff.snapshot_archive(
                self.caller_jar,
                artifact_instance_identity=foreign_instance.identity,
                expected_sha256=self.caller_sha,
                asm_jar=self.asm_jar,
            )
            store.add_artifact_snapshot(foreign_instance, foreign_snapshot)
            foreign_edge = store.connection.execute(
                """
                SELECT direct_edge_identity,edge_json
                FROM direct_edges
                WHERE caller_artifact_instance_identity=?
                  AND edge_json LIKE '%loading_constraint_type_owners%'
                ORDER BY direct_edge_identity
                LIMIT 1
                """,
                (foreign_instance.identity,),
            ).fetchone()
            self.assertIsNotNone(foreign_edge)
            payload = json.loads(foreign_edge["edge_json"])
            payload["loading_constraint_type_owners"] = []
            store.connection.execute(
                "UPDATE direct_edges SET edge_json=? "
                "WHERE direct_edge_identity=?",
                (
                    json.dumps(
                        payload, sort_keys=True, separators=(",", ":")
                    ),
                    foreign_edge["direct_edge_identity"],
                ),
            )

            reconciler = _DiagnosticTopologyReconciler(
                store,
                selected_profile,
                self.platform,
                analysis_context_identity="profile-isolated-constraints",
            )
            result = reconciler.reconcile()
            self.assertEqual(result.coverage_status, "complete")
        finally:
            store.close()

    def test_real_jvm_distinguishes_preloaded_and_deferred_conflicts(self):
        expected = {
            "preloaded": "PRELOADED_CONSTRAINT_VIOLATION",
            "deferred": (
                "CALL_SUCCEEDED_THEN_DEFERRED_CONSTRAINT_VIOLATION"
            ),
        }
        for mode, stdout in expected.items():
            with self.subTest(mode=mode):
                try:
                    completed = subprocess.run(
                        [
                            "java", "-cp", str(self.harness_classes),
                            "ConstraintHarness", str(self.provider_jar),
                            str(self.caller_jar), mode,
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=15,
                    )
                except subprocess.TimeoutExpired as error:
                    self.fail(
                        f"ConstraintHarness {mode} timed out after 15 seconds: "
                        f"stdout={error.stdout!r}; stderr={error.stderr!r}"
                    )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), stdout)

    def test_reconciler_keeps_provider_conflicts_deferred_without_load_evidence(self):
        store, result = self.reconcile("child_first")
        try:
            edges = self.caller_edges(store)
            ordinary_keys = (
                ("method", "method", "provider/ChildTarget", "accept"),
                ("field", "field", "provider/Fields", "VALUE"),
                ("iface", "method", "provider/Api", "accept"),
            )
            handle_keys = tuple(
                key for key in edges
                if key[0] in {"staticHandle", "interfaceHandle"}
                and key[1].startswith("invokedynamic_handle_")
                and key[3] == "accept"
            )
            self.assertEqual(len(handle_keys), 2, sorted(edges))
            targeted = [edges[key] for key in (*ordinary_keys, *handle_keys)]

            member_by_edge = {
                item["direct_edge_identity"]: item
                for item in result.member_resolutions
            }
            linkage_by_edge = {
                item["direct_edge_identity"]: item
                for item in result.linkage_resolutions
            }
            dispatch_by_edge = {
                item["direct_edge_identity"]: item
                for item in result.dispatch_resolutions
            }
            for edge in targeted:
                with self.subTest(
                    caller=edge["caller_method"], kind=edge["edge_kind"]
                ):
                    edge_identity = edge["direct_edge_identity"]
                    member = member_by_edge[edge_identity]
                    linkage = linkage_by_edge[edge_identity]
                    constraints = member["loading_constraints"]
                    self.assertEqual(
                        member["member_resolution_status"], "resolved"
                    )
                    self.assertEqual(
                        member["loading_constraint_status"],
                        "deferred_conflict",
                    )
                    self.assertEqual(
                        [item["class_name"] for item in constraints],
                        ["api/Param"],
                    )
                    self.assertEqual(
                        constraints[0]["constraint_status"],
                        "deferred_conflict",
                    )
                    self.assertEqual(
                        constraints[0]["runtime_load_evidence_status"],
                        "unavailable",
                    )
                    self.assertNotEqual(
                        constraints[0]["caller_class_identity"],
                        constraints[0]["declaration_class_identity"],
                    )
                    self.assertEqual(
                        linkage["linkage_status"],
                        "loading_constraint_deferred_conflict",
                    )
                    self.assertEqual(
                        linkage["linkage_failure_reason"],
                        "prospective_descriptor_type_provider_mismatch",
                    )
                    dispatch = dispatch_by_edge[edge_identity]
                    if edge["edge_kind"] == "method":
                        self.assertEqual(dispatch["dispatch_status"], "unresolved")
                        self.assertEqual(
                            dispatch["implementation_target_identities"], []
                        )
                    else:
                        self.assertEqual(
                            dispatch["dispatch_status"], "not_applicable"
                        )

            inherited = member_by_edge[
                edges[ordinary_keys[0]]["direct_edge_identity"]
            ]
            self.assertEqual(inherited["resolved_owner"], "provider/ParentTarget")
            self.assertEqual(
                inherited["resolved_defining_loader_realm_identity"],
                "provider-loader",
            )
        finally:
            store.close()

    def test_parent_first_selection_satisfies_the_same_constraints(self):
        store, result = self.reconcile("parent_first")
        try:
            edges = self.caller_edges(store)
            keys = (
                ("method", "method", "provider/ChildTarget", "accept"),
                ("field", "field", "provider/Fields", "VALUE"),
                ("iface", "method", "provider/Api", "accept"),
            )
            linkage_by_edge = {
                item["direct_edge_identity"]: item
                for item in result.linkage_resolutions
            }
            member_by_edge = {
                item["direct_edge_identity"]: item
                for item in result.member_resolutions
            }
            for key in keys:
                edge_identity = edges[key]["direct_edge_identity"]
                member = member_by_edge[edge_identity]
                self.assertEqual(
                    member["loading_constraint_status"], "satisfied"
                )
                self.assertTrue(all(
                    item["provider_equivalent"]
                    and item["constraint_status"] == "satisfied"
                    for item in member["loading_constraints"]
                ))
                self.assertEqual(
                    linkage_by_edge[edge_identity]["linkage_status"], "resolved"
                )
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
