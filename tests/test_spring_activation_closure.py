import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import framework_adapters  # noqa: E402
from step5_artifact_fact_store import Step5ArtifactFactStore  # noqa: E402


@unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
class SpringActivationClosureTest(unittest.TestCase):
    def test_realworld_source_inventory_matches_pinned_independent_oracle(self):
        project = Path("/private/tmp/jua-real-project-spring-boot-realworld")
        oracle_path = (
            ROOT / "tests/fixtures/oracles/"
            "spring-boot-realworld-security-source-oracle.json"
        )
        if not project.is_dir():
            self.skipTest("pinned realworld checkout unavailable")
        expected = json.loads(oracle_path.read_text(encoding="utf-8"))
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=project, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(revision, expected["git_revision"])
        for item in expected["files"]:
            content = (project / item["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), item["sha256"])

        inventory = framework_adapters._spring_security_source_inventory(
            [{"root": str(project / "src/main/java")}]
        )

        actual = inventory["security_filter_chains"]
        self.assertEqual(len(actual), 1)
        for field in (
            "config_owner", "chain_member", "chain_parameter_count",
            "filter_owner", "before_filter_owner", "condition_status",
            "registration_style",
        ):
            self.assertEqual(actual[0][field], expected["security_filter_chains"][0][field])

    def test_security_inventory_discovers_legacy_configurer_and_bean_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src/main/java/demo/LegacySecurityConfig.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; import org.springframework.context.annotation.Bean; "
                "import org.springframework.security.config.annotation.web.builders.HttpSecurity; "
                "import org.springframework.security.web.authentication.AnchorFilter; "
                "public class LegacySecurityConfig { "
                "@Bean public JwtFilter jwtTokenFilter() { return new JwtFilter(); } "
                "protected void configure(HttpSecurity http) throws Exception { "
                "http.addFilterBefore(jwtTokenFilter(), AnchorFilter.class); } }",
                encoding="utf-8",
            )

            inventory = framework_adapters._spring_security_source_inventory(
                [{"root": str(Path(tmp) / "src/main/java")}]
            )

        self.assertEqual(len(inventory["security_filter_chains"]), 1)
        chain = inventory["security_filter_chains"][0]
        self.assertEqual(chain["chain_member"], "configure")
        self.assertEqual(chain["filter_owner"], "demo.JwtFilter")
        self.assertEqual(
            chain["before_filter_owner"],
            "org.springframework.security.web.authentication.AnchorFilter",
        )
        self.assertEqual(chain["registration_style"], "legacy_configurer")

    def test_security_inventory_preserves_class_level_activation_condition(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src/main/java/demo/ConditionalSecurity.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; "
                "@org.springframework.context.annotation.Profile(\"prod\") "
                "public class ConditionalSecurity { "
                "public org.springframework.security.web.SecurityFilterChain chain("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http, "
                "demo.CustomFilter filter) { "
                "http.addFilterBefore(filter, demo.AnchorFilter.class); return null; } }",
                encoding="utf-8",
            )

            inventory = framework_adapters._spring_security_source_inventory(
                [{"root": str(Path(tmp) / "src/main/java")}]
            )

        self.assertEqual(len(inventory["security_filter_chains"]), 1)
        self.assertEqual(
            inventory["security_filter_chains"][0]["condition_status"],
            "unresolved",
        )

    def test_security_source_read_failure_is_explicit_coverage_failure(self):
        unreadable = Path("/unreadable/SecurityConfig.java")
        with patch.object(
            framework_adapters, "_production_java_files", return_value=[unreadable]
        ), patch.object(Path, "read_text", side_effect=OSError("denied")):
            inventory = framework_adapters._spring_security_source_inventory(
                [{"root": "/unreadable"}]
            )

        self.assertEqual(inventory["security_filter_chains"], [])
        self.assertEqual(len(inventory["errors"]), 1)
        self.assertIn("spring_security_source_read_failed", inventory["errors"][0])

    def _compile_aop_fixture(self, root):
        source = root / "src"
        classes = root / "classes"
        files = {
            "org/springframework/context/annotation/Bean.java": (
                "package org.springframework.context.annotation; import java.lang.annotation.*;"
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                "public @interface Bean {}"
            ),
            "org/aspectj/lang/annotation/Aspect.java": (
                "package org.aspectj.lang.annotation; import java.lang.annotation.*;"
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                "public @interface Aspect {}"
            ),
            "org/aspectj/lang/annotation/Before.java": (
                "package org.aspectj.lang.annotation; import java.lang.annotation.*;"
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                "public @interface Before { String value(); }"
            ),
            "org/springframework/stereotype/Component.java": (
                "package org.springframework.stereotype; import java.lang.annotation.*;"
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                "public @interface Component {}"
            ),
            "demo/Service.java": (
                "package demo; public class Service { public void run() {} }"
            ),
            "demo/ActiveAspect.java": (
                "package demo; @org.aspectj.lang.annotation.Aspect "
                "@org.springframework.stereotype.Component public class ActiveAspect {"
                "@org.aspectj.lang.annotation.Before(\"execution(void demo.Service.run())\") "
                "public void before() {} }"
            ),
            "demo/InactiveAspect.java": (
                "package demo; @org.aspectj.lang.annotation.Aspect public class InactiveAspect {"
                "@org.aspectj.lang.annotation.Before(\"execution(void demo.Service.run())\") "
                "public void before() {} }"
            ),
            "demo/UnsupportedAspect.java": (
                "package demo; @org.aspectj.lang.annotation.Aspect "
                "@org.springframework.stereotype.Component public class UnsupportedAspect {"
                "@org.aspectj.lang.annotation.Before(\"within(demo..*)\") "
                "public void before() {} }"
            ),
        }
        paths = []
        for relative, content in files.items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(str(path))
        subprocess.run(
            ["javac", "-d", str(classes), *paths],
            check=True, capture_output=True, text=True,
        )
        artifact = root / "app.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(
                    class_file,
                    "BOOT-INF/classes/" + class_file.relative_to(classes).as_posix(),
                )
        return artifact

    def test_aop_collector_requires_registration_and_reports_unsupported_pointcut(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._compile_aop_fixture(Path(tmp))
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            catalog = {"entries": [{
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": digest,
            }]}
            store = Step5ArtifactFactStore.from_catalog(catalog)
            batch = framework_adapters.collect_spring_aop_activation(
                catalog,
                {"join_points": [{
                    "owner": "demo.Service", "member": "run", "descriptor": "()V",
                }]},
                fact_store=store,
            )
            with zipfile.ZipFile(artifact) as archive:
                class_count = sum(
                    name.endswith(".class") for name in archive.namelist()
                )

        self.assertEqual(batch.collector, "spring_aop_activation")
        self.assertEqual(len(batch.edges), 1)
        edge = batch.edges[0]
        self.assertEqual(edge.caller_symbol, "demo.Service.run()")
        self.assertEqual(edge.callee_symbol, "demo.ActiveAspect.before()")
        self.assertEqual(edge.edge_kind, "spring_aop_activation")
        self.assertTrue(edge.activation_verified)
        self.assertEqual(edge.provenance.artifact_sha256, digest)
        self.assertEqual(
            edge.activation_evidence[0].proof_kind,
            "runtime_visible_aspect_registration",
        )
        self.assertFalse(any("InactiveAspect" in edge.callee_symbol for edge in batch.edges))
        self.assertIn(
            "SPRING_AOP_POINTCUT_UNSUPPORTED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertEqual(batch.coverage[0].status, "partial")
        self.assertEqual(class_count, store.metrics()["class_bytes_reads"])

    def test_aop_bad_zip_is_blocking_parser_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "broken.jar"
            artifact.write_bytes(b"not-a-zip")
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }

            batch = framework_adapters.collect_spring_aop_activation(
                {"entries": [entry]}, {},
                fact_store=Step5ArtifactFactStore.from_catalog({"entries": [entry]}),
            )

        self.assertEqual(
            {"SPRING_AOP_CLASS_PARSE_FAILED"},
            {failure.reason_code for failure in batch.failures},
        )
        self.assertTrue(all(failure.blocking for failure in batch.failures))

    def test_framework_runner_discovers_aop_join_points_from_current_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._compile_aop_fixture(Path(tmp))
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            catalog = {"entries": [{
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": digest,
            }]}

            batches = framework_adapters.run_framework_adapters(
                [], artifact_catalog=catalog,
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        batch = next(item for item in batches if item.collector == "spring_aop_activation")
        self.assertTrue(any(
            edge.caller_symbol == "demo.Service.run()"
            and edge.callee_symbol == "demo.ActiveAspect.before()"
            for edge in batch.edges
        ))

    def test_aop_collector_scans_verified_internal_module_as_business(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._compile_aop_fixture(root)
            classes = root / "classes"
            business = root / "business.jar"
            internal = root / "internal-aspects.jar"
            with zipfile.ZipFile(business, "w") as archive:
                archive.write(classes / "demo/Service.class", "demo/Service.class")
            with zipfile.ZipFile(internal, "w") as archive:
                archive.write(
                    classes / "demo/ActiveAspect.class",
                    "demo/ActiveAspect.class",
                )
            entries = [{
                "coord": "__business__", "jar_path": str(business),
                "sha256": hashlib.sha256(business.read_bytes()).hexdigest(),
            }, {
                "coord": "com.acme:internal-aspects", "jar_path": str(internal),
                "artifact_entry": "BOOT-INF/lib/internal-aspects.jar",
                "sha256": hashlib.sha256(internal.read_bytes()).hexdigest(),
                "application_owned": True,
                "ownership_evidence": {
                    "authority": "reactor_coordinate_and_final_artifact_entry",
                    "reactor_coord": "com.acme:internal-aspects",
                    "artifact_entry": "BOOT-INF/lib/internal-aspects.jar",
                    "final_artifact_sha256": "a" * 64,
                },
            }]

            batch = framework_adapters.collect_spring_aop_activation(
                {"entries": entries}, {},
                fact_store=Step5ArtifactFactStore.from_catalog({"entries": entries}),
            )

        self.assertEqual(len(batch.edges), 1)
        edge = batch.edges[0]
        self.assertEqual(edge.caller_symbol, "demo.Service.run()")
        self.assertEqual(edge.callee_symbol, "demo.ActiveAspect.before()")
        self.assertEqual(edge.provenance.artifact_sha256, entries[1]["sha256"])
        self.assertEqual(len(edge.activation_evidence), 2)

    def test_aop_collector_blocks_changed_shared_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._compile_aop_fixture(root)
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            store.inventory(entry["coord"])
            replacement = root / "replacement.jar"
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("demo/Fake.class", b"replacement")
            replacement.replace(artifact)

            batch = framework_adapters.collect_spring_aop_activation(
                {"entries": [entry]}, {}, fact_store=store,
            )

        self.assertFalse(batch.edges)
        self.assertEqual(
            {failure.reason_code for failure in batch.failures},
            {"ARTIFACT_FACT_STORE_IDENTITY_FAILED"},
        )
        self.assertTrue(all(failure.blocking for failure in batch.failures))

    def test_aop_collector_turns_javap_timeout_into_blocking_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._compile_aop_fixture(Path(tmp))
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            with patch.object(
                framework_adapters.subprocess, "run",
                side_effect=subprocess.TimeoutExpired("javap", 30),
            ):
                batch = framework_adapters.collect_spring_aop_activation(
                    {"entries": [entry]}, {},
                )

        self.assertFalse(batch.edges)
        self.assertIn(
            "FRAMEWORK_JAVAP_FAILED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertTrue(any(failure.blocking for failure in batch.failures))

    def _compile_security_fixture(self, root, *, nested_support=False):
        source = root / "security-src"
        classes = root / "security-classes"
        files = {
            "org/springframework/context/annotation/Bean.java": (
                "package org.springframework.context.annotation; import java.lang.annotation.*;"
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                "public @interface Bean {}"
            ),
            "jakarta/servlet/Filter.java": (
                "package jakarta.servlet; public interface Filter { void doFilter(); }"
            ),
            "org/springframework/security/web/SecurityFilterChain.java": (
                "package org.springframework.security.web; public interface SecurityFilterChain {}"
            ),
            "org/springframework/security/config/annotation/web/builders/HttpSecurity.java": (
                "package org.springframework.security.config.annotation.web.builders; "
                "public class HttpSecurity { public HttpSecurity addFilterBefore("
                "jakarta.servlet.Filter filter, Class<?> anchor) { return this; } }"
            ),
            "org/springframework/security/config/annotation/web/configuration/"
            "WebSecurityConfigurerAdapter.java": (
                "package org.springframework.security.config.annotation.web.configuration; "
                "public class WebSecurityConfigurerAdapter { protected void configure("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http) "
                "throws Exception {} }"
            ),
            "demo/CustomFilter.java": (
                "package demo; public class CustomFilter implements jakarta.servlet.Filter {"
                " public void doFilter() {} }"
            ),
            "demo/OrphanFilter.java": (
                "package demo; public class OrphanFilter implements jakarta.servlet.Filter {"
                " public void doFilter() {} }"
            ),
            "demo/AnchorFilter.java": (
                "package demo; public class AnchorFilter implements jakarta.servlet.Filter {"
                " public void doFilter() {} }"
            ),
            "demo/SecurityConfig.java": (
                "package demo; public class SecurityConfig { public "
                "org.springframework.security.web.SecurityFilterChain chain("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http, "
                "demo.CustomFilter filter) { http.addFilterBefore(filter, demo.AnchorFilter.class); "
                "return null; } }"
            ),
            "demo/LegacySecurityConfig.java": (
                "package demo; public class LegacySecurityConfig extends "
                "org.springframework.security.config.annotation.web.configuration."
                "WebSecurityConfigurerAdapter { "
                "@org.springframework.context.annotation.Bean public demo.CustomFilter "
                "jwtFilter() { return new demo.CustomFilter(); } "
                "protected void configure("
                "org.springframework.security.config.annotation.web.builders.HttpSecurity http) "
                "throws Exception { http.addFilterBefore(jwtFilter(), "
                "demo.AnchorFilter.class); } }"
            ),
        }
        paths = []
        for relative, content in files.items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(str(path))
        subprocess.run(
            ["javac", "-d", str(classes), *paths],
            check=True, capture_output=True, text=True,
        )
        artifact = root / "security-app.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            nested = root / "security-support.jar"
            nested_owners = {
                "demo/AnchorFilter.class",
            } if nested_support else set()
            if nested_owners:
                with zipfile.ZipFile(nested, "w") as support:
                    for owner in sorted(nested_owners):
                        support.write(classes / owner, owner)
            for class_file in sorted(classes.rglob("*.class")):
                relative = class_file.relative_to(classes).as_posix()
                if relative in nested_owners:
                    continue
                archive.write(
                    class_file,
                    "BOOT-INF/classes/" + relative,
                )
            if nested_owners:
                archive.write(nested, "BOOT-INF/lib/security-support.jar")
        return artifact

    def test_security_collector_resolves_filter_and_anchor_inside_boot_inf_lib(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._compile_security_fixture(root, nested_support=True)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

            catalog = {"entries": [{
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": digest,
            }]}
            batch = framework_adapters.collect_spring_security_filter_activation(
                catalog,
                {"security_filter_chains": [{
                    "config_owner": "demo.SecurityConfig",
                    "chain_member": "chain",
                    "chain_descriptor": (
                        "(Lorg/springframework/security/config/annotation/web/builders/"
                        "HttpSecurity;Ldemo/CustomFilter;)Lorg/springframework/security/web/"
                        "SecurityFilterChain;"
                    ),
                    "filter_owner": "demo.CustomFilter",
                    "before_filter_owner": "demo.AnchorFilter",
                    "condition_status": "resolved",
                    "registration_style": "security_filter_chain",
                }]},
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        self.assertEqual(len(batch.edges), 1)
        self.assertEqual(batch.edges[0].callee_symbol, "demo.CustomFilter.doFilter()")
        self.assertIn(
            "BOOT-INF/lib/security-support.jar!/demo/AnchorFilter.class",
            dict(batch.edges[0].metadata)["framework_provenance"][
                "anchor_entry"
            ],
        )

    def test_security_collector_uses_verified_internal_module_catalog_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._compile_security_fixture(root)
            classes = root / "security-classes"
            business = root / "business.jar"
            internal = root / "internal-security.jar"
            runtime = root / "spring-security-web.jar"
            with zipfile.ZipFile(business, "w") as archive:
                archive.write(
                    classes / "demo/SecurityConfig.class",
                    "demo/SecurityConfig.class",
                )
            with zipfile.ZipFile(internal, "w") as archive:
                archive.write(
                    classes / "demo/CustomFilter.class",
                    "demo/CustomFilter.class",
                )
            with zipfile.ZipFile(runtime, "w") as archive:
                archive.write(
                    classes / "demo/AnchorFilter.class",
                    "demo/AnchorFilter.class",
                )
            entries = [{
                "coord": "__business__", "jar_path": str(business),
                "sha256": hashlib.sha256(business.read_bytes()).hexdigest(),
            }, {
                "coord": "com.acme:internal-security", "jar_path": str(internal),
                "artifact_entry": "BOOT-INF/lib/internal-security.jar",
                "sha256": hashlib.sha256(internal.read_bytes()).hexdigest(),
                "application_owned": True,
                "ownership_evidence": {
                    "authority": "reactor_coordinate_and_final_artifact_entry",
                    "reactor_coord": "com.acme:internal-security",
                    "artifact_entry": "BOOT-INF/lib/internal-security.jar",
                    "final_artifact_sha256": "a" * 64,
                },
            }, {
                "coord": "org.springframework.security:spring-security-web",
                "jar_path": str(runtime),
                "artifact_entry": "BOOT-INF/lib/spring-security-web.jar",
                "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            }]

            batch = framework_adapters.collect_spring_security_filter_activation(
                {"entries": entries},
                {"security_filter_chains": [{
                    "config_owner": "demo.SecurityConfig",
                    "chain_member": "chain",
                    "chain_descriptor": (
                        "(Lorg/springframework/security/config/annotation/web/builders/"
                        "HttpSecurity;Ldemo/CustomFilter;)Lorg/springframework/security/web/"
                        "SecurityFilterChain;"
                    ),
                    "filter_owner": "demo.CustomFilter",
                    "before_filter_owner": "demo.AnchorFilter",
                    "condition_status": "resolved",
                    "registration_style": "security_filter_chain",
                }]},
                fact_store=Step5ArtifactFactStore.from_catalog({"entries": entries}),
            )

        self.assertEqual(len(batch.edges), 1)
        proof_sources = {
            item.proof_kind: item.artifact_sha256
            for item in batch.edges[0].activation_evidence
        }
        self.assertEqual(
            proof_sources["security_filter_callback_packaged"],
            entries[1]["sha256"],
        )
        self.assertEqual(
            proof_sources["security_filter_anchor_packaged"],
            entries[2]["sha256"],
        )

    def test_security_collector_blocks_changed_shared_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._compile_security_fixture(root)
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            store.inventory(entry["coord"])
            replacement = root / "replacement.jar"
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("demo/Fake.class", b"replacement")
            replacement.replace(artifact)

            batch = framework_adapters.collect_spring_security_filter_activation(
                {"entries": [entry]}, {"security_filter_chains": [{
                    "config_owner": "demo.SecurityConfig",
                    "chain_member": "chain",
                    "filter_owner": "demo.CustomFilter",
                    "before_filter_owner": "demo.AnchorFilter",
                    "condition_status": "resolved",
                }]}, fact_store=store,
            )

        self.assertFalse(batch.edges)
        self.assertIn(
            "ARTIFACT_FACT_STORE_IDENTITY_FAILED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertTrue(any(failure.blocking for failure in batch.failures))

    def test_security_collector_turns_javap_timeout_into_blocking_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._compile_security_fixture(root)
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            inventory = {"security_filter_chains": [{
                "config_owner": "demo.SecurityConfig",
                "chain_member": "chain",
                "chain_descriptor": (
                    "(Lorg/springframework/security/config/annotation/web/builders/"
                    "HttpSecurity;Ldemo/CustomFilter;)Lorg/springframework/security/web/"
                    "SecurityFilterChain;"
                ),
                "filter_owner": "demo.CustomFilter",
                "before_filter_owner": "demo.AnchorFilter",
                "condition_status": "resolved",
                "registration_style": "security_filter_chain",
            }]}
            with patch.object(
                framework_adapters.subprocess, "run",
                side_effect=subprocess.TimeoutExpired("javap", 30),
            ):
                batch = framework_adapters.collect_spring_security_filter_activation(
                    {"entries": [entry]}, inventory,
                )

        self.assertFalse(batch.edges)
        self.assertIn(
            "FRAMEWORK_JAVAP_FAILED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertTrue(any(failure.blocking for failure in batch.failures))

    def test_packaged_class_locator_reports_malformed_nested_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "broken-app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/broken.jar", b"not-a-zip")
            with zipfile.ZipFile(artifact) as archive:
                locations, diagnostics = framework_adapters._locate_packaged_classes(
                    archive, {"demo.Missing"}
                )

        self.assertIsNone(locations["demo.Missing"])
        self.assertEqual(len(diagnostics), 1)
        self.assertIn("spring_nested_artifact_invalid", diagnostics[0])

    def test_shared_class_locator_rejects_duplicate_logical_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "duplicate.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("demo/Config.class", b"root")
                archive.writestr("BOOT-INF/classes/demo/Config.class", b"boot")
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            locations, diagnostics = framework_adapters._locate_catalog_classes(
                [entry], {"demo.Config"}, fact_store=store,
            )

        self.assertIsNone(locations["demo.Config"])
        self.assertTrue(any(
            "spring_packaged_class_ambiguous" in item for item in diagnostics
        ))

    def test_shared_class_locator_reads_only_requested_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "large.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                for index in range(100):
                    archive.writestr(f"demo/Class{index}.class", f"{index}".encode())
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            locations, diagnostics = framework_adapters._locate_catalog_classes(
                [entry], {"demo.Class42"}, fact_store=store,
            )

        self.assertFalse(diagnostics)
        self.assertEqual(b"42", locations["demo.Class42"]["bytes"])
        self.assertEqual(1, store.metrics()["class_bytes_reads"])

    def test_shared_class_locator_classifies_malformed_nested_jar_as_parser_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "broken-app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/broken.jar", b"not-a-zip")
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            locations, diagnostics = framework_adapters._locate_catalog_classes(
                [entry], {"demo.Missing"}, include_nested=True, fact_store=store,
            )

        self.assertIsNone(locations["demo.Missing"])
        self.assertTrue(any("spring_nested_artifact_invalid" in item for item in diagnostics))
        self.assertFalse(any("artifact_fact_store_identity_failed" in item for item in diagnostics))
        failure = framework_adapters._framework_failure("spring", diagnostics[0])
        self.assertEqual("SPRING_NESTED_ARTIFACT_INVALID", failure.reason_code)
        self.assertTrue(failure.blocking)

    def test_aop_collector_streams_large_non_aspect_class_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "large.jar"
            with zipfile.ZipFile(
                artifact, "w", compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for index in range(24):
                    archive.writestr(
                        f"demo/Filler{index}.class", b"x" * (1024 * 1024),
                    )
            entry = {
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "application_owned": True,
                "ownership_evidence": {"authority": "fixture"},
            }
            catalog = {"entries": [entry]}
            store = Step5ArtifactFactStore.from_catalog(catalog)

            tracemalloc.start()
            batch = framework_adapters.collect_spring_aop_activation(
                catalog, {}, fact_store=store,
            )
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        self.assertFalse(batch.edges)
        self.assertLess(peak, 12 * 1024 * 1024)
        self.assertEqual(24, store.metrics()["class_bytes_reads"])

    def test_security_collector_requires_exact_chain_membership_and_resolved_condition(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._compile_security_fixture(Path(tmp))
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            batch = framework_adapters.collect_spring_security_filter_activation(
                {"entries": [{
                    "coord": "__business__", "jar_path": str(artifact),
                    "sha256": digest,
                }]},
                {
                    "packaged_filters": ["demo.CustomFilter", "demo.OrphanFilter"],
                    "security_filter_chains": [{
                        "config_owner": "demo.SecurityConfig",
                        "chain_member": "chain",
                        "chain_descriptor": (
                            "(Lorg/springframework/security/config/annotation/web/builders/"
                            "HttpSecurity;Ldemo/CustomFilter;)Lorg/springframework/security/web/"
                            "SecurityFilterChain;"
                        ),
                        "filter_owner": "demo.CustomFilter",
                        "before_filter_owner": "demo.AnchorFilter",
                        "condition_status": "resolved",
                    }, {
                        "config_owner": "demo.SecurityConfig",
                        "chain_member": "conditional",
                        "chain_descriptor": "()Lorg/springframework/security/web/SecurityFilterChain;",
                        "filter_owner": "demo.OrphanFilter",
                        "before_filter_owner": "demo.AnchorFilter",
                        "condition_status": "unresolved",
                    }],
                },
            )

        self.assertEqual(len(batch.edges), 1)
        edge = batch.edges[0]
        self.assertEqual(edge.edge_kind, "spring_security_filter_activation")
        self.assertEqual(edge.callee_symbol, "demo.CustomFilter.doFilter()")
        self.assertTrue(edge.activation_verified)
        self.assertEqual(edge.provenance.artifact_sha256, digest)
        self.assertFalse(any("OrphanFilter" in item.callee_symbol for item in batch.edges))
        self.assertIn(
            "SPRING_SECURITY_FILTER_CONDITION_UNRESOLVED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertEqual(batch.coverage[0].status, "partial")

    def test_framework_runner_discovers_security_chain_from_source_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._compile_security_fixture(root)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            catalog = {"entries": [{
                "coord": "__business__", "jar_path": str(artifact),
                "sha256": digest,
            }]}

            batches = framework_adapters.run_framework_adapters(
                [{"root": str(root / "security-src")}],
                artifact_catalog=catalog,
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        batch = next(
            item for item in batches
            if item.collector == "spring_security_filter_activation"
        )
        self.assertEqual(len(batch.edges), 2)
        self.assertTrue(all(
            edge.callee_symbol == "demo.CustomFilter.doFilter()"
            and edge.activation_verified
            for edge in batch.edges
        ))
        self.assertTrue(any(
            edge.caller_symbol.startswith("demo.LegacySecurityConfig.configure(")
            for edge in batch.edges
        ))


if __name__ == "__main__":
    unittest.main()
