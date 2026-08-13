import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from tests.blackbox.test_public_runtime_dispatch import (
    compile_jar,
    jdk_home,
    public_pipeline,
    runtime_profile,
)


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "framework_semantics_v1.json"
).read_text(encoding="utf-8"))


def execute(command: list[str], *, expected: int = 0) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
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


def append_resources(jar: Path, resources: dict[str, str]) -> None:
    with zipfile.ZipFile(jar, "a", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(resources.items()):
            archive.writestr(name, content.strip() + "\n")


def side_with_artifacts(
    home: Path,
    business: Path,
    dependencies: tuple[tuple[Path, str, str], ...],
    entrypoint: tuple[str, str, str],
    *,
    frameworks: tuple[str, ...] = (),
    resources: tuple[str, ...] = (),
    auto_entrypoints: bool = False,
) -> dict:
    profile = runtime_profile(entrypoint)
    profile["container_and_launcher_kind"] = (
        "spring-boot-executable-jar" if "spring_boot" in frameworks
        else "java-classpath"
    )
    profile["business_entrypoint_profile"].update({
        "activated_frameworks": list(frameworks),
        "activated_resource_names": list(resources),
    })
    if auto_entrypoints:
        profile["business_entrypoint_profile"].update({
            "discovery_mode": "binary_auto",
            "main_class": entrypoint[0],
        })
    artifacts = [{
        "path": str(business),
        "logical_location": "app/business.jar",
        "loader_realm": "application-loader",
        "path_kind": "business_classes",
        "slot": 0,
        "coord": "blackbox:framework-business:1",
        "lineage": "blackbox:framework-business",
        "runtime_code_source_origin_identity": "framework-business",
    }]
    for slot, (path, coord, lineage) in enumerate(dependencies, 1):
        artifacts.append({
            "path": str(path),
            "logical_location": f"lib/dependency-{slot}.jar",
            "loader_realm": "application-loader",
            "path_kind": "classpath",
            "slot": slot,
            "coord": coord,
            "lineage": lineage,
            "runtime_code_source_origin_identity": f"framework:{lineage}:{slot}",
        })
    return {"jdk_home": str(home), "artifacts": artifacts, "runtime_profile": profile}


def config(base: dict, current: dict) -> dict:
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "source_usage": {
            "decision": "skip_source", "decision_source": "explicit_config",
        },
        "base": base,
        "current": current,
        "runtime_comparison": {
            "controlled_profile_fields": ["loader_topology"],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
        },
    }


def identity(row: dict) -> tuple[str, str, str, str]:
    return (
        row.get("display_owner"), row.get("display_member"),
        row.get("display_descriptor"), row.get("display_member_kind"),
    )


class PublicFrameworkSemanticsBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which("java") or ""
        cls.javac = shutil.which("javac") or ""
        cls.javap = shutil.which("javap") or ""
        if not all((cls.java, cls.javac, cls.javap)):
            raise AssertionError("OpenJDK java, javac, and javap are required")
        cls.home = jdk_home(cls.java)

    def run_main(
        self, oracle: Path, business: Path, dependencies: tuple[Path, ...]
    ) -> str:
        classpath = os.pathsep.join(map(str, (oracle, business, *dependencies)))
        return execute([self.java, "-cp", classpath, "oracle.Main"]).stdout

    def assert_targets_reachable(self, formal: dict, targets: list[list[str]]) -> None:
        by_identity = {identity(row): row for row in formal["by_api"]}
        for target in targets:
            row = by_identity[tuple(target)]
            self.assertEqual(row["reachability_status"], "reachable", row)
            self.assertTrue(row["exact_path_exists"], row)

    def test_spring_entrypoints_and_conditions_match_jvm_and_resources(self):
        truth = TRUTH["cases"]["spring_entrypoints"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def framework(label: str, value: int) -> Path:
                jar = compile_jar(root, label, {
                    "org/springframework/scheduling/annotation/Scheduled.java": """
                        package org.springframework.scheduling.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME)
                        @Target({ElementType.METHOD,ElementType.ANNOTATION_TYPE})
                        public @interface Scheduled {}
                    """,
                    "vendor/EveryMinute.java": """
                        package vendor;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        @org.springframework.scheduling.annotation.Scheduled
                        public @interface EveryMinute {}
                    """,
                    "org/springframework/web/bind/annotation/GetMapping.java": """
                        package org.springframework.web.bind.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface GetMapping {}
                    """,
                    "org/springframework/context/event/EventListener.java": """
                        package org.springframework.context.event;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface EventListener {}
                    """,
                    "jakarta/annotation/PostConstruct.java": """
                        package jakarta.annotation; import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface PostConstruct {}
                    """,
                    "org/springframework/boot/autoconfigure/AutoConfiguration.java": """
                        package org.springframework.boot.autoconfigure;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                        public @interface AutoConfiguration {}
                    """,
                    "org/springframework/boot/autoconfigure/condition/ConditionalOnProperty.java": """
                        package org.springframework.boot.autoconfigure.condition;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD})
                        public @interface ConditionalOnProperty { String prefix() default ""; String[] name(); String havingValue() default ""; boolean matchIfMissing() default false; }
                    """,
                    "api/Api.java": (
                        "package api; public class Api { public int value() { "
                        f"return {value}; }} }}"
                    ),
                    "vendor/Callbacks.java": """
                        package vendor;
                        @org.springframework.boot.autoconfigure.AutoConfiguration
                        public class Callbacks {
                          @org.springframework.scheduling.annotation.Scheduled public int tick(){ return new api.Api().value(); }
                          @org.springframework.web.bind.annotation.GetMapping public int web(){ return new api.Api().value(); }
                          @org.springframework.context.event.EventListener public int event(){ return new api.Api().value(); }
                          @jakarta.annotation.PostConstruct public int init(){ return new api.Api().value(); }
                          @vendor.EveryMinute public int meta(){ return new api.Api().value(); }
                        }
                    """,
                    "vendor/ConditionalConfig.java": """
                        package vendor;
                        @org.springframework.boot.autoconfigure.AutoConfiguration
                        @org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(prefix="feature", name="enabled", havingValue="on")
                        public class ConditionalConfig {
                          @org.springframework.scheduling.annotation.Scheduled public int tick(){ return new api.Api().value(); }
                        }
                    """,
                }, self.javac)
                append_resources(jar, {
                    "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports": (
                        "vendor.Callbacks\nvendor.ConditionalConfig"
                    ),
                })
                return jar

            base = framework("spring-entry-base", 1)
            current = framework("spring-entry-current", 2)
            business = compile_jar(root, "spring-entry-business", {
                "biz/Application.java": "package biz; public class Application { public static void main(String[] args) {} }",
            }, self.javac)
            oracle = compile_jar(root, "spring-entry-oracle", {
                "oracle/Main.java": """
                    package oracle; public class Main {
                      public static void main(String[] args) {
                        vendor.Callbacks c = new vendor.Callbacks();
                        System.out.print(c.tick()+c.web()+c.event()+c.init()+c.meta());
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            bytecode = execute([
                self.javap, "-classpath", str(base), "-v", "vendor.Callbacks",
            ]).stdout
            for descriptor in (
                "Scheduled;", "GetMapping;", "EventListener;", "PostConstruct;",
            ):
                self.assertIn(descriptor, bytecode)
            with zipfile.ZipFile(base) as archive:
                registrations = archive.read(
                    "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"
                ).decode("utf-8").splitlines()
            self.assertEqual(registrations, ["vendor.Callbacks", "vendor.ConditionalConfig"])

            entrypoint = ("biz/Application", "main", "([Ljava/lang/String;)V")
            resources = (
                "classpath:META-INF/spring/"
                "org.springframework.boot.autoconfigure.AutoConfiguration.imports",
            )
            base_side = side_with_artifacts(
                self.home, business,
                ((base, "blackbox:spring-entry:1", "blackbox:spring-entry"),),
                entrypoint, frameworks=("spring_boot",), resources=resources,
                auto_entrypoints=True,
            )
            current_side = side_with_artifacts(
                self.home, business,
                ((current, "blackbox:spring-entry:2", "blackbox:spring-entry"),),
                entrypoint, frameworks=("spring_boot",), resources=resources,
                auto_entrypoints=True,
            )
            for item in (base_side, current_side):
                profile = item["runtime_profile"]
                profile["resolved_configuration_properties"] = {}
                profile["runtime_configuration_coverage_status"] = "complete"
            result, formal, _overlay = public_pipeline(
                root / "spring-entry-report", config(base_side, current_side)
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if identity(row) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            callback_entries = [row for row in entries if row["class_name"] == "vendor/Callbacks"]
            self.assertEqual(
                sorted({row["entry_kind"] for row in callback_entries}),
                truth["required_entry_kinds"],
            )
            self.assertTrue(all(row["path_certainty"] == "exact" for row in callback_entries))
            required_meta = tuple(truth["required_meta_entrypoint"])
            self.assertTrue(any(
                (
                    row["class_name"], row["member_name"], row["descriptor"],
                    row["entry_kind"], row["path_certainty"],
                ) == required_meta
                for row in entries
            ), entries)
            forbidden = tuple(truth["forbidden_entrypoint"])
            self.assertFalse(any(
                (row["class_name"], row["member_name"], row["descriptor"]) == forbidden
                for row in entries
            ))

    def test_mybatis_annotation_xml_and_extension_callbacks(self):
        truth = TRUTH["cases"]["mybatis"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def framework(label: str, digit: int) -> Path:
                jar = compile_jar(root, label, {
                    "org/apache/ibatis/annotations/Mapper.java": """
                        package org.apache.ibatis.annotations; import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Mapper {}
                    """,
                    "org/apache/ibatis/binding/MapperProxy.java": (
                        "package org.apache.ibatis.binding; public class MapperProxy { "
                        "public Object invoke(Object p, java.lang.reflect.Method m, Object[] a) { "
                        f"return Integer.valueOf({digit}); }} }}"
                    ),
                    "org/apache/ibatis/binding/MapperMethod.java": "package org.apache.ibatis.binding; public class MapperMethod { public Object execute(Object session,Object[] args){return null;} }",
                    "org/apache/ibatis/plugin/Interceptor.java": "package org.apache.ibatis.plugin; public interface Interceptor { Object intercept(Object invocation); }",
                    "org/apache/ibatis/type/TypeHandler.java": "package org.apache.ibatis.type; public interface TypeHandler { void setParameter(Object value); Object getResult(Object value); }",
                    "vendor/AuditPlugin.java": (
                        "package vendor; public class AuditPlugin implements org.apache.ibatis.plugin.Interceptor { "
                        f"public Object intercept(Object value) {{ return Integer.valueOf({digit}); }} }}"
                    ),
                    "vendor/CodeHandler.java": (
                        "package vendor; public class CodeHandler implements org.apache.ibatis.type.TypeHandler { "
                        "public void setParameter(Object value) {} "
                        f"public Object getResult(Object value) {{ return Integer.valueOf({digit}); }} }}"
                    ),
                    "vendor/UnregisteredPlugin.java": (
                        "package vendor; public class UnregisteredPlugin implements "
                        "org.apache.ibatis.plugin.Interceptor { public Object intercept(Object value) { "
                        f"return Integer.valueOf({digit}); }} }}"
                    ),
                }, self.javac)
                append_resources(jar, {
                    "mybatis-config.xml": (
                        '<configuration><plugins><plugin interceptor="vendor.AuditPlugin"/>'
                        '</plugins><typeHandlers><typeHandler javaType="java.lang.String" '
                        'handler="vendor.CodeHandler"/></typeHandlers></configuration>'
                    ),
                    "mapper/DemoMapper.xml": '<mapper namespace="biz.DemoMapper"><select id="findOne">select 1</select></mapper>',
                })
                return jar

            base = framework("mybatis-base", 1)
            current = framework("mybatis-current", 2)
            business = compile_jar(root, "mybatis-business", {
                "biz/DemoMapper.java": "package biz; @org.apache.ibatis.annotations.Mapper public interface DemoMapper { int findOne(); }",
                "biz/Entry.java": "package biz; public class Entry { public int run(DemoMapper mapper){ return mapper.findOne(); } }",
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "mybatis-oracle", {
                "oracle/Main.java": """
                    package oracle; public class Main { public static void main(String[] args) throws Exception {
                      org.apache.ibatis.binding.MapperProxy proxy = new org.apache.ibatis.binding.MapperProxy();
                      Object a = proxy.invoke(null, oracle.Main.class.getDeclaredMethod("main", String[].class), null);
                      Object b = new vendor.AuditPlugin().intercept(null);
                      Object c = new vendor.CodeHandler().getResult(null);
                      System.out.print(a.toString()+b.toString()+c.toString());
                    }}
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(self.run_main(oracle, business, (base,)), truth["expected_base_stdout"])
            self.assertEqual(self.run_main(oracle, business, (current,)), truth["expected_current_stdout"])
            with zipfile.ZipFile(base) as archive:
                config_xml = archive.read("mybatis-config.xml").decode("utf-8")
                mapper_xml = archive.read("mapper/DemoMapper.xml").decode("utf-8")
            self.assertEqual(config_xml.count("vendor.AuditPlugin"), 1)
            self.assertEqual(config_xml.count("vendor.CodeHandler"), 1)
            self.assertIn('namespace="biz.DemoMapper"', mapper_xml)

            entrypoint = ("biz/Entry", "run", "(Lbiz/DemoMapper;)I")
            resources = ("classpath:mybatis-config.xml", "classpath:mapper/DemoMapper.xml")
            sides = []
            for jar, version in ((base, "1"), (current, "2")):
                sides.append(side_with_artifacts(
                    self.home, business,
                    ((jar, f"blackbox:mybatis:{version}", "blackbox:mybatis"),),
                    entrypoint, frameworks=("mybatis",), resources=resources,
                ))
            result, formal, overlay = public_pipeline(
                root / "mybatis-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            self.assert_targets_reachable(formal, truth["targets"])
            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            self.assertEqual(
                sorted({row["entry_kind"] for row in entries if row["class_name"].startswith("vendor/")}),
                truth["required_entry_kinds"],
            )
            self.assertTrue(all(
                row["path_certainty"] == "exact" for row in entries
                if row["class_name"].startswith("vendor/")
            ))
            self.assertTrue(set(truth["required_semantic_kinds"]).issubset({
                row["semantic_edge_kind"] for row in overlay["rows"]
            }))
            forbidden = tuple(truth["forbidden_exact_entrypoint"])
            self.assertFalse(any(
                (
                    row["class_name"], row["member_name"], row["entry_kind"],
                ) == forbidden
                and row["path_certainty"] == "exact"
                for row in entries
            ), entries)

    def test_spring_transaction_bean_wiring_and_repository_proxy(self):
        truth = TRUTH["cases"]["spring_proxy_wiring"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def framework(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "org/springframework/transaction/annotation/Transactional.java": """
                        package org.springframework.transaction.annotation; import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) public @interface Transactional {}
                    """,
                    "org/aopalliance/intercept/MethodInvocation.java": "package org.aopalliance.intercept; public interface MethodInvocation {}",
                    "org/springframework/transaction/interceptor/TransactionInterceptor.java": (
                        "package org.springframework.transaction.interceptor; public class TransactionInterceptor { "
                        "public Object invoke(org.aopalliance.intercept.MethodInvocation invocation) { "
                        f"return Integer.valueOf({digit}); }} }}"
                    ),
                    "org/springframework/transaction/interceptor/TransactionAspectSupport.java": "package org.springframework.transaction.interceptor; public class TransactionAspectSupport { public interface InvocationCallback {} public Object invokeWithinTransaction(java.lang.reflect.Method method, Class<?> type, InvocationCallback callback){return null;} }",
                    "org/springframework/aop/framework/ReflectiveMethodInvocation.java": "package org.springframework.aop.framework; public class ReflectiveMethodInvocation { public Object proceed(){return null;} }",
                    "org/springframework/stereotype/Component.java": "package org.springframework.stereotype; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface Component {}",
                    "org/springframework/context/annotation/ComponentScan.java": "package org.springframework.context.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface ComponentScan { String[] value() default {}; }",
                    "org/springframework/context/annotation/Primary.java": "package org.springframework.context.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.METHOD}) public @interface Primary {}",
                    "org/springframework/data/repository/Repository.java": "package org.springframework.data.repository; public interface Repository<T,ID> {}",
                    "org/springframework/data/jpa/repository/JpaRepository.java": "package org.springframework.data.jpa.repository; public interface JpaRepository<T,ID> extends org.springframework.data.repository.Repository<T,ID> { java.util.List<T> findAll(); }",
                    "org/springframework/data/jpa/repository/support/SimpleJpaRepository.java": (
                        "package org.springframework.data.jpa.repository.support; "
                        "public class SimpleJpaRepository<T,ID> { "
                        f"public java.util.List<T> findAll() {{ return {digit} == 1 "
                        "? new java.util.ArrayList<T>() : java.util.Collections.emptyList(); } }"
                    ),
                    "lib/Service.java": "package lib; public interface Service { int ping(); }",
                    "lib/LibService.java": (
                        "package lib; @org.springframework.stereotype.Component @org.springframework.context.annotation.Primary "
                        f"public class LibService implements Service {{ public int ping() {{ return {digit}; }} }}"
                    ),
                    "lib/SecondaryService.java": (
                        "package lib; @org.springframework.stereotype.Component "
                        "public class SecondaryService implements Service { "
                        f"public int ping() {{ return {digit}; }} }}"
                    ),
                }, self.javac)

            base = framework("spring-proxy-base", 1)
            current = framework("spring-proxy-current", 2)
            business = compile_jar(root, "spring-proxy-business", {
                "biz/DemoRepository.java": "package biz; public interface DemoRepository extends org.springframework.data.jpa.repository.JpaRepository<Object,Long> {}",
                "biz/Config.java": "package biz; @org.springframework.context.annotation.ComponentScan(\"lib\") public class Config {}",
                "biz/Service.java": "package biz; public class Service { @org.springframework.transaction.annotation.Transactional public int work(){return 7;} }",
                "biz/Entry.java": "package biz; public class Entry { public int run(lib.Service service, DemoRepository repo){ return service.ping()+repo.findAll().size()+new Service().work(); } }",
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "spring-proxy-oracle", {
                "oracle/Main.java": """
                    package oracle; public class Main { public static void main(String[] args) {
                      Object tx = new org.springframework.transaction.interceptor.TransactionInterceptor().invoke(null);
                      int bean = new lib.LibService().ping();
                      int repo = new org.springframework.data.jpa.repository.support.SimpleJpaRepository<Object,Long>().findAll().size();
                      System.out.print(tx.toString()+bean+repo);
                    }}
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(self.run_main(oracle, business, (base,)), truth["expected_base_stdout"])
            self.assertEqual(self.run_main(oracle, business, (current,)), truth["expected_current_stdout"])
            business_contract = execute([
                self.javap, "-classpath", str(business), "-v", "biz.Service",
            ]).stdout
            self.assertIn("Transactional;", business_contract)

            entrypoint = ("biz/Entry", "run", "(Llib/Service;Lbiz/DemoRepository;)I")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:spring-proxy:{version}", "blackbox:spring-proxy"),),
                entrypoint, frameworks=("spring_boot",),
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, overlay = public_pipeline(
                root / "spring-proxy-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            self.assert_targets_reachable(formal, truth["targets"])
            self.assertTrue(set(truth["required_semantic_kinds"]).issubset({
                row["semantic_edge_kind"] for row in overlay["rows"]
            }))
            forbidden = tuple(truth["forbidden_exact_wiring_target"])
            self.assertFalse(any(
                row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
                and (row["target_class_name"], row["target_member_name"])
                == forbidden
                and row["path_certainty"] == "exact"
                for row in overlay["rows"]
            ), overlay["rows"])

    def test_spring_aop_and_security_filter_dispatch_match_jvm_contracts(self):
        truth = TRUTH["cases"]["spring_aop_security"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def framework(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "org/aspectj/lang/annotation/Aspect.java": """
                        package org.aspectj.lang.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                        public @interface Aspect {}
                    """,
                    "org/aspectj/lang/annotation/Around.java": """
                        package org.aspectj.lang.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface Around { String value(); }
                    """,
                    "io/micrometer/observation/annotation/Observed.java": """
                        package io.micrometer.observation.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME)
                        @Target({ElementType.TYPE,ElementType.METHOD})
                        public @interface Observed {}
                    """,
                    "io/micrometer/observation/aop/ObservedAspect.java": """
                        package io.micrometer.observation.aop;
                        @org.aspectj.lang.annotation.Aspect
                        public class ObservedAspect {
                          @org.aspectj.lang.annotation.Around("@within(io.micrometer.observation.annotation.Observed) && !@annotation(io.micrometer.observation.annotation.Observed) && execution(* *.*(..))")
                          public void observeClass() {}
                        }
                    """,
                    "org/springframework/context/annotation/Bean.java": """
                        package org.springframework.context.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface Bean {}
                    """,
                    "jakarta/servlet/Filter.java": (
                        "package jakarta.servlet; public interface Filter { "
                        "void doFilter(); }"
                    ),
                    "org/springframework/security/web/SecurityFilterChain.java": (
                        "package org.springframework.security.web; "
                        "public interface SecurityFilterChain {}"
                    ),
                    "org/springframework/security/config/annotation/web/builders/HttpSecurity.java": """
                        package org.springframework.security.config.annotation.web.builders;
                        public class HttpSecurity {
                          public HttpSecurity addFilter(jakarta.servlet.Filter filter) { return this; }
                          public org.springframework.security.web.SecurityFilterChain build() { return null; }
                        }
                    """,
                    "lib/Api.java": (
                        "package lib; public class Api { public int changed() { "
                        f"return {digit}; }} }}"
                    ),
                    "lib/LibFilter.java": (
                        "package lib; public class LibFilter implements "
                        "jakarta.servlet.Filter { public void doFilter() { "
                        f"System.out.print({digit}); }} }}"
                    ),
                    "lib/UnregisteredFilter.java": (
                        "package lib; public class UnregisteredFilter implements "
                        "jakarta.servlet.Filter { public void doFilter() { "
                        f"System.out.print({digit}); }} }}"
                    ),
                }, self.javac)

            base = framework("aop-security-base", 1)
            current = framework("aop-security-current", 2)
            business = compile_jar(root, "aop-security-business", {
                "biz/Service.java": (
                    "package biz; public class Service { "
                    "public int work() { return 1; } }"
                ),
                "biz/ObservedService.java": """
                    package biz;
                    @io.micrometer.observation.annotation.Observed
                    public class ObservedService {
                      public void observed() {}
                      @io.micrometer.observation.annotation.Observed
                      public void suppressed() {}
                    }
                """,
                "biz/TracingAspect.java": """
                    package biz;
                    @org.aspectj.lang.annotation.Aspect
                    public class TracingAspect {
                      @org.aspectj.lang.annotation.Around("execution(* biz.Service.work(..))")
                      public int around() { return new lib.Api().changed(); }
                    }
                """,
                "biz/SecurityConfig.java": """
                    package biz;
                    public class SecurityConfig {
                      @org.springframework.context.annotation.Bean
                      public org.springframework.security.web.SecurityFilterChain chain(
                          org.springframework.security.config.annotation.web.builders.HttpSecurity http) {
                        return http.addFilter(new lib.LibFilter()).build();
                      }
                    }
                """,
                "biz/Entry.java": (
                    "package biz; public class Entry { public int run() { "
                    "return new Service().work(); } }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "aop-security-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        System.out.print(new lib.Api().changed());
                        new lib.LibFilter().doFilter();
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            observed_bytecode = execute([
                self.javap, "-classpath", str(business), "-v",
                "biz.ObservedService",
            ]).stdout
            self.assertIn("Observed;", observed_bytecode)
            self.assertGreaterEqual(
                observed_bytecode.count("RuntimeVisibleAnnotations:"), 2
            )

            entrypoint = ("biz/Entry", "run", "()I")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:aop-security:{version}", "blackbox:aop-security"),),
                entrypoint, frameworks=("spring_boot",),
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, overlay = public_pipeline(
                root / "aop-security-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            self.assert_targets_reachable(formal, truth["targets"])
            kinds = {row["semantic_edge_kind"] for row in overlay["rows"]}
            self.assertTrue(set(truth["required_semantic_kinds"]).issubset(kinds))
            observed_edges = sorted({
                (
                    row["caller_class_name"], row["caller_member_name"],
                    row["path_certainty"],
                )
                for row in overlay["rows"]
                if row["semantic_edge_kind"] == "spring_aop_dispatch"
                and row["target_class_name"]
                == "io/micrometer/observation/aop/ObservedAspect"
            })
            self.assertEqual(
                observed_edges,
                sorted(tuple(row) for row in truth["expected_observed_aspect_edges"]),
            )
            forbidden = tuple(truth["forbidden_observed_aspect_edge"])
            self.assertFalse(any(
                row["semantic_edge_kind"] == "spring_aop_dispatch"
                and (row["caller_class_name"], row["caller_member_name"])
                == forbidden
                and row["target_class_name"]
                == "io/micrometer/observation/aop/ObservedAspect"
                for row in overlay["rows"]
            ))
            forbidden_security = tuple(
                truth["forbidden_exact_security_target"]
            )
            self.assertFalse(any(
                row["semantic_edge_kind"] == "spring_security_filter_dispatch"
                and (row["target_class_name"], row["target_member_name"])
                == forbidden_security
                and row["path_certainty"] == "exact"
                for row in overlay["rows"]
            ), overlay["rows"])

    def test_message_listener_adapter_literal_callback_is_exact(self):
        truth = TRUTH["cases"]["spring_message_listener_adapter"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def target(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "target/Api.java": (
                        "package target; public class Api { public int value() { "
                        f"return {digit}; }} }}"
                    ),
                }, self.javac)

            base = target("listener-target-base", 1)
            current = target("listener-target-current", 2)
            business = compile_jar(root, "listener-business", {
                "org/springframework/context/annotation/Configuration.java": """
                    package org.springframework.context.annotation;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                    public @interface Configuration {}
                """,
                "org/springframework/context/annotation/Bean.java": """
                    package org.springframework.context.annotation;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                    public @interface Bean {}
                """,
                "org/springframework/amqp/rabbit/listener/adapter/MessageListenerAdapter.java": """
                    package org.springframework.amqp.rabbit.listener.adapter;
                    public class MessageListenerAdapter {
                      public MessageListenerAdapter(Object receiver, String method) {}
                    }
                """,
                "business/Receiver.java": """
                    package business;
                    public class Receiver {
                      public int receiveMessage(String body) {
                        return new target.Api().value();
                      }
                      public int unregistered(String body) {
                        return new target.Api().value();
                      }
                    }
                """,
                "business/Config.java": """
                    package business;
                    @org.springframework.context.annotation.Configuration
                    public class Config {
                      @org.springframework.context.annotation.Bean
                      public org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter listenerAdapter(Receiver receiver) {
                        return new org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter(receiver, "receiveMessage");
                      }
                    }
                """,
                "business/Main.java": (
                    "package business; public class Main { "
                    "public static void main(String[] args) {} }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "listener-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        System.out.print(new business.Receiver().receiveMessage("x"));
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            registration = execute([
                self.javap, "-classpath", str(business), "-c", "-v",
                "business.Config",
            ]).stdout
            self.assertIn("receiveMessage", registration)
            self.assertNotIn("unregistered", registration)

            entrypoint = ("business/Main", "main", "([Ljava/lang/String;)V")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:listener-target:{version}", "blackbox:listener-target"),),
                entrypoint, frameworks=("spring_boot",), auto_entrypoints=True,
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, _overlay = public_pipeline(
                root / "listener-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            target_row = next(
                row for row in formal["by_api"]
                if identity(row) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target_row[field], value, (field, target_row))
            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            expected_entry = truth["expected_entrypoint"]
            matches = [
                row for row in entries
                if all(row.get(field) == value for field, value in expected_entry.items())
            ]
            self.assertEqual(len(matches), 1, entries)
            forbidden = tuple(truth["forbidden_entrypoint"])
            self.assertFalse(any(
                (row["class_name"], row["member_name"], row["descriptor"])
                == forbidden
                for row in entries
            ))

    def test_jpa_entity_proof_separates_exact_and_possible_lifecycle_paths(self):
        truth = TRUTH["cases"]["jpa_lifecycle_activation"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def target(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "target/Api.java": (
                        "package target; public class Api { "
                        f"public int entityValue() {{ return {digit}; }} "
                        f"public int unprovedValue() {{ return {digit}; }} "
                        "public int stable() { return 7; } }"
                    ),
                }, self.javac)

            base = target("jpa-target-base", 1)
            current = target("jpa-target-current", 2)
            business = compile_jar(root, "jpa-business", {
                "jakarta/persistence/Entity.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                    public @interface Entity {}
                """,
                "jakarta/persistence/PostLoad.java": """
                    package jakarta.persistence;
                    import java.lang.annotation.*;
                    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                    public @interface PostLoad {}
                """,
                "business/EntityThing.java": """
                    package business;
                    @jakarta.persistence.Entity
                    public class EntityThing {
                      @jakarta.persistence.PostLoad
                      public int afterLoad() { return new target.Api().entityValue(); }
                    }
                """,
                "business/Unregistered.java": """
                    package business;
                    public class Unregistered {
                      @jakarta.persistence.PostLoad
                      public int afterLoad() { return new target.Api().unprovedValue(); }
                    }
                """,
                "business/Main.java": (
                    "package business; public class Main { "
                    "public static void main(String[] args) {} }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "jpa-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        System.out.print(new business.EntityThing().afterLoad());
                        System.out.print(new business.Unregistered().afterLoad());
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            for class_name in ("business.EntityThing", "business.Unregistered"):
                bytecode = execute([
                    self.javap, "-classpath", str(business), "-v", class_name,
                ]).stdout
                self.assertIn("PostLoad;", bytecode)
            entity_bytecode = execute([
                self.javap, "-classpath", str(business), "-v",
                "business.EntityThing",
            ]).stdout
            self.assertIn("Entity;", entity_bytecode)

            entrypoint = ("business/Main", "main", "([Ljava/lang/String;)V")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:jpa-target:{version}", "blackbox:jpa-target"),),
                entrypoint, frameworks=("spring_boot",), auto_entrypoints=True,
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, _overlay = public_pipeline(
                root / "jpa-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            by_identity = {identity(row): row for row in formal["by_api"]}
            for target_truth in truth["targets"]:
                row = by_identity[tuple(target_truth["identity"])]
                for field, value in target_truth["state"].items():
                    self.assertEqual(row[field], value, (field, row))
                self.assertTrue(any(
                    target_truth["required_path_marker"] in path["path_text"]
                    for path in row["paths"]
                ), row["paths"])

            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            for expected in truth["expected_entrypoints"]:
                matches = [
                    row for row in entries
                    if all(row.get(field) == value for field, value in expected.items())
                ]
                self.assertEqual(len(matches), 1, (expected, entries))

    def test_selected_spring_xml_init_scheduled_and_quartz_are_exact(self):
        truth = TRUTH["cases"]["spring_xml_quartz"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def dependency(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "org/springframework/scheduling/quartz/MethodInvokingJobDetailFactoryBean.java": """
                        package org.springframework.scheduling.quartz;
                        public class MethodInvokingJobDetailFactoryBean {}
                    """,
                    "vendor/ScheduledConfig.java": (
                        "package vendor; public class ScheduledConfig { "
                        f"public int initialize() {{ return {digit}; }} "
                        f"public int tick() {{ return {digit}; }} "
                        f"public int unregistered() {{ return {digit}; }} }}"
                    ),
                }, self.javac)

            base = dependency("xml-base", 1)
            current = dependency("xml-current", 2)
            business = compile_jar(root, "xml-business", {
                "business/Main.java": (
                    "package business; public class Main { "
                    "public static void main(String[] args) {} }"
                ),
            }, self.javac)
            xml = """
                <beans xmlns:task="urn:test">
                  <bean id="job" class="vendor.ScheduledConfig" init-method="initialize"/>
                  <bean id="quartz" class="org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean">
                    <property name="targetObject"><ref bean="job"/></property>
                    <property name="targetMethod"><value>tick</value></property>
                  </bean>
                  <task:scheduled-tasks>
                    <task:scheduled ref="job" method="tick"/>
                  </task:scheduled-tasks>
                </beans>
            """
            append_resources(business, {truth["resource_name"]: xml})
            oracle = compile_jar(root, "xml-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        vendor.ScheduledConfig value = new vendor.ScheduledConfig();
                        System.out.print(value.initialize());
                        System.out.print(value.tick());
                        System.out.print(value.unregistered());
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            with zipfile.ZipFile(business) as archive:
                observed_xml = archive.read(truth["resource_name"]).decode("utf-8")
            self.assertEqual(observed_xml.count('init-method="initialize"'), 1)
            self.assertEqual(observed_xml.count('method="tick"'), 1)
            self.assertEqual(observed_xml.count("<value>tick</value>"), 1)
            self.assertNotIn("unregistered", observed_xml)

            entrypoint = ("business/Main", "main", "([Ljava/lang/String;)V")
            resource = f"classpath:{truth['resource_name']}"
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:xml:{version}", "blackbox:xml"),),
                entrypoint, frameworks=("spring_boot",), resources=(resource,),
                auto_entrypoints=True,
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, _overlay = public_pipeline(
                root / "xml-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            by_identity = {identity(row): row for row in formal["by_api"]}
            for expected in truth["targets"]:
                row = by_identity[tuple(expected["identity"])]
                self.assertEqual(
                    row["reachability_status"], expected["reachability_status"]
                )
                self.assertEqual(
                    row["exact_path_exists"], expected["exact_path_exists"]
                )
            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            actual_entries = {
                (
                    row["class_name"], row["member_name"], row["entry_kind"],
                    row["path_certainty"],
                )
                for row in entries
                if row["class_name"] == "vendor/ScheduledConfig"
            }
            self.assertTrue({
                tuple(expected) for expected in truth["expected_entrypoints"]
            }.issubset(actual_entries), actual_entries)
            forbidden = tuple(truth["forbidden_entrypoint"])
            self.assertFalse(any(
                (row["class_name"], row["member_name"]) == forbidden
                for row in entries
            ))

    def test_interface_callbacks_and_spring_factories_activation_are_distinct(self):
        truth = TRUTH["cases"]["spring_interface_and_factories"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def dependency(label: str, digit: int) -> Path:
                jar = compile_jar(root, label, {
                    "org/springframework/boot/ApplicationArguments.java": (
                        "package org.springframework.boot; "
                        "public interface ApplicationArguments {}"
                    ),
                    "org/springframework/boot/ApplicationRunner.java": (
                        "package org.springframework.boot; public interface "
                        "ApplicationRunner { void run(ApplicationArguments args); }"
                    ),
                    "org/springframework/context/Lifecycle.java": (
                        "package org.springframework.context; public interface "
                        "Lifecycle { void start(); void stop(); boolean isRunning(); }"
                    ),
                    "org/springframework/context/ApplicationListener.java": (
                        "package org.springframework.context; public interface "
                        "ApplicationListener<E> { void onApplicationEvent(E event); }"
                    ),
                    "org/quartz/JobExecutionContext.java": (
                        "package org.quartz; public interface JobExecutionContext {}"
                    ),
                    "org/quartz/Job.java": (
                        "package org.quartz; public interface Job { "
                        "void execute(JobExecutionContext context); }"
                    ),
                    "target/Api.java": (
                        "package target; public class Api { "
                        f"public int runnerValue() {{ return {digit}; }} "
                        f"public int lifecycleValue() {{ return {digit}; }} "
                        f"public int quartzValue() {{ return {digit}; }} "
                        f"public int factoryValue() {{ return {digit}; }} "
                        f"public int unregisteredValue() {{ return {digit}; }} }}"
                    ),
                    "vendor/RegisteredListener.java": """
                        package vendor;
                        public class RegisteredListener implements org.springframework.context.ApplicationListener<Object> {
                          public void onApplicationEvent(Object event) {
                            System.out.print(new target.Api().factoryValue());
                          }
                        }
                    """,
                    "vendor/UnregisteredListener.java": """
                        package vendor;
                        public class UnregisteredListener implements org.springframework.context.ApplicationListener<Object> {
                          public void onApplicationEvent(Object event) {
                            System.out.print(new target.Api().unregisteredValue());
                          }
                        }
                    """,
                }, self.javac)
                append_resources(jar, {
                    truth["service_resource"]: (
                        "org.springframework.context.ApplicationListener="
                        "vendor.RegisteredListener"
                    ),
                })
                return jar

            base = dependency("interface-base", 1)
            current = dependency("interface-current", 2)
            business = compile_jar(root, "interface-business", {
                "business/Callbacks.java": """
                    package business;
                    public class Callbacks implements
                        org.springframework.boot.ApplicationRunner,
                        org.springframework.context.Lifecycle,
                        org.quartz.Job {
                      public void run(org.springframework.boot.ApplicationArguments args) {
                        System.out.print(new target.Api().runnerValue());
                      }
                      public void start() {
                        System.out.print(new target.Api().lifecycleValue());
                      }
                      public void stop() {}
                      public boolean isRunning() { return true; }
                      public void execute(org.quartz.JobExecutionContext context) {
                        System.out.print(new target.Api().quartzValue());
                      }
                    }
                """,
                "business/Main.java": (
                    "package business; public class Main { "
                    "public static void main(String[] args) {} }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "interface-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        business.Callbacks callbacks = new business.Callbacks();
                        callbacks.run(null);
                        callbacks.start();
                        callbacks.execute(null);
                        new vendor.RegisteredListener().onApplicationEvent(null);
                        new vendor.UnregisteredListener().onApplicationEvent(null);
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            callback_contract = execute([
                self.javap, "-classpath", os.pathsep.join((str(business), str(base))),
                "-v", "business.Callbacks",
            ]).stdout
            for interface_name in (
                "org/springframework/boot/ApplicationRunner",
                "org/springframework/context/Lifecycle",
                "org/quartz/Job",
            ):
                self.assertIn(interface_name, callback_contract)
            with zipfile.ZipFile(base) as archive:
                registrations = archive.read(
                    truth["service_resource"]
                ).decode("utf-8")
            self.assertIn("vendor.RegisteredListener", registrations)
            self.assertNotIn("vendor.UnregisteredListener", registrations)

            entrypoint = ("business/Main", "main", "([Ljava/lang/String;)V")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:interface:{version}", "blackbox:interface"),),
                entrypoint, frameworks=("spring_boot",), auto_entrypoints=True,
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, _overlay = public_pipeline(
                root / "interface-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            by_member = {
                row["display_member"]: row
                for row in formal["by_api"]
                if row["display_owner"] == "target/Api"
            }
            for member, status, exact, possible in truth["targets"]:
                row = by_member[member]
                self.assertEqual(row["reachability_status"], status, row)
                self.assertEqual(row["exact_path_exists"], exact, row)
                self.assertEqual(row["possible_path_exists"], possible, row)

            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            actual = {
                (
                    row["class_name"], row["member_name"], row["entry_kind"],
                    row["path_certainty"], row["activation_reason"],
                )
                for row in entries
            }
            self.assertTrue({
                tuple(row) for row in truth["expected_entrypoints"]
            }.issubset(actual), actual)

    def test_transitive_spring_import_activates_only_imported_dependency(self):
        truth = TRUTH["cases"]["spring_transitive_import"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def dependency(label: str, digit: int) -> Path:
                return compile_jar(root, label, {
                    "org/springframework/context/annotation/Import.java": """
                        package org.springframework.context.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE)
                        public @interface Import { Class<?>[] value(); }
                    """,
                    "org/springframework/scheduling/annotation/Scheduled.java": """
                        package org.springframework.scheduling.annotation;
                        import java.lang.annotation.*;
                        @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
                        public @interface Scheduled {}
                    """,
                    "api/Api.java": (
                        "package api; public class Api { "
                        f"public int importedValue() {{ return {digit}; }} "
                        f"public int unimportedValue() {{ return {digit}; }} }}"
                    ),
                    "vendor/ImportedConfig.java": """
                        package vendor;
                        public class ImportedConfig {
                          @org.springframework.scheduling.annotation.Scheduled
                          public int tick() { return new api.Api().importedValue(); }
                        }
                    """,
                    "vendor/UnimportedConfig.java": """
                        package vendor;
                        public class UnimportedConfig {
                          @org.springframework.scheduling.annotation.Scheduled
                          public int tick() { return new api.Api().unimportedValue(); }
                        }
                    """,
                }, self.javac)

            base = dependency("import-base", 1)
            current = dependency("import-current", 2)
            business = compile_jar(root, "import-business", {
                "business/RootConfig.java": """
                    package business;
                    @org.springframework.context.annotation.Import(business.MiddleConfig.class)
                    public class RootConfig {}
                """,
                "business/MiddleConfig.java": """
                    package business;
                    @org.springframework.context.annotation.Import(vendor.ImportedConfig.class)
                    public class MiddleConfig {}
                """,
                "business/Main.java": (
                    "package business; public class Main { "
                    "public static void main(String[] args) {} }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "import-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) {
                        System.out.print(new vendor.ImportedConfig().tick());
                        System.out.print(new vendor.UnimportedConfig().tick());
                      }
                    }
                """,
            }, self.javac, classpath=(business, base))
            self.assertEqual(
                self.run_main(oracle, business, (base,)),
                truth["expected_base_stdout"],
            )
            self.assertEqual(
                self.run_main(oracle, business, (current,)),
                truth["expected_current_stdout"],
            )
            for class_name, imported_name in (
                ("business.RootConfig", "business/MiddleConfig"),
                ("business.MiddleConfig", "vendor/ImportedConfig"),
            ):
                bytecode = execute([
                    self.javap, "-classpath", os.pathsep.join((str(business), str(base))),
                    "-v", class_name,
                ]).stdout
                self.assertIn("Import;", bytecode)
                self.assertIn(imported_name, bytecode)
            self.assertNotIn(
                "vendor/UnimportedConfig",
                execute([
                    self.javap, "-classpath", os.pathsep.join((str(business), str(base))),
                    "-v", "business.MiddleConfig",
                ]).stdout,
            )

            entrypoint = ("business/Main", "main", "([Ljava/lang/String;)V")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:import:{version}", "blackbox:import"),),
                entrypoint, frameworks=("spring_boot",), auto_entrypoints=True,
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, _overlay = public_pipeline(
                root / "import-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            by_member = {
                row["display_member"]: row
                for row in formal["by_api"]
                if row["display_owner"] == "api/Api"
            }
            for member, status, exact, possible in truth["targets"]:
                row = by_member[member]
                self.assertEqual(row["reachability_status"], status, row)
                self.assertEqual(row["exact_path_exists"], exact, row)
                self.assertEqual(row["possible_path_exists"], possible, row)
            entries = json.loads((
                Path(result["generation_directory"]) / "binary_entrypoints.json"
            ).read_text(encoding="utf-8"))["records"]
            actual = {
                (
                    row["class_name"], row["member_name"], row["entry_kind"],
                    row["path_certainty"], row["activation_reason"],
                )
                for row in entries
            }
            self.assertTrue({
                tuple(row) for row in truth["expected_entrypoints"]
            }.issubset(actual), actual)

    def test_http_dubbo_and_service_loader_registrations(self):
        truth = TRUTH["cases"]["http_dubbo_service"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def framework(label: str, digit: int, provider: str) -> Path:
                jar = compile_jar(root, label, {
                    "org/springframework/cloud/openfeign/FeignClient.java": "package org.springframework.cloud.openfeign; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) public @interface FeignClient { String value(); }",
                    "feign/SynchronousMethodHandler.java": (
                        "package feign; public class SynchronousMethodHandler { "
                        f"public Object invoke(Object[] args) {{ return Integer.valueOf({digit}); }} }}"
                    ),
                    "org/apache/dubbo/common/extension/ExtensionLoader.java": "package org.apache.dubbo.common.extension; public class ExtensionLoader { public Object getExtension(String name){return null;} }",
                    "demo/DubboService.java": "package demo; public interface DubboService { int execute(); }",
                    "demo/Provider.java": (
                        "package demo; public class Provider implements DubboService { "
                        f"public int execute() {{ return {digit}; }} }}"
                    ),
                    "demo/Alternate.java": "package demo; public class Alternate implements DubboService { public int execute(){return 9;} }",
                    "demo/Unregistered.java": (
                        "package demo; public class Unregistered implements DubboService { "
                        f"public int execute(){{return {digit};}} }}"
                    ),
                }, self.javac)
                append_resources(jar, {
                    "META-INF/dubbo/demo.DubboService": "fast=demo.Provider",
                    truth["service_resource"]: provider,
                })
                return jar

            base = framework("http-dubbo-base", 1, "demo.Provider")
            current = framework("http-dubbo-current", 2, "demo.Alternate")
            business = compile_jar(root, "http-dubbo-business", {
                "biz/RemoteClient.java": "package biz; @org.springframework.cloud.openfeign.FeignClient(\"remote\") public interface RemoteClient { int call(); }",
                "biz/Entry.java": "package biz; public class Entry { public int run(RemoteClient client){ org.apache.dubbo.common.extension.ExtensionLoader loader=new org.apache.dubbo.common.extension.ExtensionLoader(); demo.DubboService service=(demo.DubboService)loader.getExtension(\"fast\"); java.util.ServiceLoader.load(demo.DubboService.class); return client.call()+service.execute(); } }",
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "http-dubbo-oracle", {
                "oracle/Main.java": "package oracle; public class Main { public static void main(String[] args){ Object http=new feign.SynchronousMethodHandler().invoke(null); int spi=new demo.Provider().execute(); System.out.print(http.toString()+spi); } }",
            }, self.javac, classpath=(business, base))
            self.assertEqual(self.run_main(oracle, business, (base,)), truth["expected_base_stdout"])
            self.assertEqual(self.run_main(oracle, business, (current,)), truth["expected_current_stdout"])
            with zipfile.ZipFile(base) as archive:
                self.assertEqual(
                    archive.read("META-INF/dubbo/demo.DubboService").decode("utf-8"),
                    "fast=demo.Provider\n",
                )
                self.assertEqual(
                    archive.read(truth["service_resource"]).decode("utf-8"),
                    "demo.Provider\n",
                )

            entrypoint = ("biz/Entry", "run", "(Lbiz/RemoteClient;)I")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:dispatch:{version}", "blackbox:dispatch"),),
                entrypoint, frameworks=("spring_boot",),
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, overlay = public_pipeline(
                root / "http-dubbo-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            self.assert_targets_reachable(formal, truth["targets"])
            self.assertTrue(set(truth["required_semantic_kinds"]).issubset({
                row["semantic_edge_kind"] for row in overlay["rows"]
            }))
            service_results = formal["resource_activation_results"]
            matching = [
                row for row in service_results
                if row["resource_name"] == truth["service_resource"]
            ]
            self.assertEqual(len(matching), 1, service_results)
            self.assertEqual(
                matching[0]["activation_status"],
                truth["service_activation_status"],
            )
            forbidden = tuple(truth["forbidden_exact_provider_target"])
            self.assertFalse(any(
                row["semantic_edge_kind"] == "dubbo_spi_dispatch"
                and (row["target_class_name"], row["target_member_name"])
                == forbidden
                and row["path_certainty"] == "exact"
                for row in overlay["rows"]
            ), overlay["rows"])

    def test_java_main_and_declared_runtime_entrypoints_are_independent_roots(self):
        truth = TRUTH["cases"]["java_and_declared_entrypoints"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def api(label: str, main_value: int, declared_value: int) -> Path:
                return compile_jar(root, label, {
                    "api/Api.java": (
                        "package api; public class Api { "
                        f"public static int fromMain(){{return {main_value};}} "
                        f"public static int fromDeclared(){{return {declared_value};}}"
                        "}"
                    ),
                }, self.javac)

            base = api("entrypoints-base", 1, 10)
            current = api("entrypoints-current", 2, 20)
            business = compile_jar(root, "entrypoints-business", {
                "biz/Main.java": (
                    "package biz; public class Main { public static void main(String[] a){"
                    "System.out.print(api.Api.fromMain());} }"
                ),
                "biz/Declared.java": (
                    "package biz; public class Declared { "
                    "public int run(){return api.Api.fromDeclared();} }"
                ),
            }, self.javac, classpath=(base,))
            oracle = compile_jar(root, "entrypoints-oracle", {
                "oracle/DeclaredMain.java": (
                    "package oracle; public class DeclaredMain { public static void main(String[] a){"
                    "System.out.print(new biz.Declared().run());} }"
                ),
            }, self.javac, classpath=(business, base))

            for jar, version in ((base, "base"), (current, "current")):
                self.assertEqual(
                    execute([
                        self.java, "-cp", os.pathsep.join(map(str, (business, jar))),
                        "biz.Main",
                    ]).stdout,
                    truth["expected_main_stdout"][version],
                )
                self.assertEqual(
                    execute([
                        self.java, "-cp", os.pathsep.join(map(str, (oracle, business, jar))),
                        "oracle.DeclaredMain",
                    ]).stdout,
                    truth["expected_declared_stdout"][version],
                )
            javap = execute([
                self.javap, "-classpath", str(business), "-c", "biz.Main", "biz.Declared",
            ]).stdout
            self.assertIn("api/Api.fromMain:()I", javap)
            self.assertIn("api/Api.fromDeclared:()I", javap)

            def sides(entrypoint: tuple[str, str, str], *, automatic: bool) -> list[dict]:
                values = [side_with_artifacts(
                    self.home, business,
                    ((jar, f"blackbox:entrypoints:{version}", "blackbox:entrypoints"),),
                    entrypoint, auto_entrypoints=automatic,
                ) for jar, version in ((base, "1"), (current, "2"))]
                if automatic:
                    for value in values:
                        value["runtime_profile"]["business_entrypoint_profile"]["methods"] = []
                return values

            observations = (
                (
                    "automatic-main",
                    sides(("biz/Main", "main", "([Ljava/lang/String;)V"), automatic=True),
                    truth["main_target"], truth["declared_target"],
                    truth["unselected_declared_target_state"],
                    truth["main_entrypoint"],
                ),
                (
                    "declared-runtime",
                    sides(("biz/Declared", "run", "()I"), automatic=False),
                    truth["declared_target"], truth["main_target"],
                    truth["unselected_main_target_state"],
                    truth["declared_entrypoint"],
                ),
            )
            for (
                label, runtime_sides, selected, unselected,
                unselected_state, expected_entry,
            ) in observations:
                with self.subTest(mode=label):
                    result, formal, _overlay = public_pipeline(
                        root / label, config(*runtime_sides)
                    )
                    self.assertEqual(result["validation_status"], "passed")
                    by_identity = {identity(row): row for row in formal["by_api"]}
                    for field, value in truth["selected_target_state"].items():
                        self.assertEqual(by_identity[tuple(selected)][field], value)
                    for field, value in unselected_state.items():
                        self.assertEqual(by_identity[tuple(unselected)][field], value)
                    entrypoints = json.loads((
                        Path(result["generation_directory"]) / "binary_entrypoints.json"
                    ).read_text(encoding="utf-8"))["records"]
                    actual = {
                        (
                            row["class_name"], row["member_name"], row["entry_kind"],
                            row["path_certainty"], row["activation_reason"],
                        )
                        for row in entrypoints
                    }
                    self.assertIn(tuple(expected_entry), actual)

    def test_web_binding_keeps_removed_field_as_implicit_contract(self):
        truth = TRUTH["cases"]["implicit_data_contract"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "dto-base", {
                "lib/Dto.java": "package lib; public class Dto { public String removed; public String retained; }",
            }, self.javac)
            current = compile_jar(root, "dto-current", {
                "lib/Dto.java": "package lib; public class Dto { public String retained; }",
            }, self.javac)
            business = compile_jar(root, "dto-business", {
                "org/springframework/web/bind/annotation/GetMapping.java": "package org.springframework.web.bind.annotation; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface GetMapping {}",
                "biz/Controller.java": "package biz; public class Controller { @org.springframework.web.bind.annotation.GetMapping public lib.Dto endpoint(lib.Dto request){return request;} }",
            }, self.javac, classpath=(base,))
            base_contract = execute([
                self.javap, "-classpath", str(base), "-public", "-s", "lib.Dto",
            ]).stdout
            current_contract = execute([
                self.javap, "-classpath", str(current), "-public", "-s", "lib.Dto",
            ]).stdout
            self.assertIn("removed;", base_contract)
            self.assertNotIn("removed;", current_contract)

            entrypoint = ("biz/Controller", "endpoint", "(Llib/Dto;)Llib/Dto;")
            sides = [side_with_artifacts(
                self.home, business,
                ((jar, f"blackbox:dto:{version}", "blackbox:dto"),),
                entrypoint, frameworks=("spring_boot",),
            ) for jar, version in ((base, "1"), (current, "2"))]
            result, formal, overlay = public_pipeline(
                root / "dto-report", config(*sides)
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if identity(row) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            self.assertTrue(any(
                row["semantic_edge_kind"] == truth["semantic_edge_kind"]
                and row["target_class_name"] == "lib/Dto"
                and row["target_member_name"] == "removed"
                and row["path_certainty"] == "exact"
                for row in overlay["rows"]
            ))


if __name__ == "__main__":
    unittest.main()
