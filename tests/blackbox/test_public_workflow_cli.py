import csv
import hashlib
import io
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
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "step1_public_contract_v1.json"
).read_text(encoding="utf-8"))
STEP0_SOURCE_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "step0_source_inputs_v1.json"
).read_text(encoding="utf-8"))
FULL_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "full_public_workflow_v1.json"
).read_text(encoding="utf-8"))
STEP3_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "step3_public_scans_v1.json"
).read_text(encoding="utf-8"))
WAR_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "war_public_workflow_v1.json"
).read_text(encoding="utf-8"))
STEP4_SCOPE_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "step4_scope_v1.json"
).read_text(encoding="utf-8"))
REPORT_BOUNDED_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "workflow_blackbox"
    / "report_bounded_detail_v1.json"
).read_text(encoding="utf-8"))


def run_workflow(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_step.py"), *arguments],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=240,
    )


def confirmation_event(stdout: str) -> dict:
    prefix = "JUA_CONFIRMATION_JSON:"
    matches = [
        line[len(prefix):]
        for line in stdout.splitlines()
        if line.startswith(prefix)
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one confirmation event, got {len(matches)}")
    return json.loads(matches[0])


def nested_maven_jar(version: str) -> bytes:
    """Build a standard JAR without importing any analyzer implementation."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "META-INF/maven/org.example/demo-lib/pom.properties",
            "groupId=org.example\nartifactId=demo-lib\n"
            f"version={version}\n",
        )
        archive.writestr("org/example/Demo.class", b"independent-fixture-class")
    return buffer.getvalue()


def write_boot_artifact(path: Path, version: str) -> bytes:
    nested = nested_maven_jar(version)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BOOT-INF/classes/example/Application.class", b"business")
        archive.writestr(f"BOOT-INF/lib/demo-lib-{version}.jar", nested)
    return nested


def read_csv_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def run_external(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"external command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout={completed.stdout[-2000:]}\nstderr={completed.stderr[-2000:]}"
        )
    return completed


def full_jdk_home(java: str) -> Path:
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
        if "java.home" not in line or "=" not in line:
            continue
        candidate = Path(line.split("=", 1)[1].strip()).resolve()
        if candidate.is_dir() and (candidate / "jmods").is_dir():
            return candidate
    raise AssertionError("a full JDK home with jmods is required")


def jdk_major_from_home(home: Path) -> str:
    release = home / "release"
    if not release.is_file():
        return ""
    for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("JAVA_VERSION="):
            continue
        version = line.split("=", 1)[1].strip().strip('"')
        if version.startswith("1."):
            return version.split(".", 2)[1]
        return version.split(".", 1)[0]
    return ""


def find_full_jdk_home(java: str, major: int) -> Path | None:
    """Find a real version-matched JDK; never relabel another JDK for a test."""
    candidates: list[Path] = []
    for name in (
        f"JAVA{major}_HOME",
        f"JAVA_{major}_HOME",
        f"JDK{major}_HOME",
        f"JDK_{major}_HOME",
        "JAVA_HOME",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            candidates.append(Path(value).expanduser())
    try:
        candidates.append(full_jdk_home(java))
    except AssertionError:
        pass
    for root, suffix in (
        (Path("/Library/Java/JavaVirtualMachines"), "Contents/Home"),
        (Path("/usr/lib/jvm"), ""),
        (Path("C:/Program Files/Java"), ""),
        (Path("C:/Program Files/Eclipse Adoptium"), ""),
        (Path.home() / ".pkgx" / "openjdk.org", ""),
        (Path.home() / ".local" / "pkgs" / "openjdk.org", ""),
    ):
        if root.is_dir():
            candidates.extend(
                child / suffix if suffix else child
                for child in sorted(root.iterdir())
            )
    java_home_tool = Path("/usr/libexec/java_home")
    if java_home_tool.is_file():
        completed = subprocess.run(
            [str(java_home_tool), "-v", "1.8" if major == 8 else str(major)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            candidates.append(Path(completed.stdout.strip()))
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        identity = os.path.normcase(str(resolved))
        if identity in seen:
            continue
        seen.add(identity)
        java_name = "java.exe" if os.name == "nt" else "java"
        javac_name = "javac.exe" if os.name == "nt" else "javac"
        if (
            jdk_major_from_home(resolved) == str(major)
            and (resolved / "bin" / java_name).is_file()
            and (resolved / "bin" / javac_name).is_file()
        ):
            return resolved
    return None


def write_java(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def compile_java(
    javac: str,
    source_root: Path,
    output: Path,
    *,
    release: int,
    classpath: tuple[Path, ...] = (),
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(path) for path in source_root.rglob("*.java"))
    command = [javac, "-g:none", "--release", str(release)]
    if classpath:
        command.extend(["-classpath", os.pathsep.join(map(str, classpath))])
    run_external([*command, "-d", str(output), *sources])


def jar_bytes(classes: Path, *, version: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted(classes.rglob("*.class")):
            archive.writestr(
                class_file.relative_to(classes).as_posix(),
                class_file.read_bytes(),
            )
        archive.writestr(
            "META-INF/maven/org.example/demo-lib/pom.properties",
            "groupId=org.example\nartifactId=demo-lib\n"
            f"version={version}\n",
        )
    return buffer.getvalue()


def dependency_jar_bytes(
    classes: Path | None,
    *,
    group: str,
    artifact: str,
    version: str,
    resources: dict[str, str] | None = None,
) -> bytes:
    """Author a standard dependency JAR with independently inspectable metadata."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        if classes is not None:
            for class_file in sorted(classes.rglob("*.class")):
                archive.writestr(
                    class_file.relative_to(classes).as_posix(),
                    class_file.read_bytes(),
                )
        archive.writestr(
            f"META-INF/maven/{group}/{artifact}/pom.properties",
            f"groupId={group}\nartifactId={artifact}\nversion={version}\n",
        )
        for name, content in sorted((resources or {}).items()):
            archive.writestr(name, content.strip() + "\n")
    return buffer.getvalue()


def write_boot_artifact_with_dependencies(
    target: Path,
    business_classes: Path,
    dependencies: tuple[tuple[str, bytes], ...],
) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\r\n"
            "Main-Class: org.springframework.boot.loader.launch.JarLauncher\r\n"
            "Start-Class: example.Application\r\n\r\n",
        )
        for class_file in sorted(business_classes.rglob("*.class")):
            archive.writestr(
                "BOOT-INF/classes/"
                + class_file.relative_to(business_classes).as_posix(),
                class_file.read_bytes(),
            )
        for filename, content in dependencies:
            archive.writestr(f"BOOT-INF/lib/{filename}", content)


def write_compiled_boot_artifact(
    target: Path, business_classes: Path, dependency: bytes, *, version: str,
) -> None:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\r\n"
            "Main-Class: org.springframework.boot.loader.launch.JarLauncher\r\n"
            "Start-Class: example.Application\r\n\r\n",
        )
        for class_file in sorted(business_classes.rglob("*.class")):
            archive.writestr(
                "BOOT-INF/classes/"
                + class_file.relative_to(business_classes).as_posix(),
                class_file.read_bytes(),
            )
        archive.writestr(f"BOOT-INF/lib/demo-lib-{version}.jar", dependency)


def build_full_workflow_artifacts(root: Path, javac: str) -> dict[str, Path]:
    source = root / "compiled-source"
    write_java(
        source / "base" / "demo" / "Api.java",
        """
        package demo;
        public final class Api {
            public static String removed() { return "base"; }
            public static String stable() { return "stable"; }
        }
        """,
    )
    write_java(
        source / "current" / "demo" / "Api.java",
        """
        package demo;
        public final class Api {
            public static String stable() { return "stable"; }
        }
        """,
    )
    write_java(
        source / "business" / "example" / "Application.java",
        """
        package example;
        public final class Application {
            public static void main(String[] args) {
                System.out.print(demo.Api.removed());
            }
        }
        """,
    )
    classes = root / "compiled-classes"
    compile_java(javac, source / "base", classes / "base-lib", release=8)
    compile_java(javac, source / "current", classes / "current-lib", release=8)
    compile_java(
        javac,
        source / "business",
        classes / "base-business",
        release=8,
        classpath=(classes / "base-lib",),
    )
    compile_java(
        javac,
        source / "business",
        classes / "current-business",
        release=8,
        classpath=(classes / "base-lib",),
    )
    base_dependency = jar_bytes(classes / "base-lib", version="1.0.0")
    current_dependency = jar_bytes(classes / "current-lib", version="2.0.0")
    base = root / "base-app.jar"
    current = root / "current-app.jar"
    write_compiled_boot_artifact(
        base, classes / "base-business", base_dependency, version="1.0.0"
    )
    write_compiled_boot_artifact(
        current,
        classes / "current-business",
        current_dependency,
        version="2.0.0",
    )
    business_jar = root / "business.jar"
    with zipfile.ZipFile(business_jar, "w", zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted((classes / "current-business").rglob("*.class")):
            archive.writestr(
                class_file.relative_to(classes / "current-business").as_posix(),
                class_file.read_bytes(),
            )
    base_lib = root / "base-lib.jar"
    current_lib = root / "current-lib.jar"
    base_lib.write_bytes(base_dependency)
    current_lib.write_bytes(current_dependency)
    return {
        "base": base,
        "current": current,
        "base_library": base_lib,
        "current_library": current_lib,
        "business": business_jar,
    }


def build_bounded_report_artifacts(
    root: Path, javac: str, *, method_count: int,
) -> dict[str, Path]:
    """Build more closed-set API changes than the public report display cap."""
    source = root / "bounded-report-source"
    methods = "\n".join(
        f"public static int m{index:02d}() {{ return {index}; }}"
        for index in range(method_count)
    )
    calls = " + ".join(
        f"demo.Api.m{index:02d}()" for index in range(method_count)
    )
    write_java(
        source / "base" / "demo" / "Api.java",
        f"package demo; public final class Api {{ {methods} }}",
    )
    write_java(
        source / "current" / "demo" / "Api.java",
        "package demo; public final class Api {}",
    )
    write_java(
        source / "business" / "example" / "Application.java",
        "package example; public final class Application { "
        f"public static int sum() {{ return {calls}; }} "
        "public static void main(String[] args) { System.out.print(sum()); } }",
    )
    classes = root / "bounded-report-classes"
    compile_java(javac, source / "base", classes / "base-lib", release=8)
    compile_java(javac, source / "current", classes / "current-lib", release=8)
    compile_java(
        javac, source / "business", classes / "business", release=8,
        classpath=(classes / "base-lib",),
    )
    base_dependency = jar_bytes(classes / "base-lib", version="1.0.0")
    current_dependency = jar_bytes(classes / "current-lib", version="2.0.0")
    base = root / "bounded-base-app.jar"
    current = root / "bounded-current-app.jar"
    write_compiled_boot_artifact(
        base, classes / "business", base_dependency, version="1.0.0"
    )
    write_compiled_boot_artifact(
        current, classes / "business", current_dependency, version="2.0.0"
    )
    business = root / "bounded-business.jar"
    with zipfile.ZipFile(business, "w", zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted((classes / "business").rglob("*.class")):
            archive.writestr(
                class_file.relative_to(classes / "business").as_posix(),
                class_file.read_bytes(),
            )
    base_library = root / "bounded-base-lib.jar"
    current_library = root / "bounded-current-lib.jar"
    base_library.write_bytes(base_dependency)
    current_library.write_bytes(current_dependency)
    return {
        "base": base,
        "current": current,
        "base_library": base_library,
        "current_library": current_library,
        "business": business,
    }


def build_two_dependency_workflow_artifacts(
    root: Path, javac: str,
) -> dict[str, Path]:
    source = root / "two-dependency-source"
    specifications = (
        (
            "demo", "Api", "removed", "demo-lib",
            "package demo; public final class Api { "
            "public static String removed(){ return \"D\"; } }",
            "package demo; public final class Api {}",
        ),
        (
            "other", "Other", "gone", "other-lib",
            "package other; public final class Other { "
            "public static String gone(){ return \"O\"; } }",
            "package other; public final class Other {}",
        ),
    )
    classes = root / "two-dependency-classes"
    dependencies: dict[str, dict[str, Path | bytes]] = {}
    for package, class_name, _method, artifact, base_text, current_text in specifications:
        base_source = source / artifact / "base" / package / f"{class_name}.java"
        current_source = source / artifact / "current" / package / f"{class_name}.java"
        write_java(base_source, base_text)
        write_java(current_source, current_text)
        base_classes = classes / artifact / "base"
        current_classes = classes / artifact / "current"
        compile_java(javac, base_source.parents[1], base_classes, release=8)
        compile_java(javac, current_source.parents[1], current_classes, release=8)
        dependencies[artifact] = {
            "base": dependency_jar_bytes(
                base_classes,
                group="org.example", artifact=artifact, version="1.0.0",
            ),
            "current": dependency_jar_bytes(
                current_classes,
                group="org.example", artifact=artifact, version="2.0.0",
            ),
            "base_path": root / f"{artifact}-base.jar",
            "current_path": root / f"{artifact}-current.jar",
        }
        dependencies[artifact]["base_path"].write_bytes(
            dependencies[artifact]["base"]
        )
        dependencies[artifact]["current_path"].write_bytes(
            dependencies[artifact]["current"]
        )

    business_source = source / "business" / "example" / "Application.java"
    write_java(
        business_source,
        """
        package example;
        public final class Application {
          public static String demo(){ return demo.Api.removed(); }
          public static String other(){ return other.Other.gone(); }
          public static void main(String[] args) {
            System.out.print(args.length == 0 || args[0].equals("demo")
              ? demo() : other());
          }
        }
        """,
    )
    business_classes = classes / "business"
    compile_java(
        javac, business_source.parents[1], business_classes, release=8,
        classpath=tuple(
            dependencies[name]["base_path"] for name in ("demo-lib", "other-lib")
        ),
    )
    base = root / "two-base-app.jar"
    current = root / "two-current-app.jar"
    write_boot_artifact_with_dependencies(
        base,
        business_classes,
        tuple(
            (f"{name}-1.0.0.jar", dependencies[name]["base"])
            for name in ("demo-lib", "other-lib")
        ),
    )
    write_boot_artifact_with_dependencies(
        current,
        business_classes,
        tuple(
            (f"{name}-2.0.0.jar", dependencies[name]["current"])
            for name in ("demo-lib", "other-lib")
        ),
    )
    business = root / "two-business.jar"
    with zipfile.ZipFile(business, "w", zipfile.ZIP_DEFLATED) as archive:
        for class_file in sorted(business_classes.rglob("*.class")):
            archive.writestr(
                class_file.relative_to(business_classes).as_posix(),
                class_file.read_bytes(),
            )
    return {
        "base": base,
        "current": current,
        "business": business,
        "demo_base": dependencies["demo-lib"]["base_path"],
        "demo_current": dependencies["demo-lib"]["current_path"],
        "other_base": dependencies["other-lib"]["base_path"],
        "other_current": dependencies["other-lib"]["current_path"],
    }


def convert_boot_jar_to_war(source: Path, target: Path) -> None:
    with zipfile.ZipFile(source) as source_archive:
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as target_archive:
            target_archive.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\n"
                "Main-Class: org.springframework.boot.loader.launch.WarLauncher\r\n"
                "Start-Class: example.Application\r\n\r\n",
            )
            for info in source_archive.infolist():
                if info.filename.startswith("BOOT-INF/classes/"):
                    name = "WEB-INF/classes/" + info.filename.removeprefix(
                        "BOOT-INF/classes/"
                    )
                elif info.filename.startswith("BOOT-INF/lib/"):
                    name = "WEB-INF/lib/" + info.filename.removeprefix(
                        "BOOT-INF/lib/"
                    )
                else:
                    continue
                target_archive.writestr(name, source_archive.read(info))


def build_step3_workflow_artifacts(root: Path, javac: str) -> dict[str, Path]:
    source = root / "step3-compiled-source"
    write_java(
        source / "base" / "demo" / "Api.java",
        "package demo; public final class Api { public static void removed() {} }",
    )
    write_java(
        source / "current" / "demo" / "Api.java",
        "package demo; public final class Api { public static void stable() {} }",
    )
    write_java(
        source / "business" / "example" / "Application.java",
        "package example; public final class Application { "
        "public static void main(String[] args) { demo.Api.removed(); } }",
    )
    classes = root / "step3-compiled-classes"
    compile_java(javac, source / "base", classes / "base-lib", release=8)
    compile_java(javac, source / "current", classes / "current-lib", release=17)
    compile_java(
        javac,
        source / "business",
        classes / "base-business",
        release=8,
        classpath=(classes / "base-lib",),
    )
    compile_java(
        javac,
        source / "business",
        classes / "current-business",
        release=17,
        classpath=(classes / "base-lib",),
    )
    base_demo = dependency_jar_bytes(
        classes / "base-lib",
        group="org.example",
        artifact="demo-lib",
        version="1.0.0",
        resources={
            "mapper/OrderMapper.xml": """
                <mapper namespace="scan.OrderMapper">
                  <select id="find">select id from orders</select>
                </mapper>
            """,
        },
    )
    current_demo = dependency_jar_bytes(
        classes / "current-lib",
        group="org.example",
        artifact="demo-lib",
        version="2.0.0",
        resources={
            "mapper/OrderMapper.xml": """
                <mapper namespace="scan.OrderMapper">
                  <select id="find">select id, new_column from orders</select>
                </mapper>
            """,
        },
    )
    base_spring = dependency_jar_bytes(
        None,
        group="org.springframework.boot",
        artifact="spring-boot",
        version="2.7.18",
    )
    current_spring = dependency_jar_bytes(
        None,
        group="org.springframework.boot",
        artifact="spring-boot",
        version="3.2.0",
    )
    base_demo_path = root / "step3-base-demo.jar"
    current_demo_path = root / "step3-current-demo.jar"
    base_demo_path.write_bytes(base_demo)
    current_demo_path.write_bytes(current_demo)
    base = root / "step3-base-app.jar"
    current = root / "step3-current-app.jar"
    write_boot_artifact_with_dependencies(
        base,
        classes / "base-business",
        (
            ("demo-lib-1.0.0.jar", base_demo),
            ("spring-boot-2.7.18.jar", base_spring),
        ),
    )
    write_boot_artifact_with_dependencies(
        current,
        classes / "current-business",
        (
            ("demo-lib-2.0.0.jar", current_demo),
            ("spring-boot-3.2.0.jar", current_spring),
        ),
    )
    return {
        "base": base,
        "current": current,
        "base_demo": base_demo_path,
        "current_demo": current_demo_path,
    }


def create_pinned_source_repository(root: Path, git: str) -> Path:
    origin = root / "origin.git"
    project = root / "project"
    run_external([git, "init", "--bare", str(origin)])
    project.mkdir()
    run_external([git, "init"], cwd=project)
    run_external([git, "config", "user.name", "Blackbox Oracle"], cwd=project)
    run_external(
        [git, "config", "user.email", "blackbox@example.invalid"], cwd=project
    )
    run_external([git, "remote", "add", "origin", str(origin)], cwd=project)

    pom = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <groupId>blackbox</groupId><artifactId>workflow-app</artifactId>
      <version>1.0.0</version>
      <properties><maven.compiler.release>8</maven.compiler.release></properties>
    </project>
    """
    write_java(project / "pom.xml", pom)
    write_java(
        project / "src" / "main" / "java" / "example" / "Application.java",
        """
        package example;
        public final class Application {
            public static void main(String[] args) {
                System.out.print(demo.Api.removed());
            }
        }
        """,
    )
    run_external([git, "add", "."], cwd=project)
    run_external([git, "commit", "-m", "base"], cwd=project)
    run_external([git, "branch", "-M", "base"], cwd=project)
    run_external([git, "push", "-u", "origin", "base"], cwd=project)

    write_java(
        project / "pom.xml",
        pom.replace("<version>1.0.0</version>", "<version>2.0.0</version>")
        .replace(
            "<maven.compiler.release>8</maven.compiler.release>",
            "<maven.compiler.release>17</maven.compiler.release>",
        ),
    )
    run_external([git, "add", "."], cwd=project)
    run_external([git, "commit", "-m", "current"], cwd=project)
    run_external([git, "branch", "-M", "current"], cwd=project)
    run_external([git, "push", "-u", "origin", "current"], cwd=project)
    return project


def create_context_only_repository(root: Path, git: str) -> Path:
    """Create two immutable refs with JDK context but no detectable source."""
    origin = root / "origin.git"
    project = root / "project"
    run_external([git, "init", "--bare", str(origin)])
    project.mkdir()
    run_external([git, "init"], cwd=project)
    run_external([git, "config", "user.name", "Blackbox Oracle"], cwd=project)
    run_external(
        [git, "config", "user.email", "blackbox@example.invalid"], cwd=project
    )
    run_external([git, "remote", "add", "origin", str(origin)], cwd=project)
    template = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <groupId>blackbox</groupId><artifactId>context-only</artifactId>
      <version>1.0.0</version>
      <properties><maven.compiler.release>{release}</maven.compiler.release></properties>
    </project>
    """
    for branch, release in (("base", 8), ("current", 17)):
        write_java(project / "pom.xml", template.format(release=release))
        run_external([git, "add", "."], cwd=project)
        run_external([git, "commit", "-m", branch], cwd=project)
        run_external([git, "branch", "-M", branch], cwd=project)
        run_external([git, "push", "-u", "origin", branch], cwd=project)
    return project


def create_step3_source_repository(root: Path, git: str) -> Path:
    """Create pinned JDK 8/Spring Boot 2 and JDK 17/Boot 3 source refs."""
    origin = root / "step3-origin.git"
    project = root / "step3-project"
    run_external([git, "init", "--bare", str(origin)])
    project.mkdir()
    run_external([git, "init"], cwd=project)
    run_external([git, "config", "user.name", "Blackbox Oracle"], cwd=project)
    run_external(
        [git, "config", "user.email", "blackbox@example.invalid"], cwd=project
    )
    run_external([git, "remote", "add", "origin", str(origin)], cwd=project)

    pom = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <parent><groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>{spring}</version></parent>
      <groupId>blackbox</groupId><artifactId>step3-signals</artifactId>
      <version>1.0.0</version>
      <properties><maven.compiler.release>{release}</maven.compiler.release></properties>
    </project>
    """
    write_java(project / "pom.xml", pom.format(spring="2.7.18", release=8))
    write_java(
        project / "src" / "main" / "java" / "scan" / "Baseline.java",
        "package scan; public final class Baseline {}",
    )
    run_external([git, "add", "."], cwd=project)
    run_external([git, "commit", "-m", "base"], cwd=project)
    run_external([git, "branch", "-M", "base"], cwd=project)
    run_external([git, "push", "-u", "origin", "base"], cwd=project)

    write_java(project / "pom.xml", pom.format(spring="3.2.0", release=17))
    write_java(
        project / "src" / "main" / "java" / "scan" / "MigrationSignals.java",
        """
        package scan;
        import java.io.Serializable;
        import javax.xml.bind.JAXBContext;
        public final class MigrationSignals implements Serializable {
            private javax.swing.JApplet applet;
            private sun.misc.Unsafe unsafe;
            Object load() throws Exception { return Class.forName("legacy.Type"); }
        }
        """,
    )
    write_java(
        project / "src" / "main" / "java" / "scan" / "LegacyConfig.java",
        """
        package scan;
        @ConstructorBinding
        public final class LegacyConfig {}
        """,
    )
    write_java(
        project / "src" / "main" / "resources" / "application.yml",
        "spring:\n"
        "  datasource:\n"
        "    url: jdbc:h2:mem:blackbox\n"
        "management:\n"
        "  endpoints:\n"
        "    web:\n"
        "      exposure:\n"
        "        include: health",
    )
    write_java(
        project / "src" / "main" / "resources" / "META-INF" / "spring.factories",
        "org.springframework.boot.autoconfigure.EnableAutoConfiguration=scan.LegacyConfig",
    )
    write_java(
        project / "src" / "main" / "resources" / "Dockerfile",
        'ENTRYPOINT ["java","--illegal-access=permit","-jar","app.jar"]',
    )
    run_external([git, "add", "."], cwd=project)
    run_external([git, "commit", "-m", "current"], cwd=project)
    run_external([git, "branch", "-M", "current"], cwd=project)
    run_external([git, "push", "-u", "origin", "current"], cwd=project)
    return project


def run_confirmed_artifact_workflow(
    report: Path, project: Path, artifacts: dict[str, Path], jdk_home: Path,
) -> tuple[subprocess.CompletedProcess, subprocess.CompletedProcess, tuple[str, ...]]:
    common = (
        "--project-dir", str(project),
        "--report-dir", str(report),
    )
    first = run_workflow(
        "--step", "step0", *common,
        "--base-artifact-path", str(artifacts["base"]),
        "--current-artifact-path", str(artifacts["current"]),
        "--application-source", str(project),
        "--base-branch", "origin/base",
        "--current-branch", "origin/current",
        "--base-tool", "maven",
        "--current-tool", "maven",
        "--base-jdk-home", str(jdk_home),
        "--current-jdk-home", str(jdk_home),
        "--target-module", ".",
    )
    if first.returncode != 4:
        raise AssertionError(first.stderr)
    first_interaction = json.loads((
        report / ".runtime" / "state" / "interaction.json"
    ).read_text(encoding="utf-8"))
    if first_interaction["step_id"] != "step0":
        raise AssertionError(first_interaction)
    confirmed = run_workflow(
        "--step", "step0", *common,
        "--response-json", json.dumps({"action": "continue"}),
    )
    if confirmed.returncode != 0:
        raise AssertionError(confirmed.stderr)
    analyzed = run_workflow("--step", "step1", *common)
    return first, analyzed, common


class PublicWorkflowCliBlackboxTest(unittest.TestCase):
    def test_describe_step0_contract_matches_authored_public_contract(self):
        completed = run_workflow("--describe-step0-contract")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        actual = json.loads(completed.stdout)
        expected = TRUTH["describe_contract"]
        modes = {
            row["id"]: {
                "required_fields": row["required_fields"],
            }
            for row in actual["input_modes"]
        }
        projection = {
            "schema": actual["schema"],
            "step_id": actual["step_id"],
            "input_modes": modes,
            "optional_fields": actual["optional_fields"],
        }
        self.assertEqual(projection, expected)

    def test_missing_input_checkpoint_and_cancel_are_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            report = root / "report"
            project.mkdir()
            common = (
                "--step", "auto",
                "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(*common)
            expected = TRUTH["missing_input_checkpoint"]
            self.assertEqual(first.returncode, expected["exit_code"], first.stderr)
            event = confirmation_event(first.stdout)
            interaction = json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            projection = {
                "schema": interaction["schema"],
                "status": interaction["status"],
                "kind": interaction["kind"],
                "step_id": interaction["step_id"],
                "reason_code": interaction["reason_code"],
                "checkpoint": interaction["checkpoint"],
                "hard_stop": interaction["hard_stop"],
                "required_fields": interaction["required_fields"],
                "option_ids": sorted(row["id"] for row in interaction["options"]),
                "row_labels": [
                    row["label"]
                    for row in interaction["confirmation_table"]["rows"]
                ],
            }
            self.assertEqual(projection, {
                key: value for key, value in expected.items()
                if key not in {"exit_code", "confirmation_schema"}
            })
            self.assertEqual(event["schema"], expected["confirmation_schema"])
            for field in (
                "status", "step_id", "reason_code", "checkpoint",
                "hard_stop", "required_fields",
            ):
                self.assertEqual(event[field], interaction[field])

            summary = json.loads((
                report / ".runtime" / "state" / "last_step_summary.json"
            ).read_text(encoding="utf-8"))
            expected_summary = TRUTH["last_step_summary"]
            self.assertEqual(summary["schema"], expected_summary["schema"])
            self.assertEqual(summary["event"], expected_summary["event"])
            self.assertEqual(
                summary["workflow_state"]["status"],
                expected_summary["workflow_status"],
            )
            self.assertEqual(
                summary["workflow_state"]["current_step"],
                expected_summary["current_step"],
            )
            self.assertEqual(
                summary["needs_user_input"], expected_summary["needs_user_input"]
            )

            cancelled = run_workflow(
                *common, "--response-json", '{"action":"cancel"}',
            )
            cancel_truth = TRUTH["cancel"]
            self.assertEqual(
                cancelled.returncode, cancel_truth["exit_code"], cancelled.stderr
            )
            state = json.loads((
                report / ".runtime" / "state" / "main_state.json"
            ).read_text(encoding="utf-8"))["state"]
            self.assertEqual(state["status"], cancel_truth["workflow_status"])
            self.assertEqual(state["current_step"], cancel_truth["current_step"])
            self.assertEqual(state["blocking_reason"], cancel_truth["blocking_reason"])
            self.assertEqual(
                bool(state.get("pending_interaction")),
                cancel_truth["checkpoint_is_preserved"],
            )

    def test_artifact_input_step1_matches_independent_closed_truth(self):
        expected = TRUTH["artifact_input_step1_success"]
        git = shutil.which("git") or ""
        java = shutil.which("java") or ""
        self.assertTrue(git and java)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_context_only_repository(root, git)
            report = root / "report"
            base_artifact = root / "base-app.jar"
            current_artifact = root / "current-app.jar"
            base_nested = write_boot_artifact(
                base_artifact, expected["dependency_change"]["old_version"]
            )
            current_nested = write_boot_artifact(
                current_artifact, expected["dependency_change"]["new_version"]
            )

            # Independent input oracle: the standard ZIP reader, not analyzer code,
            # proves that the authored Maven identities are actually in the fixture.
            for artifact, version in (
                (base_artifact, expected["dependency_change"]["old_version"]),
                (current_artifact, expected["dependency_change"]["new_version"]),
            ):
                with zipfile.ZipFile(artifact) as outer:
                    entry = f"BOOT-INF/lib/demo-lib-{version}.jar"
                    with zipfile.ZipFile(io.BytesIO(outer.read(entry))) as nested:
                        metadata = nested.read(
                            "META-INF/maven/org.example/demo-lib/pom.properties"
                        ).decode("ascii")
                self.assertEqual(
                    metadata,
                    "groupId=org.example\nartifactId=demo-lib\n"
                    f"version={version}\n",
                )

            _initial, completed, _common = run_confirmed_artifact_workflow(
                report,
                project,
                {"base": base_artifact, "current": current_artifact},
                full_jdk_home(java),
            )

            self.assertEqual(completed.returncode, expected["exit_code"], completed.stderr)

            dependencies = report / "evidence" / "dependencies"
            changes = read_csv_rows(dependencies / "dep_changes.csv")
            self.assertEqual(len(changes), 1)
            self.assertEqual(
                {key: changes[0][key] for key in expected["dependency_change"]},
                expected["dependency_change"],
            )
            current = read_csv_rows(dependencies / "deps_current_resolved.csv")
            self.assertEqual(len(current), 1)
            self.assertEqual(
                {key: current[0][key] for key in expected["current_dependency"]},
                expected["current_dependency"],
            )

            provenance = json.loads(
                (dependencies / "build_provenance.json").read_text(encoding="utf-8")
            )
            sides = {row["side"]: row for row in provenance["sides"]}
            self.assertTrue(provenance["both_builds_succeeded"])
            for side, artifact in (
                ("base", base_artifact), ("current", current_artifact)
            ):
                self.assertEqual(
                    sides[side]["source_mode"], expected["provenance_source_mode"]
                )
                self.assertEqual(
                    sides[side]["artifact_sha256"],
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )

            manifest = json.loads(
                (dependencies / "dependency_jars.json").read_text(encoding="utf-8")
            )
            items = {
                (row["side"], row["version"]): row for row in manifest["items"]
            }
            expected_nested = {
                ("base", expected["dependency_change"]["old_version"]): base_nested,
                ("current", expected["dependency_change"]["new_version"]): current_nested,
            }
            self.assertEqual(set(items), set(expected_nested))
            for identity, original_bytes in expected_nested.items():
                retained = Path(items[identity]["retained_path"])
                self.assertEqual(retained.read_bytes(), original_bytes)
                self.assertEqual(
                    items[identity]["nested_jar_sha256"],
                    hashlib.sha256(original_bytes).hexdigest(),
                )

            for relative_path in expected["required_outputs"]:
                self.assertTrue((report / relative_path).exists(), relative_path)

    def test_thin_artifacts_fail_closed_at_the_public_boundary(self):
        expected = TRUTH["thin_artifact_failure"]
        git = shutil.which("git") or ""
        java = shutil.which("java") or ""
        self.assertTrue(git and java)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_context_only_repository(root, git)
            report = root / "report"
            artifacts = []
            for name in ("base-thin.jar", "current-thin.jar"):
                artifact = root / name
                with zipfile.ZipFile(artifact, "w") as archive:
                    archive.writestr("example/Application.class", b"business-only")
                artifacts.append(artifact)

            # Independent archive inventory proves these are thin inputs: no
            # supported embedded dependency location exists on either side.
            for artifact in artifacts:
                with zipfile.ZipFile(artifact) as archive:
                    dependency_entries = [
                        name for name in archive.namelist()
                        if name.lower().endswith(".jar")
                        and name.lower().startswith(
                            ("boot-inf/lib/", "web-inf/lib/", "lib/")
                        )
                    ]
                self.assertEqual(dependency_entries, [])

            _initial, completed, _common = run_confirmed_artifact_workflow(
                report,
                project,
                {"base": artifacts[0], "current": artifacts[1]},
                full_jdk_home(java),
            )

            self.assertEqual(completed.returncode, expected["exit_code"])
            state = json.loads(
                (report / ".runtime" / "state" / "main_state.json").read_text(
                    encoding="utf-8"
                )
            )["state"]
            for field, value in expected["workflow_state"].items():
                self.assertEqual(state[field], value)
            self.assertIn(expected["blocking_reason_contains"], state["blocking_reason"])
            self.assertFalse((report / "evidence" / "context").exists())

    def test_corrupt_artifact_fails_closed_at_the_public_boundary(self):
        expected = TRUTH["corrupt_artifact_failure"]
        git = shutil.which("git") or ""
        java = shutil.which("java") or ""
        self.assertTrue(git and java)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_context_only_repository(root, git)
            report = root / "report"
            corrupt = root / "base-corrupt.jar"
            corrupt.write_bytes(b"not-a-zip-archive")
            current = root / "current-app.jar"
            write_boot_artifact(current, "2.0.0")

            with self.assertRaises(zipfile.BadZipFile):
                with zipfile.ZipFile(corrupt) as archive:
                    archive.namelist()

            _initial, completed, _common = run_confirmed_artifact_workflow(
                report,
                project,
                {"base": corrupt, "current": current},
                full_jdk_home(java),
            )

            self.assertEqual(completed.returncode, expected["exit_code"])
            state = json.loads(
                (report / ".runtime" / "state" / "main_state.json").read_text(
                    encoding="utf-8"
                )
            )["state"]
            for field, value in expected["workflow_state"].items():
                self.assertEqual(state[field], value)
            self.assertIn(expected["blocking_reason_contains"], state["blocking_reason"])
            self.assertFalse(
                (report / "evidence" / "dependencies" / "dep_changes.csv").exists()
            )

    def test_step0_unifies_source_inputs_and_rejects_old_step2_fields(self):
        unified_source_contract = STEP0_SOURCE_TRUTH["unified_source_contract"]
        described = run_workflow("--describe-step0-contract")
        self.assertEqual(described.returncode, 0, described.stderr)
        contract = json.loads(described.stdout)
        modes = {item["id"]: item for item in contract["input_modes"]}
        self.assertEqual(contract["step_id"], unified_source_contract["step_id"])
        self.assertEqual(
            sorted(
                mode for mode, item in modes.items()
                if "application_source" in item["required_fields"]
            ),
            sorted(unified_source_contract["application_source_required_in_modes"]),
        )
        self.assertIn(
            unified_source_contract["dependency_source_field"],
            contract["optional_fields"],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            report = root / "report"
            project.mkdir()
            common = (
                "--step", "auto",
                "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(*common)
            self.assertEqual(first.returncode, 4, first.stderr)
            first_interaction = json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            row_labels = [
                row["label"]
                for row in first_interaction["confirmation_table"]["rows"]
            ]
            self.assertEqual(row_labels, unified_source_contract["row_labels"])
            self.assertEqual(
                row_labels[unified_source_contract["application_source_row_index"]],
                "应用源码",
            )
            self.assertEqual(
                row_labels[unified_source_contract["dependency_source_row_index"]],
                "依赖包源码",
            )

            legacy_step2_source_protocol_rejected = STEP0_SOURCE_TRUTH[
                "legacy_step2_source_protocol_rejected"
            ]
            rejected = run_workflow(
                *common,
                "--response-json",
                json.dumps({
                    "action": "continue",
                    legacy_step2_source_protocol_rejected["field"]:
                        legacy_step2_source_protocol_rejected["value"],
                }),
            )
            self.assertEqual(
                rejected.returncode,
                legacy_step2_source_protocol_rejected["exit_code"],
            )
            self.assertIn(
                legacy_step2_source_protocol_rejected["error_contains"],
                rejected.stderr,
            )

            interaction = json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                interaction["step_id"],
                legacy_step2_source_protocol_rejected["checkpoint_remains"],
            )
            self.assertNotIn(
                legacy_step2_source_protocol_rejected["field"],
                interaction["response_schema"]["properties"],
            )

    def test_step3_scans_pinned_sources_resources_and_two_sided_artifacts(self):
        expected = STEP3_TRUTH
        tools = {
            name: shutil.which(name) or ""
            for name in ("git", "java", "javac", "javap")
        }
        self.assertEqual(
            [name for name, path in tools.items() if not path], [],
            "the Step3 public fixture requires Git and a full OpenJDK",
        )
        base_jdk_home = find_full_jdk_home(tools["java"], 8)
        current_jdk_home = find_full_jdk_home(tools["java"], 17)
        self.assertIsNotNone(
            base_jdk_home,
            "the JDK 8 -> 17 Step3 fixture requires a real JDK 8 home",
        )
        self.assertIsNotNone(
            current_jdk_home,
            "the JDK 8 -> 17 Step3 fixture requires a real JDK 17 home",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_step3_source_repository(root, tools["git"])
            artifacts = build_step3_workflow_artifacts(root, tools["javac"])
            report = root / "report"

            # Independent Oracle 1: OpenJDK identifies the authored classfile
            # boundary without calling any analyzer implementation.
            base_verbose = run_external([
                tools["javap"], "-classpath", str(artifacts["base_demo"]),
                "-verbose", "demo.Api",
            ]).stdout
            current_verbose = run_external([
                tools["javap"], "-classpath", str(artifacts["current_demo"]),
                "-verbose", "demo.Api",
            ]).stdout
            self.assertIn("major version: 52", base_verbose)
            self.assertIn("major version: 61", current_verbose)

            # Independent Oracle 2: standard readers prove the exact source,
            # resource and MyBatis inputs from which the closed truth was authored.
            signal_text = (
                project / "src" / "main" / "java" / "scan"
                / "MigrationSignals.java"
            ).read_text(encoding="utf-8")
            for marker in (
                "javax.xml.bind.JAXBContext", "javax.swing.JApplet",
                "sun.misc.Unsafe", 'Class.forName("legacy.Type")',
                "implements Serializable",
            ):
                self.assertEqual(signal_text.count(marker), 1, marker)
            with zipfile.ZipFile(artifacts["base_demo"]) as archive:
                base_mapper = archive.read("mapper/OrderMapper.xml").decode("utf-8")
            with zipfile.ZipFile(artifacts["current_demo"]) as archive:
                current_mapper = archive.read("mapper/OrderMapper.xml").decode("utf-8")
            self.assertNotIn("new_column", base_mapper)
            self.assertEqual(current_mapper.count("new_column"), 1)

            common = (
                "--step", "auto",
                "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(
                *common,
                "--base-artifact-path", str(artifacts["base"]),
                "--current-artifact-path", str(artifacts["current"]),
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-jdk-home", str(base_jdk_home),
                "--current-jdk-home", str(current_jdk_home),
                "--target-module", ".",
            )
            self.assertEqual(first.returncode, 4, first.stderr)
            self.assertEqual(json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))["step_id"], "step0")
            advanced = run_workflow(
                *common,
                "--response-json", json.dumps({"action": "continue"}),
            )
            self.assertEqual(advanced.returncode, 4, advanced.stderr)
            self.assertEqual(json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))["step_id"], "step4")

            context = json.loads((
                report / "evidence" / "context" / "context.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["context"].items():
                self.assertEqual(context[field], value, (field, context[field]))

            scan = report / "evidence" / "static_scan"
            projections = (
                ("s3_jdk_removed_api.csv", "jdk_removed",
                 ("API", "移除版本", "状态", "置信度")),
                ("s3_jdk_javax_refs.csv", "javax", ("引用类型", "需迁移")),
                ("s3_jdk_internal_api.csv", "jdk_internal", ("API类型",)),
                ("s3_jdk_reflection.csv", "reflection", ("反射类型",)),
                ("s3_jdk_runtime_flags.csv", "runtime_flags", ("参数", "影响版本")),
                ("s3_springboot_config.csv", "spring_config", ("配置键", "当前值")),
            )
            for filename, truth_key, fields in projections:
                rows = read_csv_rows(scan / filename)
                actual = sorted(
                    ({field: row[field] for field in fields} for row in rows),
                    key=lambda row: tuple(row[field] for field in fields),
                )
                wanted = sorted(
                    expected[truth_key],
                    key=lambda row: tuple(row[field] for field in fields),
                )
                self.assertEqual(actual, wanted, filename)

            serialization = (
                scan / "s3_jdk_serialization.txt"
            ).read_text(encoding="utf-8")
            for marker in expected["serialization"]["required_text"]:
                self.assertIn(marker, serialization)
            self.assertEqual(serialization.count("[MigrationSignals]"), 1)

            autoconfig = (
                scan / "s3_springboot_autoconfig.txt"
            ).read_text(encoding="utf-8")
            for marker in expected["spring_autoconfig_required_text"]:
                self.assertIn(marker, autoconfig)

            database_summary = json.loads((
                scan / "s3_database_contract_summary.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["database_contract"]["summary"].items():
                self.assertEqual(database_summary[field], value, field)
            database_fields = tuple(expected["database_contract"]["rows"][0])
            database_rows = [
                {field: row[field] for field in database_fields}
                for row in read_csv_rows(scan / "s3_database_contract_changes.csv")
            ]
            self.assertEqual(database_rows, expected["database_contract"]["rows"])

    def test_step4_scope_zero_one_multiple_full_partial_and_rejections(self):
        expected = STEP4_SCOPE_TRUTH
        tools = {
            name: shutil.which(name) or ""
            for name in ("git", "java", "javac", "javap")
        }
        self.assertEqual([name for name, path in tools.items() if not path], [])
        jdk_home = find_full_jdk_home(tools["java"], 8)
        self.assertIsNotNone(jdk_home, "the Step4 scope fixture requires a real JDK 8 home")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_pinned_source_repository(root, tools["git"])
            artifacts = build_two_dependency_workflow_artifacts(
                root, tools["javac"]
            )

            # Two independent javap inventories and JVM executions establish
            # the exact candidate set before the analyzer is invoked.
            for prefix, owner, method, argument, stdout in (
                ("demo", "demo.Api", "removed();", "demo", "D"),
                ("other", "other.Other", "gone();", "other", "O"),
            ):
                base_members = run_external([
                    tools["javap"], "-classpath", str(artifacts[f"{prefix}_base"]),
                    "-public", owner,
                ]).stdout
                current_members = run_external([
                    tools["javap"], "-classpath", str(artifacts[f"{prefix}_current"]),
                    "-public", owner,
                ]).stdout
                self.assertIn(method, base_members)
                self.assertNotIn(method, current_members)
                base_run = run_external([
                    tools["java"], "-cp", os.pathsep.join((
                        str(artifacts["business"]),
                        str(artifacts["demo_base"]),
                        str(artifacts["other_base"]),
                    )), "example.Application", argument,
                ])
                self.assertEqual(base_run.stdout, stdout)
                current_run = subprocess.run(
                    [
                        tools["java"], "-cp", os.pathsep.join((
                            str(artifacts["business"]),
                            str(artifacts["demo_current"]),
                            str(artifacts["other_current"]),
                        )), "example.Application", argument,
                    ],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", check=False, timeout=30,
                )
                self.assertNotEqual(current_run.returncode, 0)
                self.assertIn("NoSuchMethodError", current_run.stderr)

            def reach_scope_checkpoint(report: Path) -> tuple[str, ...]:
                common = (
                    "--step", "auto", "--project-dir", str(project),
                    "--report-dir", str(report),
                )
                started = run_workflow(
                    *common,
                    "--base-artifact-path", str(artifacts["base"]),
                    "--current-artifact-path", str(artifacts["current"]),
                    "--base-branch", "origin/base",
                    "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                    "--base-jdk-home", str(jdk_home),
                    "--current-jdk-home", str(jdk_home),
                    "--target-module", ".",
                )
                self.assertEqual(started.returncode, 4, started.stderr)
                advanced = run_workflow(
                    *common,
                    "--response-json", json.dumps({"action": "continue"}),
                )
                self.assertEqual(advanced.returncode, 4, advanced.stderr)
                return common

            partial_report = root / "partial-report"
            partial_common = reach_scope_checkpoint(partial_report)
            interaction = json.loads((
                partial_report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            checkpoint = expected["checkpoint"]
            self.assertEqual(interaction["step_id"], checkpoint["step_id"])
            self.assertEqual(interaction["kind"], "review")
            self.assertEqual(
                interaction["scope_preview"]["available_dependency_count"],
                checkpoint["available_dependency_count"],
            )
            self.assertEqual(
                interaction["scope_preview"]["total_api_count"],
                checkpoint["total_api_count"],
            )
            self.assertEqual(
                sorted(item["coord"] for item in interaction["selection_options"]),
                checkpoint["option_coords"],
            )
            self.assertEqual(
                interaction["required_fields"], checkpoint["required_fields"]
            )

            rejected = run_workflow(
                *partial_common,
                "--response-json", json.dumps({
                    "action": "continue", "scope_mode": "partial",
                }),
            )
            self.assertEqual(
                rejected.returncode,
                expected["invalid_partial_without_target"]["exit_code"],
            )
            self.assertIn(
                expected["invalid_partial_without_target"]["stderr_contains"],
                rejected.stderr,
            )
            rejected = run_workflow(
                *partial_common,
                "--response-json", json.dumps({
                    "action": "continue", "scope_mode": "partial",
                    "selected_targets": ["missing-lib"],
                }),
            )
            self.assertEqual(
                rejected.returncode,
                expected["invalid_unknown_target"]["exit_code"],
            )
            self.assertIn(
                expected["invalid_unknown_target"]["stderr_contains"],
                rejected.stderr,
            )
            completed = run_workflow(
                *partial_common,
                "--response-json", json.dumps({
                    "action": "continue", "scope_mode": "partial",
                    "selected_targets": ["org.example:demo-lib"],
                }),
            )
            self.assertEqual(
                completed.returncode, expected["partial"]["process_exit_code"],
                completed.stderr,
            )
            partial_findings = json.loads((
                partial_report / ".runtime" / "findings" / "s6_findings.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["partial"]["scope"].items():
                self.assertEqual(
                    partial_findings["analysis_scope"][field], value, field
                )
            partial_impact = read_csv_rows(
                partial_report / "deliverables" / "all-impact-details.csv"
            )
            self.assertEqual(
                len(partial_impact), expected["partial"]["impact_row_count"]
            )
            self.assertNotIn(
                expected["partial"]["forbidden_impact_text"],
                json.dumps(partial_impact, ensure_ascii=False),
            )

            full_report = root / "full-report"
            full_common = reach_scope_checkpoint(full_report)
            completed = run_workflow(
                *full_common,
                "--response-json", json.dumps({
                    "action": "continue", "scope_mode": "full",
                }),
            )
            self.assertEqual(
                completed.returncode, expected["full"]["process_exit_code"],
                completed.stderr,
            )
            full_findings = json.loads((
                full_report / ".runtime" / "findings" / "s6_findings.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["full"]["scope"].items():
                self.assertEqual(full_findings["analysis_scope"][field], value, field)
            self.assertEqual(
                len(read_csv_rows(
                    full_report / "deliverables" / "all-impact-details.csv"
                )),
                expected["full"]["impact_row_count"],
            )

            zero_report = root / "zero-report"
            zero_common = (
                "--step", "auto", "--project-dir", str(project),
                "--report-dir", str(zero_report),
            )
            started = run_workflow(
                *zero_common,
                "--base-artifact-path", str(artifacts["base"]),
                "--current-artifact-path", str(artifacts["base"]),
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-jdk-home", str(jdk_home),
                "--current-jdk-home", str(jdk_home),
                "--target-module", ".",
            )
            self.assertEqual(started.returncode, 4, started.stderr)
            zero_completed = run_workflow(
                *zero_common,
                "--response-json", json.dumps({"action": "continue"}),
            )
            self.assertEqual(
                zero_completed.returncode,
                expected["zero"]["process_exit_code"],
                zero_completed.stderr,
            )
            zero_findings = json.loads((
                zero_report / ".runtime" / "findings" / "s6_findings.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["zero"]["scope"].items():
                self.assertEqual(zero_findings["analysis_scope"][field], value, field)

    def test_war_layout_reaches_step6_with_nested_runtime_bytes(self):
        expected = WAR_TRUTH
        tools = {
            name: shutil.which(name) or ""
            for name in ("git", "java", "javac", "javap")
        }
        self.assertEqual(
            [name for name, path in tools.items() if not path], [],
            "the WAR public workflow fixture requires Git and OpenJDK",
        )
        jdk_home = find_full_jdk_home(tools["java"], 8)
        self.assertIsNotNone(jdk_home, "the WAR workflow fixture requires a real JDK 8 home")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_pinned_source_repository(root, tools["git"])
            compiled = build_full_workflow_artifacts(root, tools["javac"])
            base_war = root / "base-app.war"
            current_war = root / "current-app.war"
            convert_boot_jar_to_war(compiled["base"], base_war)
            convert_boot_jar_to_war(compiled["current"], current_war)
            report = root / "report"

            # Standard ZIP inventory is the layout and byte-identity Oracle.
            with zipfile.ZipFile(base_war) as archive:
                self.assertTrue(set(expected["required_layout"]).issubset(
                    archive.namelist()
                ))
                base_dependency = archive.read(
                    "WEB-INF/lib/demo-lib-1.0.0.jar"
                )
                business_class = archive.read(
                    "WEB-INF/classes/example/Application.class"
                )
            with zipfile.ZipFile(current_war) as archive:
                current_dependency = archive.read(
                    "WEB-INF/lib/demo-lib-2.0.0.jar"
                )
                self.assertEqual(
                    archive.read("WEB-INF/classes/example/Application.class"),
                    business_class,
                )
            self.assertEqual(
                hashlib.sha256(base_dependency).hexdigest(),
                hashlib.sha256(compiled["base_library"].read_bytes()).hexdigest(),
            )
            self.assertEqual(
                hashlib.sha256(current_dependency).hexdigest(),
                hashlib.sha256(compiled["current_library"].read_bytes()).hexdigest(),
            )

            extracted_business = root / "war-business.jar"
            with zipfile.ZipFile(extracted_business, "w") as archive:
                archive.writestr("example/Application.class", business_class)
            base_dep = root / "war-base-dependency.jar"
            current_dep = root / "war-current-dependency.jar"
            base_dep.write_bytes(base_dependency)
            current_dep.write_bytes(current_dependency)
            base_run = run_external([
                tools["java"], "-cp",
                os.pathsep.join((str(extracted_business), str(base_dep))),
                "example.Application",
            ])
            self.assertEqual(base_run.stdout, "base")
            current_run = subprocess.run(
                [
                    tools["java"], "-cp",
                    os.pathsep.join((str(extracted_business), str(current_dep))),
                    "example.Application",
                ],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", check=False, timeout=30,
            )
            self.assertNotEqual(current_run.returncode, 0)
            self.assertIn("NoSuchMethodError", current_run.stderr)

            common = (
                "--step", "auto", "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(
                *common,
                "--base-artifact-path", str(base_war),
                "--current-artifact-path", str(current_war),
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-jdk-home", str(jdk_home),
                "--current-jdk-home", str(jdk_home),
                "--target-module", ".",
            )
            self.assertEqual(first.returncode, 4, first.stderr)
            interaction_path = (
                report / ".runtime" / "state" / "interaction.json"
            )
            self.assertEqual(
                json.loads(interaction_path.read_text(encoding="utf-8"))[
                    "step_id"
                ],
                expected["expected_checkpoints"][0],
            )
            continued = run_workflow(
                *common,
                "--response-json", json.dumps({"action": "continue"}),
            )
            if len(expected["expected_checkpoints"]) > 1:
                self.assertEqual(continued.returncode, 4, continued.stderr)
                self.assertEqual(
                    json.loads(interaction_path.read_text(encoding="utf-8"))[
                        "step_id"
                    ],
                    expected["expected_checkpoints"][1],
                )
                completed = run_workflow(
                    *common,
                    "--response-json", json.dumps({
                        "action": "continue", "scope_mode": "full",
                    }),
                )
            else:
                completed = continued
            completion = expected["expected_completion"]
            self.assertEqual(
                completed.returncode, completion["process_exit_code"],
                completed.stderr,
            )
            state = json.loads((
                report / ".runtime" / "state" / "main_state.json"
            ).read_text(encoding="utf-8"))["state"]
            self.assertEqual(state["status"], completion["workflow_status"])
            self.assertEqual(state["current_step"], completion["current_step"])
            self.assertEqual(state["completed_step"], completion["completed_step"])

            active_path = (
                report / ".runtime" / "binary_authority"
                / "active_binary_generation.json"
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            formal = json.loads((
                active_path.parent / active["generation_directory"]
                / "binary_formal_results.json"
            ).read_text(encoding="utf-8"))
            target = next(
                row for row in formal["by_api"]
                if (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ) == tuple(expected["target"])
            )
            for field, value in expected["target_state"].items():
                self.assertEqual(target[field], value, (field, target))
            for relative in expected["required_outputs"]:
                self.assertTrue((report / relative).is_file(), relative)

    def test_step6_bounds_markdown_without_losing_complete_csv_detail(self):
        expected = REPORT_BOUNDED_TRUTH
        tools = {
            name: shutil.which(name) or ""
            for name in ("git", "java", "javac", "javap")
        }
        self.assertEqual(
            [name for name, path in tools.items() if not path], [],
            "the bounded-report fixture requires Git and a full OpenJDK",
        )
        jdk_home = find_full_jdk_home(tools["java"], 8)
        self.assertIsNotNone(jdk_home, "the bounded-report fixture requires a real JDK 8 home")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_pinned_source_repository(root, tools["git"])
            report = root / "report"
            method_count = int(expected["removed_method_count"])
            artifacts = build_bounded_report_artifacts(
                root, tools["javac"], method_count=method_count
            )

            base_inventory = run_external([
                tools["javap"], "-classpath", str(artifacts["base_library"]),
                "-public", "-s", "demo.Api",
            ]).stdout
            current_inventory = run_external([
                tools["javap"], "-classpath", str(artifacts["current_library"]),
                "-public", "-s", "demo.Api",
            ]).stdout
            for index in range(method_count):
                signature = f"m{index:02d}();"
                self.assertIn(signature, base_inventory)
                self.assertNotIn(signature, current_inventory)
            base_run = run_external([
                tools["java"], "-cp",
                os.pathsep.join((
                    str(artifacts["business"]), str(artifacts["base_library"]),
                )),
                "example.Application",
            ])
            self.assertEqual(base_run.stdout, str(sum(range(method_count))))
            current_run = subprocess.run(
                [
                    tools["java"], "-cp",
                    os.pathsep.join((
                        str(artifacts["business"]),
                        str(artifacts["current_library"]),
                    )),
                    "example.Application",
                ],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", check=False, timeout=30,
            )
            self.assertNotEqual(current_run.returncode, 0)
            self.assertIn("NoSuchMethodError", current_run.stderr)

            common = (
                "--step", "auto", "--project-dir", str(project),
                "--report-dir", str(report),
            )
            started = run_workflow(
                *common,
                "--base-artifact-path", str(artifacts["base"]),
                "--current-artifact-path", str(artifacts["current"]),
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-jdk-home", str(jdk_home),
                "--current-jdk-home", str(jdk_home),
                "--target-module", ".",
            )
            self.assertEqual(started.returncode, 4, started.stderr)
            completed = run_workflow(
                *common,
                "--response-json", json.dumps({"action": "continue"}),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            changed_rows = read_csv_rows(
                report / "evidence" / "api_changes" / "all_changed_apis.csv"
            )
            self.assertEqual(
                len(changed_rows), expected["expected_changed_api_row_count"]
            )
            for index in range(method_count):
                method = f"demo.Api.m{index:02d}"
                self.assertEqual(
                    sorted(
                        row["change_type"] for row in changed_rows
                        if row["api_name"] == method
                    ),
                    ["MEMBER_RESOLUTION_CHANGED", "REMOVED"],
                )

            active_path = (
                report / ".runtime" / "binary_authority"
                / "active_binary_generation.json"
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            formal = json.loads((
                active_path.parent / active["generation_directory"]
                / "binary_formal_results.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                len(formal["by_api"]), expected["expected_formal_api_count"]
            )
            impact_csv = report / "deliverables" / "all-impact-details.csv"
            self.assertTrue(impact_csv.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertEqual(
                len(read_csv_rows(impact_csv)),
                expected["expected_impact_csv_row_count"],
            )
            main_report = (
                report / "deliverables" / "report.md"
            ).read_text(encoding="utf-8")
            expected_count_marker = (
                f"正文展示 {expected['expected_main_display_count']}/"
                f"{expected['expected_main_result_count']} 个"
            )
            self.assertIn(expected_count_marker, main_report)
            for marker in expected["required_main_report_markers"]:
                self.assertIn(marker, main_report)
            detail_report = (
                report / "deliverables" / "all-impact-details.md"
            ).read_text(encoding="utf-8")
            for index in range(method_count):
                self.assertIn(f"m{index:02d}", detail_report)

    def test_artifact_workflow_reaches_step6_and_matches_closed_truth(self):
        expected = FULL_TRUTH
        tools = {
            name: shutil.which(name) or ""
            for name in ("git", "java", "javac", "javap")
        }
        self.assertEqual(
            [name for name, path in tools.items() if not path], [],
            "the public workflow fixture requires Git and a full OpenJDK",
        )
        jdk_home = find_full_jdk_home(tools["java"], 8)
        self.assertIsNotNone(jdk_home, "the closed public workflow fixture requires a real JDK 8 home")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = create_pinned_source_repository(root, tools["git"])
            report = root / "report"
            artifacts = build_full_workflow_artifacts(root, tools["javac"])

            # Independent Oracle 1: javap proves the exact removed descriptor.
            base_members = run_external([
                tools["javap"], "-classpath", str(artifacts["base_library"]),
                "-public", "-s", "demo.Api",
            ]).stdout
            current_members = run_external([
                tools["javap"], "-classpath", str(artifacts["current_library"]),
                "-public", "-s", "demo.Api",
            ]).stdout
            self.assertIn("removed();", base_members)
            self.assertIn("()Ljava/lang/String;", base_members)
            self.assertNotIn("removed();", current_members)

            # Independent Oracle 2: the JVM succeeds on base and links closed
            # with NoSuchMethodError on current using the same compiled client.
            separator = os.pathsep
            base_execution = run_external([
                tools["java"], "-cp",
                f'{artifacts["business"]}{separator}{artifacts["base_library"]}',
                "example.Application",
            ])
            self.assertEqual(base_execution.stdout, "base")
            current_execution = subprocess.run(
                [
                    tools["java"], "-cp",
                    f'{artifacts["business"]}{separator}{artifacts["current_library"]}',
                    "example.Application",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )
            self.assertNotEqual(current_execution.returncode, 0)
            self.assertIn("NoSuchMethodError", current_execution.stderr)

            common = (
                "--step", "auto",
                "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(
                *common,
                "--base-artifact-path", str(artifacts["base"]),
                "--current-artifact-path", str(artifacts["current"]),
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-tool", "maven",
                "--current-tool", "maven",
                "--base-jdk-home", str(jdk_home),
                "--current-jdk-home", str(jdk_home),
                "--target-module", ".",
            )
            self.assertEqual(first.returncode, 4, first.stderr)
            first_checkpoint = json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    "step_id": first_checkpoint["step_id"],
                    "kind": first_checkpoint["kind"],
                },
                expected["expected_checkpoints"][0],
            )

            continued = run_workflow(
                *common,
                "--response-json", json.dumps({"action": "continue"}),
            )
            if len(expected["expected_checkpoints"]) > 1:
                self.assertEqual(continued.returncode, 4, continued.stderr)
                second_checkpoint = json.loads((
                    report / ".runtime" / "state" / "interaction.json"
                ).read_text(encoding="utf-8"))
                self.assertEqual(
                    {
                        "step_id": second_checkpoint["step_id"],
                        "kind": second_checkpoint["kind"],
                    },
                    expected["expected_checkpoints"][1],
                )
                completed = run_workflow(
                    *common,
                    "--response-json", json.dumps({
                        "action": "continue", "scope_mode": "full",
                    }),
                )
            else:
                completed = continued
            self.assertEqual(
                completed.returncode,
                expected["expected_completion"]["process_exit_code"],
                completed.stderr,
            )
            state = json.loads((
                report / ".runtime" / "state" / "main_state.json"
            ).read_text(encoding="utf-8"))["state"]
            for field in ("workflow_status", "current_step", "completed_step"):
                state_field = "status" if field == "workflow_status" else field
                self.assertEqual(
                    state[state_field], expected["expected_completion"][field]
                )

            context = json.loads((
                report / "evidence" / "context" / "context.json"
            ).read_text(encoding="utf-8"))
            for field, value in expected["expected_context"].items():
                self.assertEqual(context[field], value, field)

            dependency_rows = read_csv_rows(
                report / "evidence" / "dependencies" / "dep_changes.csv"
            )
            self.assertEqual(len(dependency_rows), 1)
            for field, value in expected["expected_dependency"].items():
                self.assertEqual(dependency_rows[0][field], value)

            api_rows = read_csv_rows(
                report / "evidence" / "api_changes" / "all_changed_apis.csv"
            )
            api_truth = expected["expected_api"]
            removed_rows = [
                row for row in api_rows
                if row.get("api_name") == "demo.Api.removed"
                and row.get("symbol_kind") == "method"
                and row.get("change_type") == "REMOVED"
            ]
            self.assertEqual(len(removed_rows), 1, api_rows)
            api_fields = (
                "coord", "api_name", "symbol_kind", "change_type", "severity"
            )
            self.assertEqual(
                sorted(
                    ({field: row[field] for field in api_fields} for row in api_rows),
                    key=lambda row: (row["coord"], row["api_name"]),
                ),
                expected["expected_api_rows"],
            )

            active_path = (
                report / ".runtime" / "binary_authority"
                / "active_binary_generation.json"
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            formal = json.loads((
                active_path.parent / active["generation_directory"]
                / "binary_formal_results.json"
            ).read_text(encoding="utf-8"))
            formal_fields = (
                "dependency_lineages", "base_dependency_coords",
                "current_dependency_coords", "reachability_status",
                "static_linkage_status", "impact_conclusion",
                "runtime_verification_status", "exact_path_exists",
                "possible_path_exists", "path_set_complete",
            )
            formal_projection = sorted((
                {
                    "owner": item.get("display_owner"),
                    "member": item.get("display_member"),
                    "descriptor": item.get("display_descriptor"),
                    "member_kind": item.get("display_member_kind"),
                    **{field: item[field] for field in formal_fields},
                    "paths": [
                        {
                            "certainty": path["path_certainty"],
                            "text": path["path_text"],
                        }
                        for path in item.get("paths") or []
                    ],
                }
                for item in formal["by_api"]
            ), key=lambda item: (
                item["owner"] or "", item["member"] or "",
                item["descriptor"] or "", item["member_kind"] or "",
            ))
            self.assertEqual(
                formal_projection,
                sorted(expected["expected_formal_results"], key=lambda item: (
                    item["owner"] or "", item["member"] or "",
                    item["descriptor"] or "", item["member_kind"] or "",
                )),
            )
            matching_formal_rows = [
                row for row in formal["by_api"]
                if row.get("display_owner") == api_truth["owner"]
                and row.get("display_member") == api_truth["member"]
                and row.get("display_descriptor") == api_truth["descriptor"]
                and row.get("display_member_kind") == api_truth["member_kind"]
            ]
            self.assertEqual(len(matching_formal_rows), 1, formal["by_api"])
            row = matching_formal_rows[0]
            projection = {
                "owner": row["display_owner"],
                "member": row["display_member"],
                "descriptor": row["display_descriptor"],
                "member_kind": row["display_member_kind"],
                **{
                    field: row[field]
                    for field in (
                        "reachability_status", "static_linkage_status",
                        "impact_conclusion", "exact_path_exists",
                    )
                },
            }
            self.assertEqual(projection, api_truth)

            findings = json.loads((
                report / ".runtime" / "findings" / "s6_findings.json"
            ).read_text(encoding="utf-8"))
            report_contract = expected["expected_report_contract"]
            for field, value in report_contract["analysis_scope"].items():
                self.assertEqual(
                    findings["analysis_scope"][field], value,
                    (field, findings["analysis_scope"]),
                )
            for bucket, count in report_contract[
                "finding_bucket_counts"
            ].items():
                self.assertEqual(len(findings[bucket]), count, bucket)
            self.assertEqual(findings["diagnostics"], [])
            for relative, count in report_contract["csv_row_counts"].items():
                self.assertEqual(len(read_csv_rows(report / relative)), count, relative)
            for relative in report_contract["utf8_bom_csvs"]:
                self.assertTrue(
                    (report / relative).read_bytes().startswith(b"\xef\xbb\xbf"),
                    relative,
                )
            report_text = (
                report / "deliverables" / "report.md"
            ).read_text(encoding="utf-8")
            self.assertIn("API 汇总覆盖 2/2", report_text)
            self.assertNotIn("分析范围无法核验", report_text)
            scope_text = (
                report / "deliverables" / "analysis-scope.md"
            ).read_text(encoding="utf-8")
            self.assertIn("**模式**：全量", scope_text)
            self.assertIn("纳入本轮分析 2；未纳入 0", scope_text)
            for relative_path in expected["required_outputs"]:
                self.assertTrue((report / relative_path).exists(), relative_path)


if __name__ == "__main__":
    unittest.main()
