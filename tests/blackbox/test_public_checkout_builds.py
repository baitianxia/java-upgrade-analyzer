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
    / "checkout_builds_v1.json"
).read_text(encoding="utf-8"))


def run(
    command: list[str], *, cwd: Path | None = None, timeout: int = 240,
    environment: dict[str, str] | None = None,
):
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout={completed.stdout[-4000:]}\nstderr={completed.stderr[-4000:]}"
        )
    return completed


def run_workflow(*arguments: str, environment: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_step.py"), *arguments],
        cwd=str(ROOT),
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=300,
    )


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.strip() + "\n", encoding="utf-8")


def git_repository(
    root: Path, git: str, files: dict[str, str | bytes],
) -> tuple[Path, str, str]:
    origin = root / "origin.git"
    project = root / "project"
    run([git, "init", "--bare", str(origin)])
    project.mkdir()
    run([git, "init"], cwd=project)
    run([git, "config", "user.name", "Build Oracle"], cwd=project)
    run([git, "config", "user.email", "build@example.invalid"], cwd=project)
    run([git, "remote", "add", "origin", str(origin)], cwd=project)
    for relative, content in files.items():
        if isinstance(content, bytes):
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        else:
            write_text(project / relative, content)
    if (project / "gradlew").exists():
        (project / "gradlew").chmod(0o755)
    run([git, "add", "."], cwd=project)
    run([git, "commit", "-m", "base"], cwd=project)
    run([git, "branch", "-M", "base"], cwd=project)
    base_commit = run([git, "rev-parse", "HEAD"], cwd=project).stdout.strip()
    run([git, "push", "-u", "origin", "base"], cwd=project)

    application = project / "src" / "main" / "java" / "example" / "Application.java"
    application.write_text(
        application.read_text(encoding="utf-8").replace(
            'return "base";', 'return "current";'
        ),
        encoding="utf-8",
    )
    run([git, "add", "."], cwd=project)
    run([git, "commit", "-m", "current"], cwd=project)
    run([git, "branch", "-M", "current"], cwd=project)
    current_commit = run([git, "rev-parse", "HEAD"], cwd=project).stdout.strip()
    run([git, "push", "-u", "origin", "current"], cwd=project)
    return project, base_commit, current_commit


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
        if "java.home" in line and "=" in line:
            path = Path(line.split("=", 1)[1].strip()).resolve()
            if path.is_dir() and (path / "jmods").is_dir():
                return path
    raise AssertionError("full JDK home not found")


def jdk_major_from_home(home: Path) -> str:
    release = home / "release"
    if not release.is_file():
        return ""
    for line in release.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("JAVA_VERSION="):
            continue
        version = line.split("=", 1)[1].strip().strip('"')
        return version.split(".", 2)[1] if version.startswith("1.") else version.split(".", 1)[0]
    return ""


def find_jdk_home(java: str, major: int) -> Path | None:
    candidates = []
    for name in (f"JAVA{major}_HOME", f"JAVA_{major}_HOME", f"JDK{major}_HOME", "JAVA_HOME"):
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
    java_name = "java.exe" if os.name == "nt" else "java"
    javac_name = "javac.exe" if os.name == "nt" else "javac"
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if (
            jdk_major_from_home(resolved) == str(major)
            and (resolved / "bin" / java_name).is_file()
            and (resolved / "bin" / javac_name).is_file()
        ):
            return resolved
    return None


def find_gradle() -> Path:
    direct = shutil.which("gradle")
    if direct:
        return Path(direct).resolve()
    configured = os.environ.get("GRADLE_HOME", "")
    if configured:
        candidate = Path(configured) / "bin" / "gradle"
        if candidate.is_file():
            return candidate.resolve()
    candidates = sorted(
        (Path.home() / ".gradle" / "wrapper" / "dists").glob(
            "gradle-*-bin/*/gradle-*/bin/gradle"
        ),
        reverse=True,
    )
    if candidates:
        return candidates[0].resolve()
    raise AssertionError("a real Gradle distribution is required")


def maven_files() -> dict[str, str]:
    return {
        "pom.xml": """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>blackbox</groupId><artifactId>maven-app</artifactId>
              <version>1.0.0</version>
              <properties>
                <maven.compiler.release>17</maven.compiler.release>
                <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>org.apache.commons</groupId>
                  <artifactId>commons-lang3</artifactId>
                  <version>3.14.0</version>
                </dependency>
              </dependencies>
              <build><plugins>
                <plugin>
                  <groupId>org.apache.maven.plugins</groupId>
                  <artifactId>maven-compiler-plugin</artifactId>
                  <version>3.14.1</version>
                </plugin>
                <plugin>
                  <groupId>org.springframework.boot</groupId>
                  <artifactId>spring-boot-maven-plugin</artifactId>
                  <version>3.5.16</version>
                  <executions><execution><goals><goal>repackage</goal></goals></execution></executions>
                  <configuration><mainClass>example.Application</mainClass></configuration>
                </plugin>
              </plugins></build>
            </project>
        """,
        "src/main/java/example/Application.java": """
            package example;
            import org.apache.commons.lang3.StringUtils;
            public final class Application {
                public static void main(String[] args) { System.out.print(value()); }
                static String value() { StringUtils.isBlank("x"); return "base"; }
            }
        """,
    }


def gradle_files(gradle: Path) -> dict[str, str | bytes]:
    dependency_buffer = io.BytesIO()
    with zipfile.ZipFile(dependency_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fixture/resource.txt", "independent-runtime-dependency")
        archive.writestr(
            "META-INF/maven/org.example/gradle-lib/pom.properties",
            "groupId=org.example\nartifactId=gradle-lib\nversion=1.0.0\n",
        )
    return {
        "settings.gradle": "rootProject.name = 'gradle-app'",
        "build.gradle": """
            plugins {
                id 'java'
            }
            group = 'blackbox'
            version = '1.0.0'
            repositories { maven { url = uri('fixture-repo') } }
            dependencies { runtimeOnly 'org.example:gradle-lib:1.0.0' }
            java {
                sourceCompatibility = JavaVersion.VERSION_17
                targetCompatibility = JavaVersion.VERSION_17
            }
            tasks.named('jar') {
                into('BOOT-INF/lib') { from configurations.runtimeClasspath }
            }
        """,
        "gradlew": f"""
            #!/bin/sh
            exec {str(gradle)!r} --offline --no-daemon "$@"
        """,
        "src/main/java/example/Application.java": """
            package example;
            public final class Application {
                public static void main(String[] args) { System.out.print(value()); }
                static String value() { return "base"; }
            }
        """,
        "fixture-repo/org/example/gradle-lib/1.0.0/gradle-lib-1.0.0.jar": (
            dependency_buffer.getvalue()
        ),
        "fixture-repo/org/example/gradle-lib/1.0.0/gradle-lib-1.0.0.pom": """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>org.example</groupId>
              <artifactId>gradle-lib</artifactId>
              <version>1.0.0</version>
            </project>
        """,
    }


class PublicCheckoutBuildBlackboxTest(unittest.TestCase):
    def exercise(self, *, tool: str, files: dict[str, str | bytes]) -> None:
        expected = TRUTH[tool]
        git = shutil.which("git") or ""
        java = shutil.which("java") or ""
        self.assertTrue(git and java)
        jdk_home = find_jdk_home(java, 17)
        self.assertIsNotNone(
            jdk_home,
            f"the {tool} checkout-build fixture requires a real JDK 17 home",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = None
            if tool == "gradle":
                # Gradle extracts native libraries into its user home.  A
                # process killed during extraction can poison the shared home
                # and make an otherwise valid checkout non-runnable.  The
                # black-box contract owns an isolated home so its result does
                # not depend on mutable machine-global cache state.
                environment = dict(os.environ)
                environment["GRADLE_USER_HOME"] = str(root / "gradle-user-home")
            project, base_commit, current_commit = git_repository(root, git, files)
            report = root / "report"
            common = (
                "--project-dir", str(project),
                "--report-dir", str(report),
            )
            first = run_workflow(
                "--step", "step0", *common,
                "--base-branch", "origin/base",
                "--current-branch", "origin/current",
                "--application-source", str(project),
                "--base-jdk-home", str(jdk_home),
                "--current-jdk-home", str(jdk_home),
                "--target-module", ".",
                "--base-tool", tool,
                "--current-tool", tool,
                environment=environment,
            )
            self.assertEqual(
                first.returncode, TRUTH["checkpoint"]["exit_code"],
                first.stderr,
            )
            interaction = json.loads((
                report / ".runtime" / "state" / "interaction.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(interaction["step_id"], TRUTH["checkpoint"]["step_id"])
            self.assertEqual(
                interaction["kind"], TRUTH["checkpoint"]["kind"],
                f"interaction={interaction}\nstderr={first.stderr}",
            )
            confirmed = run_workflow(
                "--step", "step0", *common,
                "--response-json", json.dumps({"action": "continue"}),
                environment=environment,
            )
            self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
            completed = run_workflow(
                "--step", "step1", *common, environment=environment,
            )
            self.assertEqual(
                completed.returncode, TRUTH["step1_exit_code"], completed.stderr
            )

            provenance = json.loads((
                report / "evidence" / "dependencies" / "build_provenance.json"
            ).read_text(encoding="utf-8"))
            sides = {row["side"]: row for row in provenance["sides"]}
            for side, commit in (("base", base_commit), ("current", current_commit)):
                row = sides[side]
                self.assertEqual(row["input_mode"], "checkout_build")
                self.assertTrue(row["build_executed_by_system"])
                self.assertEqual(row["build_execution_status"], "succeeded")
                self.assertEqual(row["build_tool"], expected["build_tool"])
                self.assertEqual(row["revision"], commit)
                artifact = Path(row["artifact_path"])
                self.assertTrue(artifact.is_file())
                self.assertEqual(
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    row["artifact_sha256"],
                )
                with zipfile.ZipFile(artifact) as archive:
                    self.assertIn(expected["nested_prefix"], archive.namelist())

            manifest = json.loads((
                report / "evidence" / "dependencies" / "dependency_jars.json"
            ).read_text(encoding="utf-8"))
            dependency_rows = [
                row for row in manifest["items"]
                if row["coord"] == expected["dependency_coord"]
            ]
            self.assertEqual(len(dependency_rows), 2, dependency_rows)
            for row in dependency_rows:
                self.assertEqual(row["version"], expected["dependency_version"])
                retained = Path(row["retained_path"])
                with zipfile.ZipFile(retained) as archive:
                    metadata_names = [
                        name for name in archive.namelist()
                        if name.endswith("/pom.properties")
                    ]
                    self.assertEqual(len(metadata_names), 1)
                    metadata = archive.read(metadata_names[0]).decode("iso-8859-1")
                self.assertIn(
                    f'version={expected["dependency_version"]}', metadata
                )

    def test_maven_checkout_build_matches_independent_artifact_truth(self):
        self.assertTrue(shutil.which("mvn"), "a real Maven executable is required")
        self.exercise(tool="maven", files=maven_files())

    def test_gradle_checkout_build_matches_independent_artifact_truth(self):
        gradle = find_gradle()
        self.exercise(tool="gradle", files=gradle_files(gradle))


if __name__ == "__main__":
    unittest.main()
