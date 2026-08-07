import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402
import s2_context_from_deps  # noqa: E402


class GitRemotePipelineEndToEndTest(unittest.TestCase):
    def _git(self, git_executable, cwd, *args):
        completed = subprocess.run(
            [git_executable, *args],
            cwd=str(cwd),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return completed.stdout.strip()

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_transient_remote_failure_and_parent_git_env_pollution_still_pin_step2(self):
        """Exercise the real Step1 remote boundary and the Step1 -> Step2 snapshot."""
        real_git = str(Path(shutil.which("git")).resolve())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "origin.git"
            poison_git_dir = root / "poison.git"
            project = root / "project"
            report_dir = project / ".upgrade-report"

            self._git(real_git, root, "init", "--bare", str(remote))
            self._git(real_git, root, "init", "--bare", str(poison_git_dir))
            self._git(real_git, root, "init", str(project))
            self._git(real_git, project, "config", "user.email", "git-e2e@example.invalid")
            self._git(real_git, project, "config", "user.name", "Git E2E")

            (project / "pom.xml").write_text("<project><!-- base --></project>\n", encoding="utf-8")
            self._git(real_git, project, "add", "pom.xml")
            self._git(real_git, project, "commit", "-m", "base")
            base_commit = self._git(real_git, project, "rev-parse", "HEAD")
            base_ref = "gctcs26.04.27"
            self._git(real_git, project, "branch", base_ref, base_commit)

            (project / "pom.xml").write_text("<project><!-- current --></project>\n", encoding="utf-8")
            self._git(real_git, project, "add", "pom.xml")
            self._git(real_git, project, "commit", "-m", "current")
            current_commit = self._git(real_git, project, "rev-parse", "HEAD")
            current_ref = "gctcs26.08.26.DEV"
            self._git(real_git, project, "branch", current_ref, current_commit)
            self._git(real_git, project, "remote", "add", "origin", str(remote))
            self._git(
                real_git,
                project,
                "push",
                "origin",
                f"refs/heads/{base_ref}:refs/heads/{base_ref}",
                f"refs/heads/{current_ref}:refs/heads/{current_ref}",
            )

            # The reported production shape: current remote ref is exactly the
            # local checkout's HEAD. This must not make remote resolution local-first.
            self.assertEqual(current_commit, self._git(real_git, project, "rev-parse", "HEAD"))
            self.assertEqual(
                current_commit,
                self._git(real_git, project, "ls-remote", "origin", f"refs/heads/{current_ref}").split()[0],
            )

            first_ls_remote_marker = root / "first-ls-remote-failed"
            ls_remote_log = root / "ls-remote.log"
            wrapper = root / "git-with-one-transient-failure"
            wrapper.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *\" ls-remote \"*)\n"
                "    printf '%s\\n' \"$*\" >> \"$JUA_TEST_LS_REMOTE_LOG\"\n"
                "    if mkdir \"$JUA_TEST_FIRST_LS_REMOTE_MARKER\" 2>/dev/null; then\n"
                "      echo 'fatal: unable to access remote: The requested URL returned error: 429' >&2\n"
                "      exit 128\n"
                "    fi\n"
                "    ;;\n"
                "esac\n"
                f"exec {shlex.quote(real_git)} \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)

            main_state = run_step.new_main_state(report_dir)
            initial_context = {
                "analysis_mode": "checkout_build",
                "project_dir": str(project),
                "report_dir": str(report_dir),
                "base_branch": base_ref,
                "current_branch": current_ref,
            }
            run_step.store_step_input(main_state, "step1", initial_context)
            run_step.save_main_state(report_dir, main_state)

            polluted_parent_env = {
                "JUA_GIT_EXECUTABLE": str(wrapper),
                "JUA_TEST_FIRST_LS_REMOTE_MARKER": str(first_ls_remote_marker),
                "JUA_TEST_LS_REMOTE_LOG": str(ls_remote_log),
                # Without the product Git boundary's sanitization, these point
                # every `git -C project ...` call at an unrelated repo which has
                # no remote -- the exact false remote_configuration_missing path.
                "GIT_DIR": str(poison_git_dir),
                "GIT_WORK_TREE": str(project),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "protocol.file.allow",
                "GIT_CONFIG_VALUE_0": "always",
            }

            snapshots = []

            def persist_side_snapshot(context, side, resolution):
                snapshots.append((side, dict(context), dict(resolution)))
                run_step.store_step_input(main_state, "step1", context)
                run_step.save_main_state(report_dir, main_state)

            with patch.dict(os.environ, polluted_parent_env, clear=False), patch(
                "remote_source_refs.time.sleep",
                return_value=None,
            ):
                resolved, interaction = run_step.resolve_step1_refs_for_execution(
                    initial_context,
                    project,
                    on_side_resolved=persist_side_snapshot,
                )
                run_step.persist_completed_step(
                    main_state,
                    "step1",
                    report_dir,
                    resolved,
                )

                with patch.dict(
                    os.environ,
                    {
                        "JUA_ORCHESTRATED": "1",
                        "UPGRADE_REPORT_DIR": str(report_dir),
                    },
                    clear=False,
                ):
                    step2_input = s2_context_from_deps.load_orchestrated_step2_input()
                    step2_base = s2_context_from_deps.require_pinned_git_commit(
                        step2_input["base_resolved_commit"],
                        project,
                        side="base",
                    )
                    step2_current = s2_context_from_deps.require_pinned_git_commit(
                        step2_input["current_resolved_commit"],
                        project,
                        side="current",
                    )

            self.assertIsNone(interaction)
            self.assertTrue(first_ls_remote_marker.is_dir(), "transient ls-remote failure was not injected")
            self.assertGreaterEqual(len(ls_remote_log.read_text(encoding="utf-8").splitlines()), 2)
            self.assertEqual([item[0] for item in snapshots], ["base", "current"])
            self.assertNotIn(
                "remote_configuration_missing",
                {str(item[2].get("source_status") or "") for item in snapshots},
            )
            self.assertEqual(resolved["base_ref_source_status"], "remote_source_resolved")
            self.assertEqual(resolved["current_ref_source_status"], "remote_source_resolved")
            self.assertEqual(resolved["base_ref_remote"], "origin")
            self.assertEqual(resolved["current_ref_remote"], "origin")
            self.assertEqual(resolved["base_resolved_commit"], base_commit)
            self.assertEqual(resolved["current_resolved_commit"], current_commit)
            self.assertEqual(step2_base, base_commit)
            self.assertEqual(step2_current, current_commit)


if __name__ == "__main__":
    unittest.main()
