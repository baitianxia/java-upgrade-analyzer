import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402


class RunStepBackgroundTest(unittest.TestCase):
    def test_background_launch_persists_and_explicitly_injects_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )
            process = SimpleNamespace(pid=43210)
            stderr = io.StringIO()
            foreground_path = os.pathsep.join((str(project_dir / "git-bin"), str(project_dir / "jdk-bin")))

            with patch.dict(os.environ, {"PATH": foreground_path}), \
                 patch.object(run_step.subprocess, "Popen", return_value=process) as popen, \
                 patch.object(sys, "stderr", stderr):
                payload = run_step.start_background_run(
                    args,
                    [
                        "--step", "step5",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                        "--background",
                    ],
                )

            command = list(popen.call_args.args[0])
            spawn_kwargs = popen.call_args.kwargs
            environment = json.loads(
                Path(payload["environment_path"]).read_text(encoding="utf-8")
            )
            status = json.loads(
                run_step.background_status_path(report_dir).read_text(encoding="utf-8")
            )

        self.assertEqual(command[0], sys.executable)
        self.assertNotIn("--background", command)
        self.assertEqual(spawn_kwargs["env"]["PATH"], foreground_path)
        self.assertEqual(environment["path"], foreground_path)
        self.assertEqual(environment["path_source"], "current_process")
        self.assertEqual(status["status"], "running")
        self.assertEqual(status["pid"], 43210)
        self.assertIn("状态：", stderr.getvalue())
        self.assertIn("日志：", stderr.getvalue())

    def test_background_platform_flags_do_not_require_nohup(self):
        self.assertEqual(
            run_step._background_platform_kwargs("nt"),
            {"creationflags": 0x00000200 | 0x00000008},
        )
        self.assertEqual(
            run_step._background_platform_kwargs("posix"),
            {"start_new_session": True},
        )

    def test_windows_liveness_check_does_not_send_a_signal(self):
        with patch.object(run_step, "_windows_pid_is_running", return_value=True) as windows_check, \
             patch.object(run_step.os, "kill") as kill:
            running = run_step._pid_is_running(43210, platform_name="nt")

        self.assertTrue(running)
        windows_check.assert_called_once_with(43210)
        kill.assert_not_called()

    def test_background_completion_updates_stable_status_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "schema": "java-upgrade-analyzer.background-run.v1",
                    "run_id": "run-1",
                    "status": "running",
                    "pid": 123,
                    "exit_code": None,
                },
            )
            with patch.dict(
                os.environ,
                {
                    run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                    run_step.BACKGROUND_RUN_ID_ENV: "run-1",
                },
            ):
                run_step.finish_background_run(run_step.EXIT_AWAITING_USER)
            payload = json.loads(status_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "awaiting_user")
        self.assertEqual(payload["exit_code"], run_step.EXIT_AWAITING_USER)
        self.assertEqual(payload["pid"], 123)
        self.assertTrue(payload["finished_at"])

    def test_background_launch_rejects_a_second_live_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "run_id": "existing",
                    "status": "running",
                    "pid": os.getpid(),
                },
            )
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            with patch.object(run_step.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(run_step.StepError, "已有后台分析任务"):
                    run_step.start_background_run(args, ["--step", "step5", "--background"])

        popen.assert_not_called()

    def test_main_background_flag_dispatches_without_running_the_step_inline(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            argv = [
                "--step", "step5",
                "--project-dir", str(project_dir),
                "--report-dir", str(report_dir),
                "--background",
            ]

            with patch.object(run_step, "start_background_run", return_value={}) as start, \
                 patch.object(run_step, "execute_step") as execute:
                return_code = run_step.main(argv, _skip_environment_contract=True)

        self.assertEqual(return_code, 0)
        start.assert_called_once()
        self.assertEqual(start.call_args.args[1], argv)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
