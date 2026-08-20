import io
import json
import multiprocessing
import os
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402
import process_lock  # noqa: E402


def _concurrent_background_launcher_worker(
    project_dir_value,
    report_dir_value,
    acquisition_barrier,
    result_queue,
):
    """Synchronize immediately before the cross-process launcher lock."""
    args = SimpleNamespace(
        step="step5",
        project_dir=project_dir_value,
        report_dir=report_dir_value,
    )
    real_acquire = run_step._acquire_background_lock
    spawned = False

    @contextmanager
    def synchronized_acquire(path, *, timeout_seconds, purpose):
        if Path(path).name == run_step.BACKGROUND_LAUNCHER_LOCK_FILE_NAME:
            acquisition_barrier.wait(timeout=15.0)
        with real_acquire(
            path,
            timeout_seconds=timeout_seconds,
            purpose=purpose,
        ) as acquired:
            yield acquired

    def fake_popen(*_args, **_kwargs):
        nonlocal spawned
        spawned = True
        return SimpleNamespace(pid=os.getpid())

    argv = [
        "--step",
        "step5",
        "--project-dir",
        project_dir_value,
        "--report-dir",
        report_dir_value,
        "--background",
    ]
    try:
        with patch.object(run_step, "_acquire_background_lock", synchronized_acquire), \
             patch.object(run_step.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(sys, "stderr", io.StringIO()):
            run_step.start_background_run(args, argv)
    except run_step.StepError as exc:
        if "已有后台分析任务" in str(exc):
            result_queue.put(("blocked", spawned))
        else:
            result_queue.put((f"unexpected:StepError:{exc}", spawned))
    except BaseException as exc:  # pragma: no cover - surfaced to the parent assertion.
        result_queue.put((f"unexpected:{type(exc).__name__}:{exc}", spawned))
    else:
        result_queue.put(("launched", spawned))


def _crash_after_background_spawn_worker(
    project_dir_value,
    report_dir_value,
    bootstrap_dir_value,
    child_release_path_value,
):
    """Exit after Popen succeeds but before the parent can publish child PID."""
    args = SimpleNamespace(
        step="step0",
        project_dir=project_dir_value,
        report_dir=report_dir_value,
    )
    status_path = run_step.background_status_path(report_dir_value).resolve()
    real_write = run_step._write_background_json
    inherited_python_path = str(os.environ.get("PYTHONPATH") or "")
    os.environ["PYTHONPATH"] = os.pathsep.join(
        value
        for value in (bootstrap_dir_value, inherited_python_path)
        if value
    )
    os.environ["JUA_TEST_BACKGROUND_CHILD_RELEASE"] = child_release_path_value

    def crash_before_pid_publish(path, data):
        if (
            Path(path).resolve() == status_path
            and str((data or {}).get("status") or "") == "starting"
            and (data or {}).get("pid") is not None
        ):
            os._exit(77)
        real_write(path, data)

    argv = [
        "--step",
        "step0",
        "--project-dir",
        project_dir_value,
        "--report-dir",
        report_dir_value,
        "--background",
    ]
    with patch.object(
        run_step, "_write_background_json", side_effect=crash_before_pid_publish
    ):
        run_step.start_background_run(args, argv)


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
        self.assertEqual(
            spawn_kwargs["env"][run_step.BACKGROUND_CLAIM_TOKEN_ENV],
            status["claim_token"],
        )
        self.assertEqual(environment["path"], foreground_path)
        self.assertEqual(environment["path_source"], "current_process")
        self.assertEqual(status["schema"], run_step.BACKGROUND_STATUS_SCHEMA)
        self.assertEqual(status["status"], "starting")
        self.assertEqual(status["pid"], 43210)
        self.assertGreater(status["starting_deadline_epoch"], time.time())
        self.assertIn("状态：", stderr.getvalue())
        self.assertIn("日志：", stderr.getvalue())

    def test_background_platform_flags_do_not_require_nohup(self):
        self.assertEqual(
            run_step._background_platform_kwargs("nt"),
            {"creationflags": 0x08000000 | 0x00000200},
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

    def test_background_lock_preserves_body_error_when_unlock_also_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "launcher.lock"
            with patch.object(
                process_lock,
                "_unlock",
                side_effect=OSError("secondary unlock failure"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "primary transaction failure"
                ) as raised:
                    with run_step._acquire_background_lock(
                        lock_path,
                        timeout_seconds=1.0,
                        purpose="测试锁",
                    ):
                        raise RuntimeError("primary transaction failure")

            notes = list(getattr(raised.exception, "__notes__", []))
            if hasattr(raised.exception, "add_note"):
                self.assertTrue(
                    any("secondary unlock failure" in note for note in notes)
                )
            with run_step.exclusive_file_lock(lock_path, timeout_seconds=1.0):
                pass

    def test_background_completion_updates_stable_status_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                    "run_id": "run-1",
                    "claim_token": "claim-1",
                    "status": "starting",
                    "pid": None,
                    "exit_code": None,
                },
            )
            with patch.dict(
                os.environ,
                {
                    run_step.BACKGROUND_CHILD_ENV: "1",
                    run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                    run_step.BACKGROUND_RUN_ID_ENV: "run-1",
                    run_step.BACKGROUND_CLAIM_TOKEN_ENV: "claim-1",
                },
            ):
                with run_step._background_child_lease() as ownership:
                    running = json.loads(status_path.read_text(encoding="utf-8"))
                    self.assertEqual(running["status"], "running")
                    self.assertEqual(running["pid"], os.getpid())
                    self.assertTrue(
                        run_step._background_active_lease_is_held(status_path)
                    )
                    self.assertTrue(
                        run_step.finish_background_run(
                            run_step.EXIT_AWAITING_USER,
                            configuration=ownership,
                        )
                    )
                self.assertFalse(
                    run_step._background_active_lease_is_held(status_path)
                )
            payload = json.loads(status_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["status"], "awaiting_user")
        self.assertEqual(payload["exit_code"], run_step.EXIT_AWAITING_USER)
        self.assertEqual(payload["pid"], os.getpid())
        self.assertTrue(payload["finished_at"])

    def test_cli_child_holds_lease_through_fenced_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_path = run_step.background_status_path(
                Path(tmp) / ".upgrade-report"
            )
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                    "run_id": "cli-run",
                    "claim_token": "cli-claim",
                    "status": "starting",
                    "pid": os.getpid(),
                    "exit_code": None,
                    "starting_deadline_epoch": time.time() + 60.0,
                },
            )

            def main_while_leased(_argv):
                running = run_step._read_background_json(status_path)
                self.assertEqual(running["status"], "running")
                self.assertTrue(
                    run_step._background_active_lease_is_held(status_path)
                )
                for key in (
                    run_step.BACKGROUND_CHILD_ENV,
                    run_step.BACKGROUND_STATUS_PATH_ENV,
                    run_step.BACKGROUND_RUN_ID_ENV,
                    run_step.BACKGROUND_CLAIM_TOKEN_ENV,
                ):
                    self.assertNotIn(key, os.environ)
                return 0

            with patch.dict(
                os.environ,
                {
                    run_step.BACKGROUND_CHILD_ENV: "1",
                    run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                    run_step.BACKGROUND_RUN_ID_ENV: "cli-run",
                    run_step.BACKGROUND_CLAIM_TOKEN_ENV: "cli-claim",
                },
            ), patch.object(run_step, "main", side_effect=main_while_leased), \
                 patch.object(sys, "stderr", io.StringIO()):
                return_code = run_step.cli_main([])

            completed = run_step._read_background_json(status_path)
            lease_held_after_exit = run_step._background_active_lease_is_held(
                status_path
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["exit_code"], 0)
        self.assertFalse(lease_held_after_exit)

    def test_background_launch_rejects_a_second_live_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                    "run_id": "existing",
                    "claim_token": "existing-claim",
                    "status": "running",
                    "pid": os.getpid(),
                },
            )
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            active_lock = run_step.background_active_lock_path(report_dir)
            with run_step.exclusive_file_lock(active_lock, timeout_seconds=1.0), \
                 patch.object(run_step.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(run_step.StepError, "已有后台分析任务"):
                    run_step.start_background_run(
                        args, ["--step", "step5", "--background"]
                    )

        popen.assert_not_called()

    def test_concurrent_launchers_spawn_exactly_one_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            context = multiprocessing.get_context("spawn")
            acquisition_barrier = context.Barrier(2)
            result_queue = context.Queue()
            processes = [
                context.Process(
                    target=_concurrent_background_launcher_worker,
                    args=(
                        str(project_dir),
                        str(report_dir),
                        acquisition_barrier,
                        result_queue,
                    ),
                )
                for _ in range(2)
            ]
            try:
                for process in processes:
                    process.start()
                results = [result_queue.get(timeout=30.0) for _ in processes]
                for process in processes:
                    process.join(timeout=30.0)
                self.assertTrue(all(not process.is_alive() for process in processes))
                self.assertTrue(all(process.exitcode == 0 for process in processes))
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                    process.join(timeout=5.0)
                result_queue.close()
                result_queue.join_thread()

        self.assertCountEqual(results, [("launched", True), ("blocked", False)])

    def test_child_claims_parent_crash_window_before_pid_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            status_payload = {
                "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                "run_id": "crashed-parent-run",
                "claim_token": "crashed-parent-claim",
                "status": "starting",
                "launcher_pid": 999999,
                "pid": None,
                "starting_deadline_epoch": time.time() + 60.0,
            }
            run_step._write_background_json(status_path, status_payload)
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            with patch.object(run_step.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(run_step.StepError, "已有后台分析任务"):
                    run_step.start_background_run(
                        args, ["--step", "step5", "--background"]
                    )
            popen.assert_not_called()

            with patch.dict(
                os.environ,
                {
                    run_step.BACKGROUND_CHILD_ENV: "1",
                    run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                    run_step.BACKGROUND_RUN_ID_ENV: "crashed-parent-run",
                    run_step.BACKGROUND_CLAIM_TOKEN_ENV: "crashed-parent-claim",
                },
            ):
                with run_step._background_child_lease() as ownership:
                    running = run_step._read_background_json(status_path)
                    self.assertEqual(running["status"], "running")
                    self.assertEqual(running["pid"], os.getpid())
                    self.assertTrue(
                        run_step._background_record_is_live(
                            running, status_path=status_path
                        )
                    )
                    self.assertTrue(
                        run_step.finish_background_run(
                            0, configuration=ownership
                        )
                    )

            completed = run_step._read_background_json(status_path)

        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["run_id"], "crashed-parent-run")

    def test_real_child_survives_parent_crash_after_spawn_before_pid_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_dir = root / "project"
            report_dir = project_dir / ".upgrade-report"
            bootstrap_dir = root / "bootstrap"
            child_release_path = root / "allow-child-start"
            project_dir.mkdir()
            bootstrap_dir.mkdir()
            (bootstrap_dir / "sitecustomize.py").write_text(
                "import os\n"
                "import time\n"
                "from pathlib import Path\n"
                "marker = os.environ.get('JUA_TEST_BACKGROUND_CHILD_RELEASE')\n"
                "deadline = time.monotonic() + 30.0\n"
                "while marker and not Path(marker).exists() and time.monotonic() < deadline:\n"
                "    time.sleep(0.01)\n",
                encoding="utf-8",
            )
            context = multiprocessing.get_context("spawn")
            launcher = context.Process(
                target=_crash_after_background_spawn_worker,
                args=(
                    str(project_dir),
                    str(report_dir),
                    str(bootstrap_dir),
                    str(child_release_path),
                ),
            )
            launcher.start()
            launcher.join(timeout=30.0)
            try:
                self.assertFalse(launcher.is_alive())
                self.assertEqual(launcher.exitcode, 77)
                status_path = run_step.background_status_path(report_dir)
                crash_window = run_step._read_background_json(status_path)
                self.assertEqual(crash_window["status"], "starting")
                self.assertIsNone(crash_window["pid"])

                args = SimpleNamespace(
                    step="step0",
                    project_dir=str(project_dir),
                    report_dir=str(report_dir),
                )
                with patch.object(run_step.subprocess, "Popen") as duplicate_spawn:
                    with self.assertRaisesRegex(
                        run_step.StepError, "已有后台分析任务"
                    ):
                        run_step.start_background_run(
                            args,
                            [
                                "--step",
                                "step0",
                                "--project-dir",
                                str(project_dir),
                                "--report-dir",
                                str(report_dir),
                                "--background",
                            ],
                        )
                duplicate_spawn.assert_not_called()
            finally:
                child_release_path.write_text("continue\n", encoding="utf-8")
                if launcher.is_alive():
                    launcher.terminate()
                launcher.join(timeout=5.0)

            deadline = time.monotonic() + 30.0
            terminal = {}
            while time.monotonic() < deadline:
                terminal = run_step._read_background_json(status_path)
                if str(terminal.get("status") or "") not in {
                    "starting",
                    "running",
                }:
                    break
                time.sleep(0.02)

            self.assertIn(
                terminal.get("status"),
                {"completed", "awaiting_user", "interrupted", "failed"},
            )
            self.assertEqual(terminal["run_id"], crash_window["run_id"])
            self.assertFalse(
                run_step._background_active_lease_is_held(status_path)
            )

    def test_expired_starting_claim_is_recoverable(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                    "run_id": "crashed-before-spawn",
                    "claim_token": "stale-claim",
                    "status": "starting",
                    "pid": None,
                    "starting_deadline_epoch": time.time() - 1.0,
                },
            )
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            with patch.object(
                run_step.subprocess,
                "Popen",
                return_value=SimpleNamespace(pid=43210),
            ) as popen, patch.object(sys, "stderr", io.StringIO()):
                replacement = run_step.start_background_run(
                    args, ["--step", "step5", "--background"]
                )

        popen.assert_called_once()
        self.assertNotEqual(replacement["run_id"], "crashed-before-spawn")
        self.assertNotEqual(replacement["claim_token"], "stale-claim")
        self.assertEqual(replacement["status"], "starting")

    def test_mismatched_child_identity_fails_closed_before_main(self):
        cases = (
            ("other-run", "stored-claim", "child-run", "stored-claim"),
            ("stored-run", "other-claim", "stored-run", "child-claim"),
        )
        for stored_run, stored_claim, child_run, child_claim in cases:
            with self.subTest(stored_run=stored_run, stored_claim=stored_claim), \
                 tempfile.TemporaryDirectory() as tmp:
                status_path = run_step.background_status_path(
                    Path(tmp) / ".upgrade-report"
                )
                original = {
                    "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                    "run_id": stored_run,
                    "claim_token": stored_claim,
                    "status": "starting",
                    "pid": None,
                    "starting_deadline_epoch": time.time() + 60.0,
                }
                run_step._write_background_json(status_path, original)
                with patch.dict(
                    os.environ,
                    {
                        run_step.BACKGROUND_CHILD_ENV: "1",
                        run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                        run_step.BACKGROUND_RUN_ID_ENV: child_run,
                        run_step.BACKGROUND_CLAIM_TOKEN_ENV: child_claim,
                    },
                ), patch.object(run_step, "main") as main, patch.object(
                    sys, "stderr", io.StringIO()
                ):
                    return_code = run_step.cli_main([])

                self.assertEqual(return_code, 1)
                main.assert_not_called()
                self.assertEqual(run_step._read_background_json(status_path), original)

    def test_old_child_cannot_overwrite_newer_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_path = run_step.background_status_path(
                Path(tmp) / ".upgrade-report"
            )
            newer = {
                "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                "run_id": "new-run",
                "claim_token": "new-claim",
                "status": "running",
                "pid": os.getpid(),
                "exit_code": None,
            }
            run_step._write_background_json(status_path, newer)
            with patch.dict(
                os.environ,
                {
                    run_step.BACKGROUND_CHILD_ENV: "1",
                    run_step.BACKGROUND_STATUS_PATH_ENV: str(status_path),
                    run_step.BACKGROUND_RUN_ID_ENV: "new-run",
                    run_step.BACKGROUND_CLAIM_TOKEN_ENV: "old-claim",
                },
            ):
                published = run_step.finish_background_run(0)

            persisted = run_step._read_background_json(status_path)

        self.assertFalse(published)
        self.assertEqual(persisted, newer)

    def test_active_lease_not_pid_is_authoritative_for_liveness(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            status_path = run_step.background_status_path(report_dir)
            payload = {
                "schema": run_step.BACKGROUND_STATUS_SCHEMA,
                "run_id": "reused-pid-run",
                "claim_token": "reused-pid-claim",
                "status": "running",
                "pid": os.getpid(),
            }
            run_step._write_background_json(status_path, payload)

            with patch.object(run_step, "_pid_is_running", return_value=True) as pid_check:
                self.assertFalse(
                    run_step._background_record_is_live(
                        payload, status_path=status_path
                    )
                )
            pid_check.assert_not_called()

            active_lock = run_step.background_active_lock_path(report_dir)
            with run_step.exclusive_file_lock(active_lock, timeout_seconds=1.0), \
                 patch.object(run_step, "_pid_is_running", return_value=False) as pid_check:
                self.assertTrue(
                    run_step._background_record_is_live(
                        payload, status_path=status_path
                    )
                )
            pid_check.assert_not_called()

    def test_fresh_v1_running_record_uses_bounded_pid_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_LEGACY_STATUS_SCHEMA,
                    "run_id": "legacy-running",
                    "status": "running",
                    "pid": 45678,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            with patch.object(
                run_step, "_pid_is_running", return_value=True
            ) as pid_check, patch.object(run_step.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(
                    run_step.StepError, "已有后台分析任务"
                ):
                    run_step.start_background_run(
                        args, ["--step", "step5", "--background"]
                    )

        pid_check.assert_called_once_with(45678)
        popen.assert_not_called()

    def test_v1_running_record_without_started_at_uses_recent_status_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            status_path = run_step.background_status_path(
                Path(tmp) / ".upgrade-report"
            )
            payload = {
                "schema": run_step.BACKGROUND_LEGACY_STATUS_SCHEMA,
                "run_id": "legacy-mtime",
                "status": "running",
                "pid": 56789,
            }
            run_step._write_background_json(status_path, payload)

            with patch.object(
                run_step, "_pid_is_running", return_value=True
            ) as pid_check:
                live = run_step._background_record_is_live(
                    payload,
                    status_path=status_path,
                    now_epoch=status_path.stat().st_mtime + 1.0,
                )

        self.assertTrue(live)
        pid_check.assert_called_once_with(56789)

    def test_expired_v1_running_record_does_not_trust_reused_live_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            status_path = run_step.background_status_path(report_dir)
            expired_started_at = datetime.fromtimestamp(
                time.time()
                - run_step.BACKGROUND_LEGACY_RUNNING_GRACE_SECONDS
                - 1.0,
                timezone.utc,
            ).isoformat()
            run_step._write_background_json(
                status_path,
                {
                    "schema": run_step.BACKGROUND_LEGACY_STATUS_SCHEMA,
                    "run_id": "expired-legacy-running",
                    "status": "running",
                    "pid": 67890,
                    "started_at": expired_started_at,
                },
            )
            args = SimpleNamespace(
                step="step5",
                project_dir=str(project_dir),
                report_dir=str(report_dir),
            )

            with patch.object(
                run_step, "_pid_is_running", return_value=True
            ) as pid_check, patch.object(
                run_step.subprocess,
                "Popen",
                return_value=SimpleNamespace(pid=43210),
            ) as popen, patch.object(sys, "stderr", io.StringIO()):
                replacement = run_step.start_background_run(
                    args, ["--step", "step5", "--background"]
                )

        pid_check.assert_not_called()
        popen.assert_called_once()
        self.assertEqual(replacement["schema"], run_step.BACKGROUND_STATUS_SCHEMA)
        self.assertNotEqual(replacement["run_id"], "expired-legacy-running")

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
