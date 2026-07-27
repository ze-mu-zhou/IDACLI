"""Tests for the JSONL command entry point."""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import ida_cli
from ida_cli import __main__ as main_mod
from ida_cli import runtime as runtime_mod
from ida_cli.__main__ import _serve, main
from ida_cli.daemon import get_pid_path, get_port_path, get_token_path
from ida_cli.kernel import PythonOnlyBackend, create_session
from ida_cli.runtime import PythonRuntime


def _responses(text: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in text.splitlines() if line]


class MainTests(unittest.TestCase):
    """Verify stdout stays JSONL while the runtime executes multiple requests."""

    def test_cli_loop_executes_multiple_requests_and_preserves_state(self) -> None:
        stdin = io.StringIO(
            '{"id":null,"code":"value = 40 + 2\\n__result__ = value"}\n'
            '{"id":"next","code":"__result__ = value"}\n'
        )
        stdout = io.StringIO()

        with mock.patch(
            "ida_cli.__main__.create_session",
            lambda target: create_session(target, backend=PythonOnlyBackend()),
        ):
            exit_code = main(["sample.i64"], stdin=stdin, stdout=stdout)

        self.assertEqual(exit_code, 0)
        payloads = _responses(stdout.getvalue())
        self.assertEqual(payloads[0]["id"], None)
        self.assertEqual(payloads[0]["result"], 42)
        self.assertEqual(payloads[1]["id"], "next")
        self.assertEqual(payloads[1]["result"], 42)

    def test_bad_json_writes_structured_error_and_survives(self) -> None:
        stdin = io.StringIO('{"code":\n{"id":"after","code":"__result__ = 40 + 2"}\n')
        stdout = io.StringIO()

        with mock.patch(
            "ida_cli.__main__.create_session",
            lambda target: create_session(target, backend=PythonOnlyBackend()),
        ):
            exit_code = main(["sample.i64"], stdin=stdin, stdout=stdout)

        payloads = _responses(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(payloads[0]["ok"])
        self.assertEqual(payloads[0]["error"]["type"], "JSONDecodeError")
        self.assertEqual(payloads[1]["id"], "after")
        self.assertEqual(payloads[1]["result"], 42)

    def test_missing_target_is_protocol_error(self) -> None:
        stdout = io.StringIO()

        exit_code = main([], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["error"]["type"], "CLIArgumentError")


class ServeLoopTests(unittest.TestCase):
    """Exercise _serve edge cases: id correlation and per-line size caps."""

    def test_format_error_preserves_request_id(self) -> None:
        stdin = io.StringIO('{"id": 5, "code": 7}\n{"id": 6, "code": "__result__ = 1"}\n')
        stdout = io.StringIO()

        exit_code = _serve(PythonRuntime(), stdin, stdout)

        payloads = _responses(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(payloads[0]["ok"])
        self.assertEqual(payloads[0]["id"], 5)
        self.assertEqual(payloads[0]["error"]["type"], "RequestFormatError")
        self.assertTrue(payloads[1]["ok"])
        self.assertEqual(payloads[1]["id"], 6)

    def test_oversized_line_gets_error_envelope_and_loop_continues(self) -> None:
        oversized = '{"id":"big","code":"' + ("x" * (17 * 1024 * 1024)) + '"}'
        stdin = io.StringIO(oversized + '\n{"id":"after","code":"__result__ = 7"}\n')
        stdout = io.StringIO()

        exit_code = _serve(PythonRuntime(), stdin, stdout)

        payloads = _responses(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(payloads), 2)
        self.assertFalse(payloads[0]["ok"])
        self.assertEqual(payloads[0]["error"]["type"], "RequestFormatError")
        self.assertIn("size limit", payloads[0]["error"]["message"])
        self.assertTrue(payloads[1]["ok"])
        self.assertEqual(payloads[1]["result"], 7)

    def test_stdio_shutdown_message_is_not_a_control_channel(self) -> None:
        # Without a control handler (stdio mode), {"shutdown": true} is just
        # a malformed request, never a kernel command.
        stdin = io.StringIO('{"shutdown": true}\n{"id":1,"code":"__result__ = 7"}\n')
        stdout = io.StringIO()

        exit_code = _serve(PythonRuntime(), stdin, stdout)

        payloads = _responses(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertFalse(payloads[0]["ok"])
        self.assertEqual(payloads[0]["error"]["type"], "RequestFormatError")
        self.assertTrue(payloads[1]["ok"])
        self.assertEqual(payloads[1]["result"], 7)

    def test_control_handler_intercepts_lines_and_ends_the_loop(self) -> None:
        seen: list[str] = []

        def handler(line: str, out: object) -> bool:
            seen.append(line)
            return True

        stdin = io.StringIO('{"shutdown": true}\n{"id":1,"code":"__result__ = 7"}\n')
        stdout = io.StringIO()

        exit_code = _serve(PythonRuntime(), stdin, stdout, control_handler=handler)

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(seen), 1)
        self.assertIn("shutdown", seen[0])
        # The handler owns the response; _serve writes nothing for that line,
        # and the loop ends before the following request line.
        self.assertEqual(stdout.getvalue(), "")


class _CloseTrackingSession:
    """Session double recording close() calls for daemon lifecycle tests."""

    def __init__(self) -> None:
        self.runtime = object()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _KeyboardInterruptServer:
    """DaemonServer double raising KeyboardInterrupt while serving."""

    instances: ClassVar[list[_KeyboardInterruptServer]] = []

    def __init__(self, target: str, runtime: object) -> None:
        self.handler_seen: object = None
        self.shutdown_called = False
        _KeyboardInterruptServer.instances.append(self)

    def start(self) -> None:
        pass

    def serve_forever(self) -> None:
        self.handler_seen = signal.getsignal(signal.SIGTERM)
        raise KeyboardInterrupt

    def shutdown(self) -> None:
        self.shutdown_called = True


class StdioSignalTests(unittest.TestCase):
    """In stdio mode Ctrl+C must escape the runtime's envelope and exit cleanly."""

    def setUp(self) -> None:
        runtime_mod._SIGNAL_INTERRUPT.clear()
        self.addCleanup(runtime_mod._SIGNAL_INTERRUPT.clear)

    def test_stdio_installs_and_restores_sigint_handler(self) -> None:
        recorded: dict[str, object] = {}

        class _RecordingRuntime:
            def execute_request(self, request: object) -> dict[str, object]:
                recorded["handler"] = signal.getsignal(signal.SIGINT)
                return {"ok": True}

        session = _CloseTrackingSession()
        session.runtime = _RecordingRuntime()
        previous = signal.getsignal(signal.SIGINT)
        with mock.patch("ida_cli.__main__.create_session", return_value=session):
            exit_code = main(
                ["sample.i64"],
                stdin=io.StringIO('{"id":1,"code":"__result__ = 1"}\n'),
                stdout=io.StringIO(),
            )

        self.assertEqual(exit_code, 0)
        self.assertIs(recorded["handler"], main_mod._raise_keyboard_interrupt)
        self.assertIs(signal.getsignal(signal.SIGINT), previous)

    def test_stdio_keyboard_interrupt_exits_cleanly(self) -> None:
        class _InterruptRuntime:
            def execute_request(self, request: object) -> dict[str, object]:
                raise KeyboardInterrupt

        session = _CloseTrackingSession()
        session.runtime = _InterruptRuntime()
        stdout = io.StringIO()
        with mock.patch("ida_cli.__main__.create_session", return_value=session):
            exit_code = main(
                ["sample.i64"],
                stdin=io.StringIO('{"id":1,"code":"__result__ = 1"}\n'),
                stdout=stdout,
            )

        self.assertEqual(exit_code, 0)  # clean exit: no traceback, no envelope spam
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(session.closed)


class ShutdownDaemonTests(unittest.TestCase):
    """Verify --shutdown exit codes, error envelopes, and daemon file cleanup."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._env = mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": self._tmp.name})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.target = "D:/targets/sample.exe"

    def _write_daemon_files(self, pid: int, port: int) -> None:
        Path(get_pid_path(self.target)).write_text(str(pid))
        Path(get_port_path(self.target)).write_text(str(port))
        Path(get_token_path(self.target)).write_text("token")

    def _daemon_paths(self) -> tuple[Path, Path, Path]:
        return (
            Path(get_pid_path(self.target)),
            Path(get_port_path(self.target)),
            Path(get_token_path(self.target)),
        )

    @contextlib.contextmanager
    def _listening_port(self) -> object:
        """Yield a loopback port answering probes with the ida-cli daemon banner."""
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        stop = threading.Event()

        def answer_probes() -> None:
            while not stop.is_set():
                try:
                    conn, _addr = listener.accept()
                except OSError:
                    return
                try:
                    conn.sendall(b'{"hello":"ida-cli-daemon","version":1}\n')
                except OSError:
                    pass
                conn.close()

        thread = threading.Thread(target=answer_probes, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1]
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=5)

    def test_shutdown_without_target_is_cli_error(self) -> None:
        stdout = io.StringIO()

        exit_code = main(["--shutdown"], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["error"]["type"], "CLIArgumentError")

    def test_shutdown_without_daemon_returns_error_code(self) -> None:
        stdout = io.StringIO()

        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "NoDaemonError")

    def test_shutdown_with_garbage_pid_file_keeps_files(self) -> None:
        Path(get_pid_path(self.target)).write_text("not-a-pid")
        stdout = io.StringIO()

        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "ValueError")
        self.assertTrue(Path(get_pid_path(self.target)).is_file())

    def test_shutdown_kills_daemon_and_removes_files(self) -> None:
        with self._listening_port() as port:
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                self._write_daemon_files(proc.pid, port)
                stdout = io.StringIO()

                exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

                payload = _responses(stdout.getvalue())[0]
                if os.name == "nt":
                    # The banner listener never answers the shutdown protocol,
                    # and Windows SIGTERM is TerminateProcess — the CLI must
                    # refuse to hard-kill rather than skip graceful cleanup.
                    self.assertEqual(exit_code, 1)
                    self.assertFalse(payload["ok"])
                    self.assertEqual(payload["error"]["type"], "DaemonShutdownError")
                    self.assertIsNone(proc.poll(), "Windows path must not force-kill")
                    for path in self._daemon_paths():
                        self.assertTrue(path.is_file(), f"{path} should be kept after refusal")
                else:
                    self.assertEqual(exit_code, 0)
                    self.assertTrue(payload["ok"])
                    for path in self._daemon_paths():
                        self.assertFalse(path.exists(), f"{path} should be removed after death")
                    proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=10)

    def test_shutdown_via_protocol_cleans_files_after_confirmed_exit(self) -> None:
        with self._listening_port() as port:
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            try:
                self._write_daemon_files(proc.pid, port)
                stdout = io.StringIO()
                with mock.patch.object(main_mod, "_request_protocol_shutdown", return_value=True) as req:
                    with mock.patch.object(main_mod, "_wait_for_process_exit", return_value=True):
                        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

                payload = _responses(stdout.getvalue())[0]
                self.assertEqual(exit_code, 0)
                self.assertTrue(payload["ok"])
                req.assert_called_once()
                for path in self._daemon_paths():
                    self.assertFalse(path.exists(), f"{path} should be removed after protocol shutdown")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=10)

    def test_shutdown_acknowledged_but_daemon_survives_keeps_files(self) -> None:
        with self._listening_port() as port:
            self._write_daemon_files(os.getpid(), port)
            stdout = io.StringIO()
            with mock.patch.object(main_mod, "_request_protocol_shutdown", return_value=True):
                with mock.patch.object(main_mod, "_SHUTDOWN_TIMEOUT", 0.3):
                    with mock.patch.object(main_mod, "_SHUTDOWN_POLL_INTERVAL", 0.02):
                        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

            payload = _responses(stdout.getvalue())[0]
            self.assertEqual(exit_code, 1)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["type"], "DaemonShutdownError")
            for path in self._daemon_paths():
                self.assertTrue(path.is_file(), f"{path} should be kept while daemon lives")

    # Platform selection goes through main_mod._is_windows, never os.name:
    # pathlib binds its PosixPath/WindowsPath guard at import time, so
    # patching os.name makes every Path call raise UnsupportedOperation --
    # on Windows for the "posix" case and on Linux for the "nt" case.
    def test_shutdown_protocol_failure_falls_back_to_sigterm_on_posix(self) -> None:
        with self._listening_port() as port:
            self._write_daemon_files(os.getpid(), port)
            stdout = io.StringIO()
            kills: list[tuple[int, int]] = []
            with mock.patch.object(main_mod, "_request_protocol_shutdown", return_value=False):
                with mock.patch.object(main_mod.os, "kill", lambda pid, sig: kills.append((pid, sig))):
                    with mock.patch.object(main_mod, "_is_windows", return_value=False):
                        with mock.patch.object(main_mod, "_SHUTDOWN_TIMEOUT", 0.3):
                            with mock.patch.object(main_mod, "_SHUTDOWN_POLL_INTERVAL", 0.02):
                                exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

            payload = _responses(stdout.getvalue())[0]
            self.assertEqual(exit_code, 1)
            self.assertEqual(payload["error"]["type"], "DaemonShutdownError")
            self.assertEqual(kills[0], (os.getpid(), signal.SIGTERM))

    def test_shutdown_protocol_failure_on_windows_reports_without_kill(self) -> None:
        with self._listening_port() as port:
            self._write_daemon_files(os.getpid(), port)
            stdout = io.StringIO()
            with mock.patch.object(main_mod, "_request_protocol_shutdown", return_value=False):
                with mock.patch.object(
                    main_mod.os, "kill", side_effect=AssertionError("Windows must not hard-kill")
                ):
                    with mock.patch.object(main_mod, "_is_windows", return_value=True):
                        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

            payload = _responses(stdout.getvalue())[0]
            self.assertEqual(exit_code, 1)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["type"], "DaemonShutdownError")
            self.assertIn("--force", payload["error"]["message"])
            for path in self._daemon_paths():
                self.assertTrue(path.is_file(), f"{path} should be kept after refusal")

    def test_shutdown_force_kills_on_windows(self) -> None:
        with self._listening_port() as port:
            self._write_daemon_files(os.getpid(), port)
            stdout = io.StringIO()
            kills: list[tuple[int, int]] = []
            with mock.patch.object(main_mod, "_request_protocol_shutdown", return_value=False):
                with mock.patch.object(main_mod.os, "kill", lambda pid, sig: kills.append((pid, sig))):
                    with mock.patch.object(main_mod, "_is_windows", return_value=True):
                        with mock.patch.object(main_mod, "_SHUTDOWN_TIMEOUT", 0.3):
                            with mock.patch.object(main_mod, "_SHUTDOWN_POLL_INTERVAL", 0.02):
                                exit_code = main(
                                    ["--shutdown", "--force", self.target],
                                    stdin=io.StringIO(),
                                    stdout=stdout,
                                )

            self.assertEqual(exit_code, 1)  # our own live PID never dies
            self.assertEqual(kills[0], (os.getpid(), signal.SIGTERM))

    def test_shutdown_failed_kill_keeps_files(self) -> None:
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait(timeout=30)
        with self._listening_port() as port:
            self._write_daemon_files(dead.pid, port)
            stdout = io.StringIO()

            exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

            payload = _responses(stdout.getvalue())[0]
            self.assertEqual(exit_code, 1)
            self.assertFalse(payload["ok"])
            for path in self._daemon_paths():
                self.assertTrue(path.is_file(), f"{path} should be kept after failed kill")

    def test_shutdown_reports_when_daemon_survives_sigterm(self) -> None:
        with self._listening_port() as port:
            self._write_daemon_files(os.getpid(), port)
            stdout = io.StringIO()
            with mock.patch.object(main_mod.os, "kill", lambda pid, sig: None):
                with mock.patch.object(main_mod, "_SHUTDOWN_TIMEOUT", 0.3):
                    with mock.patch.object(main_mod, "_SHUTDOWN_POLL_INTERVAL", 0.02):
                        exit_code = main(["--shutdown", self.target], stdin=io.StringIO(), stdout=stdout)

            payload = _responses(stdout.getvalue())[0]
            self.assertEqual(exit_code, 1)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["type"], "DaemonShutdownError")
            for path in self._daemon_paths():
                self.assertTrue(path.is_file(), f"{path} should be kept while daemon lives")

    def test_sigterm_handler_triggers_graceful_daemon_shutdown(self) -> None:
        previous = signal.getsignal(signal.SIGTERM)
        session = _CloseTrackingSession()
        _KeyboardInterruptServer.instances.clear()

        with mock.patch.object(main_mod, "DaemonServer", _KeyboardInterruptServer):
            exit_code = main_mod._serve_daemon(self.target, session)

        server = _KeyboardInterruptServer.instances[-1]
        self.assertEqual(exit_code, 0)
        self.assertTrue(server.shutdown_called)
        self.assertTrue(session.closed)
        self.assertNotIn(server.handler_seen, (previous, signal.SIG_DFL, signal.SIG_IGN, None))
        with self.assertRaises(KeyboardInterrupt):
            server.handler_seen(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_daemon_race_loser_gets_daemon_running_envelope(self) -> None:
        # is_daemon_running() at CLI entry cannot close the race across
        # create_session(); start() losing the O_EXCL race must surface as a
        # DaemonRunningError envelope, not a traceback.
        from ida_cli import daemon as daemon_mod

        session = _CloseTrackingSession()
        stdout = io.StringIO()
        with mock.patch("ida_cli.__main__.create_session", return_value=session):
            with mock.patch.object(
                main_mod,
                "_serve_daemon",
                side_effect=daemon_mod.DaemonRunningError("daemon already running"),
            ):
                exit_code = main(["--daemon", self.target], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "DaemonRunningError")


class CliFrontDoorTests(unittest.TestCase):
    """Human-facing meta flags must not be mistaken for target paths."""

    def test_help_prints_usage_and_exits_zero(self) -> None:
        for flag in ("--help", "-h"):
            stdout = io.StringIO()
            exit_code = main([flag], stdin=io.StringIO(), stdout=stdout)

            self.assertEqual(exit_code, 0, flag)
            text = stdout.getvalue()
            self.assertIn("usage:", text.lower())
            self.assertIn("--daemon", text)
            self.assertIn("--shutdown", text)

    def test_version_prints_package_version(self) -> None:
        stdout = io.StringIO()
        exit_code = main(["--version"], stdin=io.StringIO(), stdout=stdout)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue().strip(), f"ida-ai {ida_cli.__version__}")

    def test_doctor_success_is_one_jsonl_result(self) -> None:
        stdout = io.StringIO()
        details: dict[str, object] = {"status": "ready", "message": "ready"}

        with mock.patch.object(main_mod, "run_doctor", return_value=(0, details)) as doctor:
            exit_code = main(["doctor"], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"], details)
        doctor.assert_called_once_with(fix_license=False)

    def test_doctor_fix_license_reports_actionable_error_details(self) -> None:
        stdout = io.StringIO()
        details: dict[str, object] = {
            "status": "license_not_accepted",
            "message": "accept once",
            "installation": {"root": "D:/IDA"},
        }

        with mock.patch.object(main_mod, "run_doctor", return_value=(1, details)) as doctor:
            exit_code = main(["doctor", "--fix-license"], stdin=io.StringIO(), stdout=stdout)

        payload = _responses(stdout.getvalue())[0]
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "IdaLicenseNotAcceptedError")
        self.assertEqual(payload["details"], details)
        doctor.assert_called_once_with(fix_license=True)

    def test_startup_exception_classifies_raw_ida_license_message(self) -> None:
        payload = main_mod._startup_exception(
            RuntimeError("License not yet accepted, cannot run in batch mode")
        )

        self.assertEqual(payload["error"]["type"], "IdaLicenseNotAcceptedError")
        self.assertIn("doctor --fix-license", payload["error"]["message"])

    def test_version_matches_pyproject(self) -> None:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertEqual(ida_cli.__version__, data["project"]["version"])


if __name__ == "__main__":
    unittest.main()
