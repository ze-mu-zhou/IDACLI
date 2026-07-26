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
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import ida_cli
from ida_cli import __main__ as main_mod
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


class _CloseTrackingSession:
    """Session double recording close() calls for daemon lifecycle tests."""

    def __init__(self) -> None:
        self.runtime = object()
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _KeyboardInterruptServer:
    """DaemonServer double raising KeyboardInterrupt while serving."""

    instances: list["_KeyboardInterruptServer"] = []

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
                self.assertEqual(exit_code, 0)
                self.assertTrue(payload["ok"])
                for path in self._daemon_paths():
                    self.assertFalse(path.exists(), f"{path} should be removed after death")
                proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=10)

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

    def test_version_matches_pyproject(self) -> None:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertEqual(ida_cli.__version__, data["project"]["version"])


if __name__ == "__main__":
    unittest.main()
