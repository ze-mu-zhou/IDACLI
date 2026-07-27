"""Tests for external-agent subprocess integration."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO
from unittest import mock

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli import agent_bridge as agent_bridge_mod
from ida_cli import daemon as daemon_mod
from ida_cli.agent_bridge import AgentBridgeError, AgentBridgeLicenseError, AgentBridgeTimeoutError, AgentSession


def _python_only_command() -> tuple[str, ...]:
    """Return a subprocess command that forces the Python backend for tests."""

    code = (
        "import sys;"
        f"sys.path.insert(0, {str(SRC)!r});"
        "import ida_cli.__main__ as main_mod;"
        "from ida_cli.kernel import PythonOnlyBackend, create_session;"
        "main_mod.create_session = lambda target: create_session(target, backend=PythonOnlyBackend());"
        "raise SystemExit(main_mod.main())"
    )
    return (sys.executable, "-B", "-c", code)


def _recording_popen(processes: list[subprocess.Popen[bytes]]) -> Callable[..., subprocess.Popen[bytes]]:
    """Return a real Popen wrapper that keeps spawned processes observable to tests."""

    real_popen = subprocess.Popen

    def record(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    return record


class AgentBridgeTests(unittest.TestCase):
    """Exercise the bridge exactly as an external coding agent would use it."""

    def test_agent_session_preserves_state_and_raw_protocol_response(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command()) as session:
            first = session.execute("value = 41\n__result__ = value + 1", request_id="first")
            second = session.result("__result__ = value", request_id=None)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first["id"], "first")
        self.assertEqual(first["result"], 42)
        self.assertEqual(second, 41)

    def test_agent_session_result_raises_with_structured_response(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command()) as session:
            with self.assertRaisesRegex(AgentBridgeError, "ValueError: boom") as captured:
                session.result("raise ValueError('boom')", request_id="err")

        self.assertIsNotNone(captured.exception.response)
        self.assertEqual(captured.exception.response["id"], "err")
        self.assertFalse(captured.exception.response["ok"])

    def test_probe_backend_caches_metadata_and_can_require_ida(self) -> None:
        with AgentSession.start("sample.i64", command=_python_only_command(), probe_backend=True) as session:
            backend = session.backend

        self.assertIsNotNone(backend)
        self.assertEqual(backend["name"], "python")
        with self.assertRaisesRegex(AgentBridgeError, "IDA backend required"):
            AgentSession.start("sample.i64", command=_python_only_command(), require_ida=True)

    def test_result_preserves_distinct_license_acceptance_error(self) -> None:
        response = {
            "ok": False,
            "error": {
                "type": "IdaLicenseNotAcceptedError",
                "message": "IDA license terms have not been accepted",
            },
        }
        session = AgentSession()

        with mock.patch.object(session, "execute", return_value=response):
            with self.assertRaisesRegex(AgentBridgeLicenseError, "doctor --fix-license"):
                session.result("__result__ = 1")

    def test_agent_session_rejects_mismatched_response_id(self) -> None:
        command = _one_response_command('{"id":"wrong","ok":true,"result":1}')
        with AgentSession.start("sample.i64", command=command) as session:
            with self.assertRaisesRegex(AgentBridgeError, "response id does not match"):
                session.execute("__result__ = 1", request_id="right")

    def test_agent_session_rejects_non_strict_json_response(self) -> None:
        command = _one_response_command('{"ok":true,"ok":true,"result":1}')
        with AgentSession.start("sample.i64", command=command) as session:
            with self.assertRaisesRegex(AgentBridgeError, "duplicate JSON object key"):
                session.execute("__result__ = 1")

    def test_agent_session_timeout_kills_hung_kernel(self) -> None:
        code = "import sys,time; sys.stdin.readline(); time.sleep(30)"
        with AgentSession.start("sample.i64", command=(sys.executable, "-B", "-c", code), request_timeout_s=0.2) as session:
            with self.assertRaisesRegex(AgentBridgeError, "timed out"):
                session.execute("__result__ = 1")
            self.assertIsNotNone(session._process.poll())

    def test_daemon_startup_failure_reports_daemon_stderr(self) -> None:
        command = (
            sys.executable,
            "-B",
            "-c",
            "import sys; sys.stderr.write('daemon boom evidence'); sys.stderr.flush(); sys.exit(3)",
        )
        processes: list[subprocess.Popen[bytes]] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": temp_dir}), \
                 mock.patch.object(agent_bridge_mod, "_DAEMON_STARTUP_TIMEOUT", 0.5), \
                 mock.patch.object(agent_bridge_mod.subprocess, "Popen", side_effect=_recording_popen(processes)):
                with self.assertRaisesRegex(AgentBridgeError, "daemon boom evidence"):
                    AgentSession.start("D:/targets/failing-daemon.exe", command=command, daemon=True)

        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].returncode, 3)

    def test_daemon_startup_timeout_reaps_hung_process(self) -> None:
        command = (sys.executable, "-B", "-c", "import time; time.sleep(30)")
        processes: list[subprocess.Popen[bytes]] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": temp_dir}), \
                 mock.patch.object(agent_bridge_mod, "_DAEMON_STARTUP_TIMEOUT", 0.2), \
                 mock.patch.object(agent_bridge_mod.subprocess, "Popen", side_effect=_recording_popen(processes)):
                with self.assertRaisesRegex(AgentBridgeError, "did not start"):
                    AgentSession.start("D:/targets/hung-daemon.exe", command=command, daemon=True)

        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)


class AgentBridgeDaemonTransportTests(unittest.TestCase):
    """Cover the daemon transport: one bad read must not leave the kernel running."""

    def setUp(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        patcher = mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": temp_dir.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_daemon_read_timeout_poisons_session_so_later_code_never_executes(self) -> None:
        """After a read timeout the daemon must not execute one more request.

        The bridge used to leave the connection open, so CPython's latched
        SocketIO timeout turned every later readline() into a bare OSError
        while _write_request kept succeeding: the agent recorded the renames
        as failed and the daemon renamed away regardless.
        """

        target = "D:/targets/poisoned-session.i64"
        daemon = _FakeDaemon(slow_request=2, delay_s=0.6)
        self.addCleanup(daemon.stop)
        daemon.register(target)
        session = AgentSession.connect(target, request_timeout_s=0.2)
        self.addCleanup(session.close)

        self.assertEqual(session.result("ai.rename(0, 'a')"), "ai.rename(0, 'a')")
        with self.assertRaises(AgentBridgeTimeoutError):
            session.result("ai.rename(1, 'b')")
        for index in range(2, 5):
            # Every later call must fail inside the documented hierarchy and
            # name the way back to a working session.
            with self.assertRaisesRegex(AgentBridgeError, r"unusable.*AgentSession\.connect"):
                session.result(f"ai.rename({index}, 'c')")

        session.close()
        daemon.wait_for_connections()  # the peer has now consumed every byte we sent
        self.assertEqual(daemon.executed, ["ai.rename(0, 'a')", "ai.rename(1, 'b')"])

    def test_daemon_connect_failure_stays_inside_the_bridge_error_hierarchy(self) -> None:
        """DaemonClient's bare RuntimeError must reach callers as AgentBridgeError."""

        with self.assertRaisesRegex(AgentBridgeError, "could not connect to the daemon"):
            AgentSession.connect("D:/targets/no-daemon-here.i64")

    def test_daemon_write_failure_raises_bridge_error_and_poisons_the_session(self) -> None:
        """A dead transport must not escape as a bare RuntimeError on write either."""

        target = "D:/targets/write-failure.i64"
        daemon = _FakeDaemon()
        self.addCleanup(daemon.stop)
        daemon.register(target)
        session = AgentSession.connect(target, request_timeout_s=1.0)
        self.addCleanup(session.close)
        session._daemon_client.close()  # the transport dies under a live session

        with self.assertRaisesRegex(AgentBridgeError, "daemon request write failed"):
            session.execute("__result__ = 1")
        with self.assertRaisesRegex(AgentBridgeError, "unusable"):
            session.execute("__result__ = 2")
        self.assertEqual(daemon.executed, [])


class _FakeDaemon:
    """A daemon peer on a real socket: banner, auth, echo, and a scripted stall.

    A real socket on purpose: the defect under test is CPython's SocketIO
    latching _timeout_occurred after the first timed-out read, which no
    in-process double reproduces. `executed` records what the peer actually
    ran, so a test can tell "the agent saw an error" from "nothing happened".
    """

    def __init__(self, *, slow_request: int = 0, delay_s: float = 0.0) -> None:
        self.executed: list[str] = []
        self._slow_request = slow_request
        self._delay_s = delay_s
        self._served = 0
        self._threads: list[threading.Thread] = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.port: int = self._server.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def register(self, target_path: str) -> None:
        """Write the port/pid/token files AgentSession.connect() looks for."""

        Path(daemon_mod.get_port_path(target_path)).write_text(str(self.port), encoding="utf-8")
        Path(daemon_mod.get_pid_path(target_path)).write_text(str(os.getpid()), encoding="utf-8")
        Path(daemon_mod.get_token_path(target_path)).write_text("fake-token", encoding="utf-8")

    def wait_for_connections(self, timeout: float = 5.0) -> None:
        """Join every served connection: only then is `executed` final.

        Each connection thread ends at EOF, which the peer reaches after
        consuming everything the client ever wrote — a deterministic
        alternative to sleeping and hoping the request did not arrive.
        """

        for thread in list(self._threads):
            thread.join(timeout=timeout)

    def stop(self) -> None:
        """Close the listener; the connection threads are daemons and follow."""

        try:
            self._server.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _addr = self._server.accept()
            except OSError:
                return  # stop() closed the listener
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            with conn, conn.makefile(mode="r", encoding="utf-8") as reader, \
                 conn.makefile(mode="w", encoding="utf-8") as writer:
                writer.write(json.dumps({"hello": "ida-cli-daemon", "version": 1}) + "\n")
                writer.flush()
                if not reader.readline():
                    return  # a liveness probe: it reads the banner and hangs up
                for line in reader:
                    if not line.strip():
                        continue
                    self._answer(json.loads(line), writer)
        except (OSError, ValueError):
            return  # the client vanished mid-exchange; nothing left to answer

    def _answer(self, request: dict[str, object], writer: TextIO) -> None:
        """Record the request as executed, stall if scripted to, then reply."""

        self.executed.append(str(request["code"]))
        self._served += 1
        if self._served == self._slow_request:
            time.sleep(self._delay_s)
        response: dict[str, object] = {"ok": True, "result": request["code"]}
        if "id" in request:
            response["id"] = request["id"]
        writer.write(json.dumps(response) + "\n")
        writer.flush()


def _one_response_command(response: str) -> tuple[str, ...]:
    """Return a tiny protocol-shaped responder for bridge validation tests."""

    code = (
        "import sys;"
        "sys.stdin.readline();"
        f"sys.stdout.write({response + chr(10)!r});"
        "sys.stdout.flush()"
    )
    return (sys.executable, "-B", "-c", code)


if __name__ == "__main__":
    unittest.main()
