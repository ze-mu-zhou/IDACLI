"""Tests for daemon mode without requiring IDA."""

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
import time
import unittest
from pathlib import Path
from unittest import mock

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ida_cli import daemon as daemon_mod
from ida_cli import __main__ as main_mod
from ida_cli import runtime as runtime_mod
from ida_cli.agent_bridge import AgentBridgeTimeoutError, AgentSession
from ida_cli.daemon import DaemonClient, DaemonServer, DaemonTimings
from ida_cli.protocol import ProtocolRequest
from ida_cli.runtime import PythonRuntime


def fast_timings(**overrides: object) -> DaemonTimings:
    """Production timing behaviour compressed to milliseconds.

    Injected per server/executor instead of patching daemon module globals:
    these tests run several daemons concurrently in one process, so shared
    mutable timing state is a flakiness source rather than a seam.
    """

    base = {
        "auth_timeout": 0.5,
        "watchdog_poll": 0.01,
        "watchdog_refire": 0.05,
        "execute_wait_margin": 0.5,
        "owner_probe_attempts": 2,
        "owner_probe_interval": 0.01,
        "owner_probe_timeout": 0.2,
        "startup_timeout": 5.0,
        "startup_poll_interval": 0.01,
    }
    base.update(overrides)
    return DaemonTimings(**base)


class _FakeRuntime:
    """Minimal runtime double recording requests and echoing code."""

    def __init__(self) -> None:
        self.requests: list[object] = []

    def execute_request(self, request: object) -> dict[str, object]:
        self.requests.append(request)
        envelope: dict[str, object] = {
            "elapsed_ms": 0,
            "stderr": "",
            "stdout": "",
            "ok": True,
            "result": {"echo": request.code},
        }
        if request.has_id:
            envelope["id"] = request.request_id
        return envelope


class _SlowRuntime:
    """Runtime double that sleeps before answering to simulate a hung kernel."""

    def __init__(self, delay_s: float) -> None:
        self._delay_s = delay_s

    def execute_request(self, request: object) -> dict[str, object]:
        time.sleep(self._delay_s)
        envelope: dict[str, object] = {
            "elapsed_ms": 0,
            "stderr": "",
            "stdout": "",
            "ok": True,
            "result": {"echo": request.code},
        }
        if request.has_id:
            envelope["id"] = request.request_id
        return envelope


class DaemonServerTests(unittest.TestCase):
    """Verify bind policy, banner, auth handshake, and concurrent client serving."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._env = mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": self._tmp.name})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.target = "D:/targets/sample.exe"
        self.runtime = _FakeRuntime()
        self.server = DaemonServer(self.target, self.runtime, timings=fast_timings())
        self.server.start()
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def test_binds_loopback_by_default(self) -> None:
        self.assertEqual(self.server._server.getsockname()[0], "127.0.0.1")

    def test_writes_token_file_on_start(self) -> None:
        token_path = Path(self._tmp.name) / f"{daemon_mod.get_target_id(self.target)}.token"

        self.assertTrue(token_path.is_file())
        token = token_path.read_text(encoding="utf-8").strip()
        self.assertEqual(len(token), 64)
        int(token, 16)

    def test_server_sends_protocol_banner_first(self) -> None:
        port = int(Path(daemon_mod.get_port_path(self.target)).read_text(encoding="utf-8").strip())
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            banner = json.loads(self._recv_line(sock))

        self.assertEqual(banner, {"hello": "ida-cli-daemon", "version": 1})

    def test_requests_execute_on_the_serving_thread(self) -> None:
        """IDA only answers on its owning thread, so execution must stay there."""
        idents: list[int] = []

        class _IdentRuntime(_FakeRuntime):
            def execute_request(self, request: object) -> dict[str, object]:
                idents.append(threading.get_ident())
                return super().execute_request(request)

        server = DaemonServer("D:/targets/threaded.exe", _IdentRuntime(), timings=fast_timings())
        server.start()
        self.addCleanup(server.shutdown)
        serve_idents: list[int] = []

        def _run() -> None:
            serve_idents.append(threading.get_ident())
            server.serve_forever()

        threading.Thread(target=_run, daemon=True).start()
        deadline = time.monotonic() + 5
        while not serve_idents and time.monotonic() < deadline:
            time.sleep(0.01)

        client = DaemonClient("D:/targets/threaded.exe", timings=fast_timings())
        client.connect()
        self.addCleanup(client.close)
        client.write('{"id":1,"code":"__result__ = 1"}\n')
        self.assertTrue(json.loads(client.readline())["ok"])

        self.assertTrue(idents)
        self.assertEqual(set(idents), {serve_idents[0]})

    def test_unauthenticated_request_is_rejected(self) -> None:
        sock = self._connect_raw()
        with sock:
            sock.sendall(b'{"id":1,"code":"__result__ = 1"}\n')
            payload = json.loads(self._recv_line(sock))

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "DaemonAuthError")
        self.assertEqual(self.runtime.requests, [])

    def test_unauthenticated_shutdown_message_is_rejected(self) -> None:
        # The shutdown control message is honored only after token auth.
        sock = self._connect_raw()
        with sock:
            sock.sendall(b'{"shutdown": true}\n')
            payload = json.loads(self._recv_line(sock))

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "DaemonAuthError")
        self.assertFalse(self.server._runtime._stop.is_set())

    def test_authenticated_shutdown_message_stops_server(self) -> None:
        target = "D:/targets/proto-shutdown.exe"
        server = DaemonServer(target, _FakeRuntime(), timings=fast_timings())
        server.start()
        self.addCleanup(server.shutdown)
        serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
        serve_thread.start()

        port = int(Path(daemon_mod.get_port_path(target)).read_text().strip())
        token = Path(daemon_mod.get_token_path(target)).read_text().strip()
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            reader = sock.makefile(mode="r", encoding="utf-8", errors="replace")
            banner = json.loads(reader.readline())
            self.assertEqual(banner.get("hello"), "ida-cli-daemon")
            sock.sendall((json.dumps({"auth": token}) + "\n").encode())
            sock.sendall(b'{"shutdown": true}\n')
            ack = json.loads(reader.readline())

        self.assertEqual(ack, {"ok": True, "shutdown": True})
        serve_thread.join(timeout=10)
        self.assertFalse(serve_thread.is_alive(), "serve_forever must unwind after a shutdown message")
        self.assertTrue(server._runtime._stop.is_set())

    def _authenticated_session(self, target: str, runtime: object | None = None):
        """Start a daemon and return (server, socket, reader) past the handshake."""
        server = DaemonServer(target, runtime or _FakeRuntime(), timings=fast_timings())
        server.start()
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = int(Path(daemon_mod.get_port_path(target)).read_text().strip())
        token = Path(daemon_mod.get_token_path(target)).read_text().strip()
        sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.addCleanup(sock.close)
        reader = sock.makefile(mode="r", encoding="utf-8", errors="replace")
        self.assertEqual(json.loads(reader.readline()).get("hello"), "ida-cli-daemon")
        sock.sendall((json.dumps({"auth": token}) + "\n").encode())
        return server, sock, reader

    # The control channel shares the request line format, and _handle_control_message
    # runs before parse_request. Its three guards -- sole key, literal true, identity
    # not equality -- had zero coverage: every one-token weakening left the suite
    # green while an ordinary request could silently kill the daemon and discard
    # unsaved renames, comments and types via close_database(False).
    def test_request_carrying_a_shutdown_key_executes_and_leaves_the_daemon_up(self) -> None:
        server, sock, reader = self._authenticated_session(
            "D:/targets/ctl-extra-key.exe", PythonRuntime()
        )

        sock.sendall(b'{"id":1,"code":"__result__ = 40 + 2","shutdown":true}\n')
        envelope = json.loads(reader.readline())

        self.assertTrue(envelope["ok"], envelope)
        self.assertEqual(envelope["result"], 42)
        self.assertFalse(server._runtime._stop.is_set())

    def test_truthy_but_non_literal_shutdown_value_does_not_stop_the_daemon(self) -> None:
        server, sock, reader = self._authenticated_session("D:/targets/ctl-truthy.exe")

        sock.sendall(b'{"shutdown": 1}\n')  # 1 == True in Python; identity must be required
        envelope = json.loads(reader.readline())

        self.assertFalse(envelope["ok"], envelope)
        self.assertFalse(server._runtime._stop.is_set())

    def test_shutdown_false_does_not_stop_the_daemon(self) -> None:
        server, sock, reader = self._authenticated_session("D:/targets/ctl-false.exe")

        sock.sendall(b'{"shutdown": false}\n')
        envelope = json.loads(reader.readline())

        self.assertFalse(envelope["ok"], envelope)
        self.assertFalse(server._runtime._stop.is_set())

    def test_shutdown_message_never_reaches_the_request_queue(self) -> None:
        # A hung request must not block the shutdown path: the control
        # message is answered on the connection thread, never queued behind
        # _MainThreadExecutor work.
        target = "D:/targets/shutdown-while-hung.exe"
        # A budget far longer than the test: only the stop() trigger can end
        # the hung request, which is exactly what this asserts.
        server = DaemonServer(target, PythonRuntime(), timings=fast_timings(exec_timeout=30.0))
        server.start()
        self.addCleanup(server.shutdown)
        serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
        serve_thread.start()

        client = DaemonClient(target, timings=fast_timings())
        client.connect()
        self.addCleanup(client.close)
        client.write('{"id":"hang","code":"while True: pass"}\n')
        time.sleep(0.3)  # let the hung request reach the serving thread

        port = int(Path(daemon_mod.get_port_path(target)).read_text().strip())
        token = Path(daemon_mod.get_token_path(target)).read_text().strip()
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            reader = sock.makefile(mode="r", encoding="utf-8", errors="replace")
            reader.readline()  # banner
            sock.sendall((json.dumps({"auth": token}) + "\n").encode())
            sock.sendall(b'{"shutdown": true}\n')
            sock.settimeout(10.0)
            ack = json.loads(reader.readline())

        self.assertEqual(ack, {"ok": True, "shutdown": True})
        self.assertTrue(server._runtime._stop.is_set())
        # The watchdog interrupts the hung request at budget, letting the
        # serving thread unwind; bound the join so a failure cannot hang CI.
        serve_thread.join(timeout=15)
        self.assertFalse(serve_thread.is_alive())

    def test_request_protocol_shutdown_acknowledged_by_live_daemon(self) -> None:
        target = "D:/targets/proto-shutdown-live.exe"
        server = DaemonServer(target, _FakeRuntime(), timings=fast_timings())
        server.start()
        self.addCleanup(server.shutdown)
        serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
        serve_thread.start()

        self.assertTrue(main_mod._request_protocol_shutdown(target))
        serve_thread.join(timeout=10)
        self.assertFalse(serve_thread.is_alive())

    def test_request_protocol_shutdown_returns_false_without_ack(self) -> None:
        target = "D:/targets/banner-only.exe"
        listener = self._start_payload_listener(
            [b'{"hello":"ida-cli-daemon","version":1}\n'] * 4
        )
        port = listener.getsockname()[1]
        Path(daemon_mod.get_pid_path(target)).write_text(str(os.getpid()), encoding="utf-8")
        Path(daemon_mod.get_port_path(target)).write_text(str(port), encoding="utf-8")
        Path(daemon_mod.get_token_path(target)).write_text("token", encoding="utf-8")

        with mock.patch.object(main_mod, "_SHUTDOWN_TIMEOUT", 0.3):
            self.assertFalse(main_mod._request_protocol_shutdown(target))

    def test_wrong_token_is_rejected(self) -> None:
        sock = self._connect_raw()
        with sock:
            sock.sendall(b'{"auth":"wrong-token"}\n{"id":1,"code":"__result__ = 1"}\n')
            payload = json.loads(self._recv_line(sock))

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "DaemonAuthError")
        self.assertEqual(self.runtime.requests, [])

    def test_client_round_trip_executes_requests(self) -> None:
        client = DaemonClient(self.target, timings=fast_timings())
        client.connect()
        self.addCleanup(client.close)

        client.write('{"id":7,"code":"__result__ = 40 + 2"}\n')
        payload = json.loads(client.readline())

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["id"], 7)
        self.assertEqual(len(self.runtime.requests), 1)

    def test_idle_connection_does_not_block_other_clients(self) -> None:
        idle = self._connect_raw()
        with idle:
            idle.sendall((json.dumps({"auth": self._read_token()}) + "\n").encode())
            guest = self._connect_raw()
            with guest:
                guest.sendall((json.dumps({"auth": self._read_token()}) + "\n").encode())
                guest.sendall(b'{"id":9,"code":"__result__ = 1"}\n')
                payload = json.loads(self._recv_line(guest))

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["id"], 9)

    def test_auth_handshake_times_out(self) -> None:
        target = "D:/targets/auth-timeout.exe"
        server = DaemonServer(target, _FakeRuntime(), timings=fast_timings(auth_timeout=0.2))
        server.start()
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        sock = self._connect_raw(timeout=5.0, target=target)
        with sock:
            # Send nothing after the banner: the server must close the connection itself.
            eof = sock.recv(1)

        self.assertEqual(eof, b"")

    def test_non_loopback_bind_requires_explicit_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_HOST": "0.0.0.0"}):
            other = DaemonServer("D:/targets/other.exe", _FakeRuntime(), timings=fast_timings())
            buffer = io.StringIO()
            with contextlib.redirect_stderr(buffer):
                other.start()
            self.addCleanup(other.shutdown)
            threading.Thread(target=other.serve_forever, daemon=True).start()

            self.assertEqual(other._server.getsockname()[0], "0.0.0.0")
            self.assertIn("0.0.0.0", buffer.getvalue())

    def test_connection_handler_errors_are_logged_to_stderr(self) -> None:
        buffer = io.StringIO()
        with mock.patch.object(DaemonServer, "_authorize", side_effect=RuntimeError("handler boom")):
            with contextlib.redirect_stderr(buffer):
                sock = self._connect_raw()
                with sock:
                    sock.sendall(b'{"auth":"whatever"}\n')
                    deadline = time.monotonic() + 5.0
                    while "handler boom" not in buffer.getvalue() and time.monotonic() < deadline:
                        time.sleep(0.01)

        self.assertIn("handler boom", buffer.getvalue())

    def test_is_daemon_running_accepts_real_daemon(self) -> None:
        self.assertTrue(daemon_mod.is_daemon_running(self.target))

    def test_is_daemon_running_rejects_non_daemon_service(self) -> None:
        target = "D:/targets/garbage-service.exe"
        listener = self._start_payload_listener([b"garbage-not-a-banner\n"])
        port = listener.getsockname()[1]
        Path(daemon_mod.get_pid_path(target)).write_text(str(os.getpid()), encoding="utf-8")
        Path(daemon_mod.get_port_path(target)).write_text(str(port), encoding="utf-8")

        self.assertFalse(daemon_mod.is_daemon_running(target))

    def test_client_connect_rejects_invalid_banner(self) -> None:
        target = "D:/targets/stale-banner.exe"
        listener = self._start_payload_listener(
            [b'{"hello":"ida-cli-daemon","version":1}\n', b"garbage-not-a-banner\n"]
        )
        port = listener.getsockname()[1]
        Path(daemon_mod.get_pid_path(target)).write_text(str(os.getpid()), encoding="utf-8")
        Path(daemon_mod.get_port_path(target)).write_text(str(port), encoding="utf-8")

        client = DaemonClient(target, timings=fast_timings())
        with self.assertRaisesRegex(RuntimeError, "banner"):
            client.connect()

    def test_write_private_file_refuses_existing_path(self) -> None:
        path = Path(self._tmp.name) / "existing.txt"
        path.write_text("original", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            daemon_mod._write_private_file(str(path), "replacement")

        self.assertEqual(path.read_text(encoding="utf-8"), "original")

    def test_start_never_clobbers_preexisting_symlink(self) -> None:
        target = "D:/targets/symlink-victim.exe"
        victim = Path(self._tmp.name) / "victim.txt"
        victim.write_text("precious", encoding="utf-8")
        port_path = Path(daemon_mod.get_port_path(target))
        try:
            port_path.symlink_to(victim)
        except (NotImplementedError, OSError):
            self.skipTest("symlink creation requires privileges on this host")
        server = DaemonServer(target, _FakeRuntime(), timings=fast_timings())
        # Keep cleanup from removing the symlink: it reappeared after cleanup (race lost).
        with mock.patch.object(daemon_mod, "_cleanup_daemon_files", lambda _target: None):
            with self.assertRaises(FileExistsError):
                server.start()
        server.shutdown()

        self.assertEqual(victim.read_text(encoding="utf-8"), "precious")

    def test_second_start_on_same_target_fails_and_keeps_first_files(self) -> None:
        # setUp already started self.server on self.target; a second start
        # must lose the O_EXCL race without touching the winner's files.
        paths = [
            Path(daemon_mod.get_token_path(self.target)),
            Path(daemon_mod.get_pid_path(self.target)),
            Path(daemon_mod.get_port_path(self.target)),
        ]
        before = [p.read_bytes() for p in paths]

        second = DaemonServer(self.target, _FakeRuntime(), timings=fast_timings())
        with self.assertRaises(daemon_mod.DaemonRunningError):
            second.start()

        self.assertEqual([p.read_bytes() for p in paths], before)
        # The loser's shutdown must not unlink the winner's registration.
        second.shutdown()
        for path in paths:
            self.assertTrue(path.is_file(), f"{path} must survive the losing daemon")
        self.assertTrue(daemon_mod.is_daemon_running(self.target))

    def test_start_takes_over_stale_registration_files(self) -> None:
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait(timeout=30)
        target = "D:/targets/stale-owner.exe"
        Path(daemon_mod.get_pid_path(target)).write_text(str(dead.pid), encoding="utf-8")
        Path(daemon_mod.get_port_path(target)).write_text("1", encoding="utf-8")
        Path(daemon_mod.get_token_path(target)).write_text("stale-token", encoding="utf-8")

        server = DaemonServer(target, _FakeRuntime(), timings=fast_timings())
        server.start()
        self.addCleanup(server.shutdown)

        self.assertEqual(Path(daemon_mod.get_pid_path(target)).read_text().strip(), str(os.getpid()))
        self.assertEqual(len(Path(daemon_mod.get_token_path(target)).read_text().strip()), 64)

    def test_shutdown_removes_own_registration_files(self) -> None:
        paths = [
            Path(daemon_mod.get_token_path(self.target)),
            Path(daemon_mod.get_pid_path(self.target)),
            Path(daemon_mod.get_port_path(self.target)),
        ]
        self.server.shutdown()
        for path in paths:
            self.assertFalse(path.exists(), f"{path} should be removed on own shutdown")

    def test_shutdown_keeps_registration_files_owned_by_another_pid(self) -> None:
        # After a lost start() race the pid file names the surviving daemon;
        # shutdown() must leave those files alone.
        pid_path = Path(daemon_mod.get_pid_path(self.target))
        pid_path.write_text(str(os.getpid() + 4096), encoding="utf-8")
        paths = [
            pid_path,
            Path(daemon_mod.get_port_path(self.target)),
            Path(daemon_mod.get_token_path(self.target)),
        ]

        self.server.shutdown()

        for path in paths:
            self.assertTrue(path.is_file(), f"{path} must survive a foreign-pid shutdown")

    def test_daemon_request_timeout_raises_bridge_timeout(self) -> None:
        target = "D:/targets/slow-daemon.exe"
        slow_server = DaemonServer(target, _SlowRuntime(1.0), timings=fast_timings())
        slow_server.start()
        self.addCleanup(slow_server.shutdown)
        threading.Thread(target=slow_server.serve_forever, daemon=True).start()
        client = DaemonClient(target, timings=fast_timings())
        client.connect()
        self.addCleanup(client.close)
        session = AgentSession(None, None, request_timeout_s=5.0, daemon_client=client)

        with self.assertRaises(AgentBridgeTimeoutError):
            session.execute("__result__ = 1", timeout_s=0.2)

        # The per-request read timeout must be restored to blocking afterwards.
        self.assertIsNone(client._sock.gettimeout())

    def test_daemon_request_within_timeout_succeeds(self) -> None:
        client = DaemonClient(self.target, timings=fast_timings())
        client.connect()
        self.addCleanup(client.close)
        session = AgentSession(None, None, request_timeout_s=5.0, daemon_client=client)

        response = session.execute("__result__ = 1", request_id="fast", timeout_s=2.0)

        self.assertTrue(response["ok"])
        self.assertEqual(response["id"], "fast")

    def _connect_raw(self, timeout: float = 5.0, attempts: int = 3, target: str | None = None) -> socket.socket:
        # A loaded CI box can drop a single loopback SYN; these tests assert
        # protocol behaviour, not connect reliability, so retry rather than
        # turn transient timeouts into red builds.
        port_path = daemon_mod.get_port_path(self.target if target is None else target)
        port = int(Path(port_path).read_text(encoding="utf-8").strip())
        for attempt in range(attempts):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
                break
            except (TimeoutError, ConnectionRefusedError):
                if attempt + 1 == attempts:
                    raise
                time.sleep(0.1)
        banner = json.loads(self._recv_line(sock))
        self.assertEqual(banner.get("hello"), "ida-cli-daemon")
        return sock

    def _start_payload_listener(self, payloads: list[bytes]) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(len(payloads))
        self.addCleanup(listener.close)

        def _serve_payloads() -> None:
            for payload in payloads:
                try:
                    conn, _addr = listener.accept()
                except OSError:
                    return
                with conn:
                    conn.sendall(payload)

        threading.Thread(target=_serve_payloads, daemon=True).start()
        return listener

    def _read_token(self) -> str:
        try:
            token_path = Path(self._tmp.name) / f"{daemon_mod.get_target_id(self.target)}.token"
            return token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""  # servers without auth support have no token file

    @staticmethod
    def _recv_line(sock: socket.socket) -> str:
        return sock.makefile(mode="r", encoding="utf-8", errors="replace").readline()


class MainThreadExecutorTests(unittest.TestCase):
    """Cover the execution watchdog, wait timeout, and shutdown draining."""

    def setUp(self) -> None:
        runtime_mod._SIGNAL_INTERRUPT.clear()
        self.addCleanup(runtime_mod._SIGNAL_INTERRUPT.clear)
        main_mod._ACTIVE_EXECUTOR = None
        self.addCleanup(setattr, main_mod, "_ACTIVE_EXECUTOR", None)

    def test_watchdog_interrupts_hung_request_and_executor_survives(self) -> None:
        class _SometimesHung:
            def execute_request(self, request: object) -> object:
                if request == "hang":
                    while True:
                        pass
                return "pong"

        executor = daemon_mod._MainThreadExecutor(_SometimesHung(), fast_timings(exec_timeout=0.5))
        serve_thread = threading.Thread(target=executor.serve, daemon=True)
        serve_thread.start()
        self.addCleanup(executor.stop)

        with self.assertRaises(daemon_mod._RequestInterrupt):
            executor.execute_request("hang")

        self.assertEqual(executor.execute_request("ping"), "pong")

    def test_queue_wait_is_not_charged_to_the_waiting_client(self) -> None:
        """The budget starts at dequeue, not at enqueue.

        Charging queue time to the waiter tore down a healthy client that
        was merely sitting behind a slow one, once
        queue_wait + own_exec_time exceeded the budget -- while its own
        execution had barely begun.
        """
        # Budget 1.0s + margin 0.1s. The first request runs 0.9s (legal, under
        # its own budget); the second is queued behind it for that whole time
        # and then needs 0.3s of its own. Charging from enqueue the second
        # breaches at 1.1s and is torn down; charging from dequeue it uses
        # only 0.3s of its 1.1s and must survive.
        class _TimedRuntime:
            def execute_request(self, request: object) -> object:
                time.sleep(0.9 if request == "first" else 0.3)
                return f"done:{request}"

        executor = daemon_mod._MainThreadExecutor(
            _TimedRuntime(), fast_timings(exec_timeout=1.0, execute_wait_margin=0.1)
        )
        threading.Thread(target=executor.serve, daemon=True).start()
        self.addCleanup(executor.stop)

        second: dict[str, object] = {}
        threading.Thread(target=lambda: self._swallow(executor, "first"), daemon=True).start()
        time.sleep(0.05)  # let "first" reach the serving thread

        def _run_second() -> None:
            try:
                second["value"] = executor.execute_request("second")
            except BaseException as exc:  # noqa: BLE001 - the failure mode under test is unrestricted.
                second["error"] = exc

        waiter = threading.Thread(target=_run_second, daemon=True)
        waiter.start()
        waiter.join(timeout=10.0)

        self.assertNotIn("error", second, f"queued client was torn down: {second.get('error')!r}")
        self.assertEqual(second.get("value"), "done:second")

    def test_abandoned_request_is_never_executed(self) -> None:
        """A request whose waiter gave up must not reach the database.

        Before the abandonment flag the waiter raised and the serving thread
        still ran the request, so renames landed in the .i64 while the agent
        recorded every one of them as failed.
        """
        executed: list[object] = []
        release = threading.Event()

        class _BlockedRuntime:
            def execute_request(self, request: object) -> object:
                release.wait(3.0)
                executed.append(request)
                return "ok"

        executor = daemon_mod._MainThreadExecutor(
            _BlockedRuntime(), fast_timings(exec_timeout=0.2, execute_wait_margin=0.05)
        )
        threading.Thread(target=executor.serve, daemon=True).start()
        self.addCleanup(executor.stop)

        blocker = threading.Thread(target=lambda: self._swallow(executor, "blocker"), daemon=True)
        blocker.start()
        time.sleep(0.05)

        with self.assertRaises(TimeoutError):
            executor.execute_request("abandoned")  # never dequeued before giving up

        release.set()
        time.sleep(0.4)
        self.assertNotIn("abandoned", executed, "an abandoned request must never execute")

    @staticmethod
    def _swallow(executor: object, request: object) -> None:
        """Run a request and drop whatever it raises; used to occupy the executor."""
        try:
            executor.execute_request(request)
        except BaseException:  # noqa: BLE001 - helper only needs to keep the executor occupied.
            pass

    def test_late_interrupt_during_request_teardown_still_answers_the_waiter(self) -> None:
        """_end_request must survive an async interrupt on the lock acquire.

        The watchdog holds _state_lock across its ctypes call, so a serving
        thread finishing right then parks on that lock and takes the
        exception the instant it acquires it -- the limb production actually
        hits. Without the retry the waiter is never released and
        done.set() is skipped.
        """
        executor = daemon_mod._MainThreadExecutor(_FakeRuntime(), fast_timings(exec_timeout=30.0))

        class _InterruptingLock:
            """Fire _RequestInterrupt once, on _end_request's acquire.

            Keyed on the calling frame rather than an acquire count: serve()
            and the watchdog thread take this same lock on their own
            schedule, so counting is nondeterministic. _end_request is the
            limb the watchdog actually parks the serving thread on, and the
            one whose retry loop is under test.
            """

            def __init__(self) -> None:
                self._real = threading.Lock()
                self._armed = True

            def __enter__(self) -> object:
                if self._armed and sys._getframe(1).f_code.co_name == "_end_request":
                    self._armed = False
                    raise daemon_mod._RequestInterrupt
                return self._real.__enter__()

            def __exit__(self, *exc: object) -> None:
                self._real.__exit__(*exc)

        done = threading.Event()
        box: dict[str, object] = {}
        request = ProtocolRequest(code="__result__ = 1", request_id="late", has_id=True)
        executor._work.put((request, box, done))
        executor._state_lock = _InterruptingLock()

        threading.Thread(target=executor.serve, daemon=True).start()
        self.addCleanup(executor.stop)

        self.assertTrue(done.wait(2.0), "waiter was never released after a late interrupt")
        self.assertIn("response", box)

    def test_hung_request_gets_error_envelope_and_daemon_serves_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_DIR": tmp}):
                target = "D:/targets/hung.exe"
                server = DaemonServer(target, PythonRuntime(), timings=fast_timings(exec_timeout=0.2))
                server.start()
                self.addCleanup(server.shutdown)
                threading.Thread(target=server.serve_forever, daemon=True).start()

                client = DaemonClient(target, timings=fast_timings())
                client.connect()
                self.addCleanup(client.close)
                client.set_read_timeout(15.0)

                client.write('{"id":"hang","code":"while True: pass"}\n')
                hung = json.loads(client.readline())
                self.assertFalse(hung["ok"])
                self.assertEqual(hung["id"], "hang")
                self.assertEqual(hung["error"]["type"], "_RequestInterrupt")

                client.write('{"id":"after","code":"__result__ = 42"}\n')
                after = json.loads(client.readline())
                self.assertTrue(after["ok"])
                self.assertEqual(after["result"], 42)

    def test_execute_request_times_out_when_never_served(self) -> None:
        # Last-resort backstop for a dead watchdog: the wait must not hang.
        executor = daemon_mod._MainThreadExecutor(
            _FakeRuntime(), fast_timings(exec_timeout=0.2, execute_wait_margin=0.2)
        )
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            executor.execute_request(object())
        self.assertLess(time.monotonic() - started, 5.0)

    def test_execute_request_fails_fast_when_executor_stopped(self) -> None:
        executor = daemon_mod._MainThreadExecutor(_FakeRuntime(), fast_timings(exec_timeout=30.0))
        executor.stop()

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "stopped"):
            executor.execute_request(object())
        self.assertLess(time.monotonic() - started, 5.0)

    def test_serve_answers_queued_requests_with_error_on_stop(self) -> None:
        executor = daemon_mod._MainThreadExecutor(_FakeRuntime(), fast_timings(exec_timeout=30.0))
        outcome: dict[str, BaseException] = {}

        def _client() -> None:
            try:
                executor.execute_request("req")
            except BaseException as exc:  # noqa: BLE001 - record any failure for the assertion below.
                outcome["error"] = exc

        client_thread = threading.Thread(target=_client, daemon=True)
        client_thread.start()
        deadline = time.monotonic() + 5
        while executor._work.qsize() == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(executor._work.qsize(), 1)

        executor.stop()
        executor.serve()  # sees _stop and must drain the queue, not hang
        client_thread.join(timeout=5)

        self.assertFalse(client_thread.is_alive())
        self.assertIsInstance(outcome.get("error"), RuntimeError)

    def test_signal_handler_flags_interrupt_stops_executor_and_raises(self) -> None:
        executor = daemon_mod._MainThreadExecutor(_FakeRuntime(), fast_timings(exec_timeout=30.0))
        serve_thread = threading.Thread(target=executor.serve, daemon=True)
        serve_thread.start()
        main_mod._ACTIVE_EXECUTOR = executor

        with self.assertRaises(KeyboardInterrupt):
            main_mod._raise_keyboard_interrupt(signal.SIGTERM, None)

        self.assertTrue(runtime_mod._SIGNAL_INTERRUPT.is_set())
        serve_thread.join(timeout=5)
        self.assertFalse(serve_thread.is_alive(), "serve() must exit once stop() is called")

    def test_env_var_overrides_execution_budget(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_CLI_EXEC_TIMEOUT": "7.5"}):
            executor = daemon_mod._MainThreadExecutor(_FakeRuntime())
        self.assertEqual(executor._exec_timeout, 7.5)

    def test_invalid_env_var_falls_back_to_default_budget(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_CLI_EXEC_TIMEOUT": "not-a-number"}):
            executor = daemon_mod._MainThreadExecutor(_FakeRuntime())
        self.assertEqual(executor._exec_timeout, daemon_mod._DEFAULT_EXEC_TIMEOUT)


class DaemonDirTests(unittest.TestCase):
    """Verify the WSL shared-dir guess degrades gracefully off real WSL.

    These scenarios exercise the \\\\wsl$ UNC fallback, which only exists on
    Windows; on POSIX a set WSLENV legitimately means "inside WSL", where the
    shared /tmp dir is the correct answer.
    """

    @unittest.skipUnless(os.name == "nt", "\\\\wsl$ fallback is Windows-only")
    def test_unreachable_wsl_daemon_dir_falls_back_to_default(self) -> None:
        with mock.patch.dict(os.environ, {"WSLENV": "WT_SESSION:"}):
            os.environ.pop("IDA_CLI_DAEMON_DIR", None)
            with mock.patch.object(daemon_mod, "_wsl_share_reachable", return_value=True, create=True):
                with mock.patch.object(
                    daemon_mod,
                    "_wsl_to_win_path",
                    return_value="\\\\wsl$\\ida-cli-nonexistent-distro\\tmp\\.ida-cli\\daemons",
                ):
                    path = daemon_mod.get_daemon_dir()

        self.assertEqual(path, Path("~/.ida-cli/daemons").expanduser())
        self.assertTrue(path.is_dir())

    @unittest.skipUnless(os.name == "nt", "\\\\wsl$ fallback is Windows-only")
    def test_unreachable_wsl_share_skips_wsl_subprocesses(self) -> None:
        with mock.patch.dict(os.environ, {"WSLENV": "WT_SESSION:"}):
            os.environ.pop("IDA_CLI_DAEMON_DIR", None)
            with mock.patch.object(daemon_mod, "_wsl_share_reachable", return_value=False, create=True):
                with mock.patch.object(
                    daemon_mod,
                    "_wsl_to_win_path",
                    side_effect=AssertionError("wsl subprocess must not run"),
                ):
                    path = daemon_mod.get_daemon_dir()

        self.assertEqual(path, Path("~/.ida-cli/daemons").expanduser())
        self.assertTrue(path.is_dir())

    def test_console_output_decodes_utf16_and_utf8(self) -> None:
        decode = daemon_mod._decode_console_output
        self.assertEqual(decode("Debian\n".encode("utf-16-le")).strip(), "Debian")
        self.assertEqual(decode(b"Debian\n").strip(), "Debian")
        self.assertIn("�", decode(b"\xff\xfe invalid \xff"))

    def test_wsl_distro_name_handles_utf16_console_output(self) -> None:
        fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="Debian\n".encode("utf-16-le"))
        with mock.patch("subprocess.run", return_value=fake):
            self.assertEqual(daemon_mod._wsl_distro_name(), "Debian")


class TargetPathNormalizationTests(unittest.TestCase):
    """Relative and absolute spellings of one target must share a daemon."""

    def test_relative_and_absolute_paths_share_target_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a.exe"
            target.write_bytes(b"x")
            cwd = Path.cwd()
            try:
                os.chdir(tmp)
                relative = daemon_mod.get_target_id("a.exe")
            finally:
                os.chdir(cwd)
            absolute = daemon_mod.get_target_id(str(target))

        self.assertEqual(relative, absolute)

    def test_wsl_mnt_path_still_maps_to_windows_form(self) -> None:
        self.assertEqual(
            daemon_mod._normalize_target_path("/mnt/d/work/a.exe"),
            "D:\\work\\a.exe",
        )

    def test_mnt_lookalike_paths_never_share_a_target_id(self) -> None:
        # "/mnt/data/a.i64" once normalized to "D:\ta\a.i64", colliding with
        # "/mnt/d/ta/a.i64" — a client could reach a daemon serving another
        # database, so the two spellings must hash differently.
        self.assertNotEqual(
            daemon_mod.get_target_id("/mnt/data/a.i64"),
            daemon_mod.get_target_id("/mnt/d/ta/a.i64"),
        )


if __name__ == "__main__":
    unittest.main()
