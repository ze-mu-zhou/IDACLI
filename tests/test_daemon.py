"""Tests for daemon mode without requiring IDA."""

from __future__ import annotations

import contextlib
import io
import json
import os
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
from ida_cli.agent_bridge import AgentBridgeTimeoutError, AgentSession
from ida_cli.daemon import DaemonClient, DaemonServer


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
        self.server = DaemonServer(self.target, self.runtime)
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

        server = DaemonServer("D:/targets/threaded.exe", _IdentRuntime())
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

        client = DaemonClient("D:/targets/threaded.exe")
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

    def test_wrong_token_is_rejected(self) -> None:
        sock = self._connect_raw()
        with sock:
            sock.sendall(b'{"auth":"wrong-token"}\n{"id":1,"code":"__result__ = 1"}\n')
            payload = json.loads(self._recv_line(sock))

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["type"], "DaemonAuthError")
        self.assertEqual(self.runtime.requests, [])

    def test_client_round_trip_executes_requests(self) -> None:
        client = DaemonClient(self.target)
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
        with mock.patch.object(daemon_mod, "_AUTH_TIMEOUT", 0.2, create=True):
            sock = self._connect_raw(timeout=5.0)
            with sock:
                # Send nothing after the banner: the server must close the connection itself.
                eof = sock.recv(1)

        self.assertEqual(eof, b"")

    def test_non_loopback_bind_requires_explicit_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"IDA_CLI_DAEMON_HOST": "0.0.0.0"}):
            other = DaemonServer("D:/targets/other.exe", _FakeRuntime())
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

        client = DaemonClient(target)
        with self.assertRaisesRegex(RuntimeError, "banner"):
            client.connect()

    def test_write_private_file_refuses_existing_path(self) -> None:
        path = Path(self._tmp.name) / "existing.txt"
        path.write_text("original", encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "refusing"):
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
        server = DaemonServer(target, _FakeRuntime())
        # Keep cleanup from removing the symlink: it reappeared after cleanup (race lost).
        with mock.patch.object(daemon_mod, "_cleanup_daemon_files", lambda _target: None):
            with self.assertRaisesRegex(RuntimeError, "refusing"):
                server.start()
        server.shutdown()

        self.assertEqual(victim.read_text(encoding="utf-8"), "precious")

    def test_daemon_request_timeout_raises_bridge_timeout(self) -> None:
        target = "D:/targets/slow-daemon.exe"
        slow_server = DaemonServer(target, _SlowRuntime(1.0))
        slow_server.start()
        self.addCleanup(slow_server.shutdown)
        threading.Thread(target=slow_server.serve_forever, daemon=True).start()
        client = DaemonClient(target)
        client.connect()
        self.addCleanup(client.close)
        session = AgentSession(None, None, request_timeout_s=5.0, daemon_client=client)

        with self.assertRaises(AgentBridgeTimeoutError):
            session.execute("__result__ = 1", timeout_s=0.2)

        # The per-request read timeout must be restored to blocking afterwards.
        self.assertIsNone(client._sock.gettimeout())

    def test_daemon_request_within_timeout_succeeds(self) -> None:
        client = DaemonClient(self.target)
        client.connect()
        self.addCleanup(client.close)
        session = AgentSession(None, None, request_timeout_s=5.0, daemon_client=client)

        response = session.execute("__result__ = 1", request_id="fast", timeout_s=2.0)

        self.assertTrue(response["ok"])
        self.assertEqual(response["id"], "fast")

    def _connect_raw(self, timeout: float = 5.0) -> socket.socket:
        port = int(Path(daemon_mod.get_port_path(self.target)).read_text(encoding="utf-8").strip())
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
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
        self.assertEqual(decode("Debian\n".encode("utf-8")).strip(), "Debian")
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


if __name__ == "__main__":
    unittest.main()
