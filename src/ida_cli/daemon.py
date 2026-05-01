"""Daemon mode: keep one IDA kernel alive across multiple client sessions.

Uses TCP loopback (127.0.0.1) for cross-platform compatibility — works on
native Linux, Windows, and WSL. Clients connect/disconnect without restarting
the kernel — IDA database, globals, and caches are reused across sessions.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time
from pathlib import Path
from typing import Any


_DEFAULT_DAEMON_DIR = "~/.ida-cli/daemons"
_DAEMON_HOST = "127.0.0.1"
_STARTUP_POLL_INTERVAL = 0.05  # seconds
_STARTUP_TIMEOUT = 15.0  # seconds


def get_daemon_dir() -> Path:
    """Return the daemon runtime directory (created on first use)."""
    env = os.environ.get("IDA_CLI_DAEMON_DIR")
    path = Path(env).expanduser() if env else Path(_DEFAULT_DAEMON_DIR).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_target_id(target_path: str) -> str:
    """Return a deterministic short hash for a target path."""
    return hashlib.sha256(target_path.encode()).hexdigest()[:16]


def get_port_path(target_path: str) -> str:
    """Return path to the port file for a target daemon."""
    return str(get_daemon_dir() / f"{get_target_id(target_path)}.port")


def get_pid_path(target_path: str) -> str:
    """Return path to the PID file for a target daemon."""
    return str(get_daemon_dir() / f"{get_target_id(target_path)}.pid")


def is_daemon_running(target_path: str) -> bool:
    """Check whether a daemon for this target is alive."""
    pid_path = get_pid_path(target_path)
    port_path = get_port_path(target_path)
    if not Path(pid_path).is_file() or not Path(port_path).is_file():
        return False
    try:
        pid = int(Path(pid_path).read_text().strip())
        port = int(Path(port_path).read_text().strip())
    except (OSError, ValueError):
        return False
    # Verify PID is alive
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # Verify port is actually listening
    try:
        probe = socket.create_connection((_DAEMON_HOST, port), timeout=0.5)
        probe.close()
        return True
    except OSError:
        return False


def _cleanup_daemon_files(target_path: str) -> None:
    """Remove PID and port files for a target."""
    for p in (get_pid_path(target_path), get_port_path(target_path)):
        try:
            Path(p).unlink(missing_ok=True)
        except OSError:
            pass


class DaemonServer:
    """Accept client connections and serve the kernel runtime per connection."""

    def __init__(self, target_path: str, runtime: Any) -> None:
        self._target_path = target_path
        self._runtime = runtime
        self._port_path = get_port_path(target_path)
        self._pid_path = get_pid_path(target_path)
        self._server: socket.socket | None = None
        self._port: int = 0

    def start(self) -> None:
        """Bind on 127.0.0.1:0, write PID + port to files."""
        _cleanup_daemon_files(self._target_path)
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((_DAEMON_HOST, 0))
        self._port = self._server.getsockname()[1]
        self._server.listen(5)
        Path(self._pid_path).write_text(str(os.getpid()))
        Path(self._port_path).write_text(str(self._port))

    def serve_forever(self, timeout: float | None = None) -> None:
        """Accept connections and serve them sequentially until shutdown."""
        if self._server is None:
            raise RuntimeError("DaemonServer.start() must be called first")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = None if deadline is None else max(0, deadline - time.monotonic())
            if remaining == 0:
                break
            self._server.settimeout(remaining)
            try:
                conn, _addr = self._server.accept()
            except socket.timeout:
                break
            except OSError:
                break
            self._serve_connection(conn)

    def _serve_connection(self, conn: socket.socket) -> None:
        """Run one _serve() loop over a client connection."""
        try:
            with conn.makefile(mode="r", encoding="utf-8", errors="replace") as stdin, \
                 conn.makefile(mode="w", encoding="utf-8", errors="replace") as stdout:
                from .__main__ import _serve  # noqa: PLC0415
                _serve(self._runtime, stdin, stdout)
        except Exception:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def shutdown(self) -> None:
        """Close the server socket and remove runtime files."""
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        _cleanup_daemon_files(self._target_path)


class DaemonClient:
    """Connect to a daemon and provide a JSONL transport."""

    def __init__(self, target_path: str) -> None:
        self._target_path = target_path
        self._addr: tuple[str, int] | None = None
        self._sock: socket.socket | None = None
        self._stdin: Any = None
        self._stdout: Any = None

    def connect(self) -> None:
        """Connect to the daemon and prepare text-mode streams."""
        if not is_daemon_running(self._target_path):
            raise RuntimeError(
                f"No daemon running for {self._target_path!r}. "
                f"Start with: ida-ai --daemon {self._target_path}"
            )
        port = int(Path(get_port_path(self._target_path)).read_text().strip())
        self._addr = (_DAEMON_HOST, port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        started = time.monotonic()
        while True:
            try:
                self._sock.connect(self._addr)
                break
            except (ConnectionRefusedError, OSError):
                if time.monotonic() - started > _STARTUP_TIMEOUT:
                    raise TimeoutError(
                        f"Daemon did not become available within {_STARTUP_TIMEOUT}s "
                        f"for {self._target_path!r}"
                    ) from None
                time.sleep(_STARTUP_POLL_INTERVAL)
        self._stdin = self._sock.makefile(mode="w", encoding="utf-8", errors="replace")
        self._stdout = self._sock.makefile(mode="r", encoding="utf-8", errors="replace")

    def close(self) -> None:
        """Close the client connection without shutting down the daemon."""
        if self._stdin is not None:
            try: self._stdin.close()
            except OSError: pass
            self._stdin = None
        if self._stdout is not None:
            try: self._stdout.close()
            except OSError: pass
            self._stdout = None
        if self._sock is not None:
            try: self._sock.close()
            except OSError: pass
            self._sock = None

    def write(self, data: str) -> None:
        """Write one JSONL line to the daemon."""
        if self._stdin is None:
            raise RuntimeError("DaemonClient not connected")
        self._stdin.write(data)
        self._stdin.flush()

    def readline(self) -> str:
        """Read one JSONL line from the daemon."""
        if self._stdout is None:
            raise RuntimeError("DaemonClient not connected")
        return self._stdout.readline()


__all__ = (
    "DaemonClient",
    "DaemonServer",
    "get_port_path",
    "get_pid_path",
    "is_daemon_running",
)
