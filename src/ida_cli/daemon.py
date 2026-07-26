"""Daemon mode: keep one IDA kernel alive across multiple client sessions.

Uses TCP loopback (127.0.0.1) by default for cross-platform compatibility —
works on native Linux, Windows, and WSL. Clients connect/disconnect without
restarting the kernel — IDA database, globals, and caches are reused across
sessions.

Security model: the kernel executes arbitrary Python, so every connection
must authenticate with a per-daemon token before serving. The token is
generated at startup and written next to the port/pid files with owner-only
permissions; clients read it from the same daemon directory. Binding beyond
loopback (e.g. 0.0.0.0 for WSL/Windows cross-access) requires the explicit
IDA_CLI_DAEMON_HOST environment variable and prints a warning on startup.

Concurrency: each connection is served on its own thread so one idle or
slow client cannot block the others, while a shared lock serializes request
execution inside the (non-thread-safe) kernel runtime.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, TextIO


_DEFAULT_DAEMON_DIR = "~/.ida-cli/daemons"
# When running inside WSL (Windows Python spawned from WSL), use a shared
# temp directory that is accessible from both Windows and Linux sides.
_WSL_DAEMON_DIR = "/tmp/.ida-cli/daemons"
_DEFAULT_BIND_HOST = "127.0.0.1"
_AUTH_TIMEOUT = 10.0  # seconds a connection may take to present its token
_STARTUP_POLL_INTERVAL = 0.05  # seconds
_STARTUP_TIMEOUT = 15.0  # seconds
_BANNER_HELLO = "ida-cli-daemon"
_BANNER_VERSION = 1


def _get_connect_host() -> str:
    """Return the host address for clients to connect to the daemon.

    On WSL Linux, localhost doesn't reach Windows services — use the
    WSL gateway IP instead. On native platforms, use 127.0.0.1.
    """
    # Check if we're on the WSL client side (Linux, not Windows)
    if os.name != "nt" and Path("/proc/sys/fs/binfmt_misc/WSLInterop").is_file():
        try:
            returncode, output = _run_text(["ip", "route", "show", "default"])
            if returncode == 0 and output.startswith("default via "):
                return output.split()[2]
        except Exception:
            pass
    return "127.0.0.1"


def _run_text(argv: list[str]) -> tuple[int, str]:
    """Run a console command and decode its stdout without locale crashes."""
    import subprocess as sp
    result = sp.run(argv, capture_output=True, timeout=5)
    return result.returncode, _decode_console_output(result.stdout)


def _decode_console_output(data: bytes) -> str:
    """Decode console bytes from tools that may emit UTF-16 (wsl.exe pipes)."""
    if b"\x00" in data[:64]:
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def _wsl_share_reachable() -> bool:
    """Return whether the \\\\wsl$ UNC share responds (real WSL present)."""
    try:
        return Path("\\\\wsl$").exists()
    except OSError:
        return False


def _wsl_to_win_path(linux_path: str) -> str:
    """Convert a WSL path to Windows UNC path using wslpath.exe."""
    # Normalize to forward slashes for detection
    normalized = linux_path.replace("\\", "/")
    try:
        returncode, output = _run_text(["wslpath", "-w", normalized])
        if returncode == 0 and output.strip():
            return output.strip()
    except Exception:
        pass
    # Fallback: /tmp/x -> \\wsl$\Debian\tmp\x (best-effort)
    if normalized.startswith("/"):
        distro = _wsl_distro_name()
        sep = "\\"
        return f"\\\\wsl$\\{distro}{normalized.replace('/', sep)}"
    return linux_path


def _wsl_distro_name() -> str:
    """Return the WSL distro name or a safe default."""
    try:
        returncode, output = _run_text(["wsl.exe", "sh", "-c", "echo $WSL_DISTRO_NAME"])
        if returncode == 0 and output.strip():
            return output.strip()
    except Exception:
        pass
    return "Debian"


def get_daemon_dir() -> Path:
    """Return the daemon runtime directory (created on first use).

    When WSLENV is set (Windows Python spawned from WSL), uses /tmp/.ida-cli/
    converted to a Windows-accessible UNC path. The WSL Linux side reads the
    same files directly via /tmp/.ida-cli/. WSLENV also leaks into plain
    Windows terminals, so an unreachable WSL share falls back to the default.
    """
    env = os.environ.get("IDA_CLI_DAEMON_DIR")
    if env:
        path = Path(env).expanduser()
    elif os.environ.get("WSLENV"):
        if os.name == "nt" and not _wsl_share_reachable():
            # WSLENV leaks into plain Windows terminals; without a live WSL
            # share the UNC conversion would only slow every caller down.
            path = Path(_DEFAULT_DAEMON_DIR).expanduser()
        else:
            path = Path(_WSL_DAEMON_DIR)
            if os.name == "nt":
                path = Path(_wsl_to_win_path(str(path)))
    else:
        path = Path(_DEFAULT_DAEMON_DIR).expanduser()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = Path(_DEFAULT_DAEMON_DIR).expanduser()
        path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)  # owner-only daemon dir on POSIX; tolerated elsewhere
    except OSError:
        pass
    return path


def get_target_id(target_path: str) -> str:
    """Return a deterministic short hash for a target path.

    Normalizes WSL paths (/mnt/d/...) to Windows form (D:\\...) so
    daemon (Windows Python) and client (WSL Python) produce the same hash.
    """
    # Normalize WSL /mnt/X/ paths to X:\ for consistent hashing
    normalized = _normalize_target_path(target_path)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _normalize_target_path(path: str) -> str:
    """Canonicalize a target path so all spellings share one daemon identity.

    WSL /mnt/d/... paths map to the Windows D:\\... form (they are not valid
    local paths, so they are returned before filesystem resolution); every
    other spelling is resolved to an absolute path so that relative and
    absolute references to the same target hash identically.
    """
    p = path.replace("\\", "/")
    if p.startswith("/mnt/") and len(p) > 6:
        drive = p[5].upper()
        tail = p[7:]
        sep = "\\"
        return f"{drive}:{sep}{tail.replace('/', sep)}"
    return str(Path(path).expanduser().resolve())


def get_port_path(target_path: str) -> str:
    """Return path to the port file for a target daemon."""
    return str(get_daemon_dir() / f"{get_target_id(target_path)}.port")


def get_pid_path(target_path: str) -> str:
    """Return path to the PID file for a target daemon."""
    return str(get_daemon_dir() / f"{get_target_id(target_path)}.pid")


def get_token_path(target_path: str) -> str:
    """Return path to the auth token file for a target daemon."""
    return str(get_daemon_dir() / f"{get_target_id(target_path)}.token")


def is_daemon_running(target_path: str) -> bool:
    """Check whether a daemon for this target is alive.

    A bare TCP connect is not enough — a crashed daemon's port may be reused
    by an unrelated service. Probe the protocol banner instead: only a real
    ida-cli daemon identifies itself with {"hello": "ida-cli-daemon"}.
    """
    pid_path = get_pid_path(target_path)
    port_path = get_port_path(target_path)
    if not Path(pid_path).is_file() or not Path(port_path).is_file():
        return False
    try:
        pid = int(Path(pid_path).read_text().strip())
        port = int(Path(port_path).read_text().strip())
    except (OSError, ValueError):
        return False
    # Verify the peer speaks the ida-cli daemon protocol (PID check unreliable cross-platform)
    try:
        host = _get_connect_host()
        probe = socket.create_connection((host, port), timeout=0.5)
        try:
            reader = probe.makefile(mode="r", encoding="utf-8", errors="replace")
            try:
                line = reader.readline()
            finally:
                reader.close()
        finally:
            probe.close()
    except OSError:
        return False
    try:
        payload = json.loads(line)
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("hello") == _BANNER_HELLO


def _cleanup_daemon_files(target_path: str) -> None:
    """Remove PID, port, and token files for a target."""
    for p in (get_pid_path(target_path), get_port_path(target_path), get_token_path(target_path)):
        try:
            Path(p).unlink(missing_ok=True)
        except OSError:
            pass


def _write_private_file(path: str, content: str) -> None:
    """Write a new owner-only file, refusing to clobber anything already there.

    Uses O_CREAT | O_EXCL (plus O_NOFOLLOW where available) so a file or
    symlink appearing between cleanup and write is never followed or
    overwritten — an existing path means a lost race or an attack.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"refusing to overwrite existing daemon file: {path}") from exc
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _banner_payload() -> dict[str, Any]:
    """Return the protocol banner sent to every accepted connection."""
    return {"hello": _BANNER_HELLO, "version": _BANNER_VERSION}


class _MainThreadExecutor:
    """Run runtime requests on the thread that calls serve_forever.

    IDA only answers API calls from the thread that opened the database, so
    connection threads hand requests over a queue and wait for the answer.
    """

    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime
        self._work: queue.Queue = queue.Queue()
        self._stop = threading.Event()

    def execute_request(self, request: Any) -> Any:
        """Enqueue one request and wait for the serving thread to answer."""
        box: dict[str, Any] = {}
        done = threading.Event()
        self._work.put((request, box, done))
        done.wait()
        if "error" in box:
            raise box["error"]
        return box["response"]

    def serve(self) -> None:
        """Drain queued requests until stopped; call from the serving thread."""
        while not self._stop.is_set():
            try:
                request, box, done = self._work.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                box["response"] = self._runtime.execute_request(request)
            except BaseException as exc:
                box["error"] = exc
            finally:
                done.set()

    def stop(self) -> None:
        """Ask serve() to return after the in-flight request completes."""
        self._stop.set()


class DaemonServer:
    """Accept client connections and serve the kernel runtime per connection."""

    def __init__(self, target_path: str, runtime: Any) -> None:
        self._target_path = target_path
        self._runtime = _MainThreadExecutor(runtime)
        self._port_path = get_port_path(target_path)
        self._pid_path = get_pid_path(target_path)
        self._token_path = get_token_path(target_path)
        self._server: socket.socket | None = None
        self._port: int = 0
        self._token: str = ""

    def start(self) -> None:
        """Bind the listening socket and write token, PID, and port files.

        Binds 127.0.0.1:0 by default. Set IDA_CLI_DAEMON_HOST to bind another
        interface (e.g. 0.0.0.0 for WSL/Windows cross-access); any non-loopback
        bind prints a warning because it exposes kernel execution to the network.
        """
        _cleanup_daemon_files(self._target_path)
        host = os.environ.get("IDA_CLI_DAEMON_HOST", _DEFAULT_BIND_HOST)
        if host != _DEFAULT_BIND_HOST:
            print(
                f"ida-cli daemon: WARNING binding {host} exposes the kernel "
                "beyond loopback; clients must authenticate with the daemon token",
                file=sys.stderr,
            )
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, 0))
        self._port = self._server.getsockname()[1]
        self._server.listen(5)
        self._token = secrets.token_hex(32)
        try:
            _write_private_file(self._token_path, self._token)
            _write_private_file(self._pid_path, str(os.getpid()))
            _write_private_file(self._port_path, str(self._port))
        except Exception:
            try:
                self._server.close()
            finally:
                self._server = None
            _cleanup_daemon_files(self._target_path)
            raise

    def serve_forever(self, timeout: float | None = None) -> None:
        """Serve connections until shutdown; request execution stays on this thread."""
        if self._server is None:
            raise RuntimeError("DaemonServer.start() must be called first")
        acceptor = threading.Thread(
            target=self._accept_loop,
            args=(timeout,),
            name="ida-cli-daemon-accept",
            daemon=True,
        )
        acceptor.start()
        try:
            self._runtime.serve()
        finally:
            self._runtime.stop()
            acceptor.join(timeout=2)

    def _accept_loop(self, timeout: float | None) -> None:
        """Accept connections and serve each on its own thread until stopped."""
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while True:
                remaining = None if deadline is None else max(0, deadline - time.monotonic())
                if remaining == 0:
                    break
                server = self._server
                if server is None:
                    break  # shutdown() closed the socket from another thread
                try:
                    server.settimeout(remaining)
                    conn, _addr = server.accept()
                except socket.timeout:
                    break
                except OSError:
                    break
                thread = threading.Thread(
                    target=self._serve_connection,
                    args=(conn,),
                    name="ida-cli-daemon-client",
                    daemon=True,
                )
                thread.start()
        finally:
            self._runtime.stop()

    def _serve_connection(self, conn: socket.socket) -> None:
        """Send the protocol banner, authenticate, then run one _serve() loop."""
        try:
            conn.settimeout(_AUTH_TIMEOUT)
            with conn.makefile(mode="r", encoding="utf-8", errors="replace") as stdin, \
                 conn.makefile(mode="w", encoding="utf-8", errors="replace") as stdout:
                from .protocol import write_jsonl  # noqa: PLC0415
                write_jsonl(stdout, _banner_payload())
                if not self._authorize(stdin, stdout):
                    return
                conn.settimeout(None)
                from .__main__ import _serve  # noqa: PLC0415
                _serve(self._runtime, stdin, stdout)
        except Exception as exc:
            print(f"ida-cli daemon: connection handler failed: {exc!r}", file=sys.stderr)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def _authorize(self, stdin: TextIO, stdout: TextIO) -> bool:
        """Require the first client line to carry the daemon auth token."""
        line = stdin.readline()
        if line == "":
            return False  # banner probe or peer vanished before presenting a token
        try:
            payload = json.loads(line)
        except ValueError:
            payload = None
        token = payload.get("auth") if isinstance(payload, dict) else None
        if isinstance(token, str) and hmac.compare_digest(token, self._token):
            return True
        from .protocol import error_response, write_jsonl  # noqa: PLC0415
        write_jsonl(
            stdout,
            error_response(
                None,
                error_type="DaemonAuthError",
                message="daemon authentication failed: send {\"auth\": <token>} first",
                traceback="",
                stdout="",
                stderr="",
            ),
        )
        return False

    def shutdown(self) -> None:
        """Stop accepting and executing, close the socket, remove runtime files."""
        self._runtime.stop()
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
        """Connect to the daemon, validate its protocol banner, and authenticate."""
        if not is_daemon_running(self._target_path):
            raise RuntimeError(
                f"No daemon running for {self._target_path!r}. "
                f"Start with: ida-ai --daemon {self._target_path}"
            )
        port = int(Path(get_port_path(self._target_path)).read_text().strip())
        host = _get_connect_host()
        self._addr = (host, port)
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
        self._sock.settimeout(_AUTH_TIMEOUT)  # bound the banner read
        self._stdin = self._sock.makefile(mode="w", encoding="utf-8", errors="replace")
        self._stdout = self._sock.makefile(mode="r", encoding="utf-8", errors="replace")
        self._read_banner()
        self._sock.settimeout(None)
        self.write(json.dumps({"auth": self._read_token()}) + "\n")

    def _read_banner(self) -> None:
        """Require the peer's first line to be the ida-cli daemon banner."""
        try:
            line = self._stdout.readline()
        except OSError as exc:
            self.close()
            raise RuntimeError(
                f"daemon banner read failed for {self._target_path!r}: {exc}"
            ) from exc
        try:
            payload = json.loads(line)
        except ValueError:
            payload = None
        if not isinstance(payload, dict) or payload.get("hello") != _BANNER_HELLO:
            self.close()
            raise RuntimeError(
                f"invalid daemon banner for {self._target_path!r}: not an ida-cli daemon"
            )

    def _read_token(self) -> str:
        """Read the daemon auth token written next to the port/pid files."""
        try:
            return Path(get_token_path(self._target_path)).read_text(encoding="utf-8").strip()
        except OSError:
            self.close()
            raise RuntimeError(
                f"Daemon auth token missing for {self._target_path!r}; restart the daemon"
            ) from None

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

    def set_read_timeout(self, timeout_s: float | None) -> None:
        """Set the socket timeout applied to subsequent reads; None restores blocking."""
        if self._sock is None:
            raise RuntimeError("DaemonClient not connected")
        self._sock.settimeout(timeout_s)

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
    "get_token_path",
    "is_daemon_running",
)
