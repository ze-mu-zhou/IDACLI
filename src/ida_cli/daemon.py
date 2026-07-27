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

import errno
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
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
# A WSL Windows-drive mount is exactly one letter: /mnt/d or /mnt/d/...
_MNT_DRIVE_RE = re.compile(r"^/mnt/([A-Za-z])($|/)")
_PROBE_TIMEOUT = 3.0  # seconds a liveness probe waits for connect + banner
# A token line is ~80 bytes. The 16 MiB request cap lives past authentication,
# so without this an unauthenticated peer could stream unbounded data into one
# connection buffer (measured: 1 GiB in ~2.4 s, daemon RSS +1.1 GiB).
_MAX_AUTH_LINE_CHARS = 4096
# accept() failing for lack of descriptors is transient, not fatal.
_ACCEPT_RETRYABLE_ERRNOS = frozenset(
    code for code in (getattr(errno, name, None) for name in ("EMFILE", "ENFILE", "ENOBUFS", "ENOMEM"))
    if code is not None
)
_ACCEPT_BACKOFF = 0.05  # seconds to wait out descriptor pressure before retrying
_OWNER_PROBE_ATTEMPTS = 3  # liveness probes after losing the O_EXCL race
_OWNER_PROBE_INTERVAL = 0.5  # seconds between probes; the winner may still be starting
# Startup probes retry, so each one stays short: a dead port must not make
# every daemon launch pay the full tolerant timeout three times over.
_OWNER_PROBE_TIMEOUT = 0.5
_EXEC_TIMEOUT_ENV = "IDA_CLI_EXEC_TIMEOUT"
_DEFAULT_EXEC_TIMEOUT = 300.0  # seconds one request may occupy the kernel
_EXECUTE_WAIT_MARGIN = 5.0  # grace beyond the budget in execute_request
_WATCHDOG_POLL = 0.1  # seconds between watchdog checks
_WATCHDOG_REFIRE = 1.0  # seconds between async-exception deliveries


@dataclass(frozen=True, slots=True)
class DaemonTimings:
    """Every wall-clock knob one daemon or client obeys; defaults are production.

    Injected rather than read from module globals so callers -- above all
    tests -- can exercise the real timing code paths at millisecond scale
    instead of sleeping through production timeouts. Patching the globals
    instead makes concurrent daemons in one process fight over shared
    state, which is exactly the flakiness this replaces.

    ``exec_timeout=None`` defers to IDA_CLI_EXEC_TIMEOUT and then to
    _DEFAULT_EXEC_TIMEOUT, so injecting timings never silently overrides an
    operator's environment.
    """

    auth_timeout: float = _AUTH_TIMEOUT
    exec_timeout: float | None = None
    execute_wait_margin: float = _EXECUTE_WAIT_MARGIN
    watchdog_poll: float = _WATCHDOG_POLL
    watchdog_refire: float = _WATCHDOG_REFIRE
    owner_probe_attempts: int = _OWNER_PROBE_ATTEMPTS
    owner_probe_interval: float = _OWNER_PROBE_INTERVAL
    owner_probe_timeout: float = _OWNER_PROBE_TIMEOUT
    startup_timeout: float = _STARTUP_TIMEOUT
    startup_poll_interval: float = _STARTUP_POLL_INTERVAL

    def resolved_exec_timeout(self) -> float:
        """Return the effective per-request budget in seconds."""
        return _exec_timeout_seconds() if self.exec_timeout is None else self.exec_timeout

    def scaled(self, factor: float) -> DaemonTimings:
        """Return the same knobs scaled by factor; handy for slow CI hosts."""
        return replace(
            self,
            auth_timeout=self.auth_timeout * factor,
            exec_timeout=None if self.exec_timeout is None else self.exec_timeout * factor,
            execute_wait_margin=self.execute_wait_margin * factor,
            watchdog_poll=self.watchdog_poll * factor,
            watchdog_refire=self.watchdog_refire * factor,
            owner_probe_interval=self.owner_probe_interval * factor,
            owner_probe_timeout=self.owner_probe_timeout * factor,
            startup_timeout=self.startup_timeout * factor,
            startup_poll_interval=self.startup_poll_interval * factor,
        )


DEFAULT_TIMINGS = DaemonTimings()


class _RequestInterrupt(Exception):
    """Raised asynchronously in the serving thread when a request overruns its budget."""


def _exec_timeout_seconds() -> float:
    """Return the per-request execution budget; IDA_CLI_EXEC_TIMEOUT overrides."""
    raw = os.environ.get(_EXEC_TIMEOUT_ENV)
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = 0
        if value > 0:
            return value
    return _DEFAULT_EXEC_TIMEOUT


def _raise_async_in_thread(ident: int, exc_type: type[BaseException]) -> bool:
    """Deliver exc_type to a running thread; return False when unsupported.

    PyThreadState_SetAsyncExc is CPython's only cross-thread interrupt and is
    inherently blunt: the exception can surface inside finally blocks or —
    when it lands late — during the next request. Callers must narrow that
    window with a generation check and tolerate late delivery; code that
    cannot use ctypes (non-CPython) degrades to logging only.
    """
    try:
        import ctypes
        set_async = ctypes.pythonapi.PyThreadState_SetAsyncExc
    except (ImportError, AttributeError):
        return False
    set_async.argtypes = (ctypes.c_ulong, ctypes.py_object)
    set_async.restype = ctypes.c_int
    raised = set_async(ctypes.c_ulong(ident), ctypes.py_object(exc_type))
    if raised == 0:
        return False  # thread already gone
    if raised > 1:
        # Defensive: the API promises 0/1 for one ident; undo rather than
        # leave exceptions pending in unknown threads.
        set_async(ctypes.c_ulong(ident), None)
        return False
    return True


def _get_connect_host() -> str:
    """Return the host address for clients to connect to the daemon.

    On WSL Linux, localhost doesn't reach Windows services — use the
    WSL gateway IP instead. On native platforms, use 127.0.0.1.
    """
    # Check if we're on the WSL client side (Linux, not Windows)
    if os.name != "nt" and Path("/proc/sys/fs/binfmt_misc/WSLInterop").is_file():
        try:
            returncode, output = _run_text(["ip", "route", "show", "default"])
            fields = output.split()
            if returncode == 0 and fields[:2] == ["default", "via"] and len(fields) >= 3:
                return fields[2]
        except (OSError, subprocess.TimeoutExpired):
            pass
    return "127.0.0.1"


def _run_text(argv: list[str]) -> tuple[int, str]:
    """Run a console command and decode its stdout without locale crashes."""
    result = subprocess.run(argv, capture_output=True, timeout=5)
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
    except (OSError, subprocess.TimeoutExpired):
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
    except (OSError, subprocess.TimeoutExpired):
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
    local paths, so they are returned before filesystem resolution), and
    paths already in Windows drive form pass through unchanged on POSIX
    hosts — resolve() there would mangle them into cwd-relative nonsense,
    while on Windows resolve() is exactly what canonicalizes 8.3/case
    spellings. Every other spelling is resolved to an absolute path so that
    relative and absolute references to the same target hash identically.

    Only ^/mnt/<letter>($|/) counts as a drive mapping: guessing a drive
    from longer names ("/mnt/data/..." → "D:\\ta\\...") both corrupts the
    path and collides with genuine /mnt/d/ta/... spellings.
    """
    p = path.replace("\\", "/")
    match = _MNT_DRIVE_RE.match(p)
    if match:
        drive = match.group(1).upper()
        tail = p[match.end():].strip("/")
        sep = "\\"
        return f"{drive}:{sep}{tail.replace('/', sep)}"
    if os.name != "nt" and len(p) >= 3 and p[0].isalpha() and p[1] == ":" and p[2] == "/":
        return path  # Windows absolute form on a POSIX host; resolve() would mangle it
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


def is_daemon_running(target_path: str, *, timeout: float = _PROBE_TIMEOUT) -> bool:
    """Check whether a daemon for this target is alive.

    A bare TCP connect is not enough — a crashed daemon's port may be reused
    by an unrelated service. Probe the protocol banner instead: only a real
    ida-cli daemon identifies itself with {"hello": "ida-cli-daemon"}.

    timeout bounds both the connect and the banner read. Keep it generous:
    a busy daemon that answers late must not be reported dead, because
    callers turn that into "no daemon running" and either refuse to connect
    or try to start a duplicate.
    """
    port_path = get_port_path(target_path)
    if not Path(get_pid_path(target_path)).is_file() or not Path(port_path).is_file():
        return False
    try:
        port = int(Path(port_path).read_text().strip())
    except (OSError, ValueError):
        return False
    # Verify the peer speaks the ida-cli daemon protocol (PID check unreliable cross-platform)
    try:
        host = _get_connect_host()
        probe = socket.create_connection((host, port), timeout=timeout)
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
    overwritten — an existing path means a lost race or an attack, and the
    caller decides whether it is stale or belongs to a live daemon.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class DaemonRunningError(RuntimeError):
    """Raised when registration files belong to another live daemon."""


def _probe_owner_alive(target_path: str, timings: DaemonTimings = DEFAULT_TIMINGS) -> bool:
    """Probe for a live daemon, retrying while the winner's accept loop starts.

    The race winner can hold the registration files for a moment before its
    accept loop answers the banner probe, so one negative answer is not
    proof of a stale file.
    """
    for attempt in range(timings.owner_probe_attempts):
        if is_daemon_running(target_path, timeout=timings.owner_probe_timeout):
            return True
        if attempt + 1 < timings.owner_probe_attempts:
            time.sleep(timings.owner_probe_interval)
    return False


def _banner_payload() -> dict[str, Any]:
    """Return the protocol banner sent to every accepted connection."""
    return {"hello": _BANNER_HELLO, "version": _BANNER_VERSION}


class _MainThreadExecutor:
    """Run runtime requests on the thread that calls serve_forever.

    IDA only answers API calls from the thread that opened the database, so
    connection threads hand requests over a queue and wait for the answer.

    A watchdog thread bounds every request to the execution budget (default
    300s, IDA_CLI_EXEC_TIMEOUT overrides): an overrun gets _RequestInterrupt
    delivered asynchronously into the serving thread, so even a tight
    `while True: pass` bytecode loop is interrupted and the daemon keeps
    serving later requests. execute_request itself also waits with a
    deadline (budget + margin) as a last-resort backstop in case the
    watchdog cannot fire (e.g. no ctypes on a non-CPython host).
    """

    def __init__(self, runtime: Any, timings: DaemonTimings = DEFAULT_TIMINGS) -> None:
        self._runtime = runtime
        self._work: queue.Queue[tuple[Any, dict[str, Any], threading.Event]] = queue.Queue()
        self._stop = threading.Event()
        self._timings = timings
        self._exec_timeout = timings.resolved_exec_timeout()
        # Watchdog state: guarded by _state_lock; the epoch counts request
        # starts/ends so the watchdog never interrupts a *new* request.
        self._state_lock = threading.Lock()
        self._serve_ident: int | None = None
        self._request_started: float | None = None
        self._request_epoch = 0
        self._last_interrupt_at = 0.0
        self._watchdog: threading.Thread | None = None
        # Separate from _stop on purpose: stop() means "abandon the in-flight
        # request", which is exactly when the watchdog is needed most. Only
        # serve() returning retires the watchdog.
        self._watchdog_stop = threading.Event()

    def execute_request(self, request: Any) -> Any:
        """Enqueue one request and wait for the serving thread to answer.

        The budget is charged from the moment the serving thread DEQUEUES
        the request, not from enqueue. Charging queue time to the waiter tore
        down a perfectly healthy client that was merely sitting behind a slow
        one -- and its request then executed against the database anyway,
        because nothing ever told the serving thread the caller had left.

        A waiter that does give up marks its box abandoned, and _serve_one
        refuses to run an abandoned request. Two distinct give-up reasons are
        reported so an operator can tell "your own request ran too long" from
        "the kernel never got to your request".
        """
        box: dict[str, Any] = {}
        done = threading.Event()
        self._work.put((request, box, done))
        limit = self._exec_timeout + self._timings.execute_wait_margin
        idle_since = time.monotonic()
        last_epoch = self._request_epoch
        while not done.wait(timeout=self._timings.watchdog_poll):
            if self._stop.is_set():
                self._abandon(box)
                raise RuntimeError("daemon executor stopped while the request was in flight")
            now = time.monotonic()
            started_at = box.get("started_at")
            if started_at is not None:
                if now - started_at >= limit:
                    self._abandon(box)
                    raise TimeoutError("daemon request outlived the execution budget and its margin")
                continue
            # Still queued. Waiting behind healthy work is not this request's
            # fault, so the clock only runs while the executor makes NO
            # progress: every start or finish bumps the epoch and resets it.
            # A stalled epoch means the kernel is stuck on something the
            # watchdog cannot interrupt -- a long native IDA call offers no
            # bytecode boundary to deliver an exception at.
            epoch = self._request_epoch
            if epoch != last_epoch:
                last_epoch = epoch
                idle_since = now
            elif now - idle_since >= limit:
                self._abandon(box)
                raise TimeoutError(
                    "daemon request was never executed: the kernel stopped making progress"
                )
        if "error" in box:
            raise box["error"]
        return box["response"]

    def _abandon(self, box: dict[str, Any]) -> None:
        """Mark a request as no longer wanted, under the start/finish lock.

        Taking _state_lock makes abandonment atomic against _begin_request,
        so a request can never be observed as "not abandoned" and then be
        abandoned between that check and the call into the runtime.
        """
        with self._state_lock:
            box["abandoned"] = True

    def serve(self) -> None:
        """Drain queued requests until stopped; call from the serving thread.

        On exit, still-queued requests are answered with an error so their
        waiting connection threads release instead of hanging forever.
        """
        with self._state_lock:
            self._serve_ident = threading.get_ident()
        self._start_watchdog()
        try:
            while not self._stop.is_set():
                try:
                    self._serve_one()
                except _RequestInterrupt:
                    # Async delivery that landed outside a request body (the
                    # queue wait, or after the answer was already recorded).
                    # It must never escape: serve_forever only unwinds on
                    # KeyboardInterrupt, so anything else kills the daemon.
                    continue
        finally:
            self._watchdog_stop.set()
            self._answer_leftovers()
            with self._state_lock:
                self._serve_ident = None

    def _serve_one(self) -> None:
        """Run at most one queued request, always answering its waiter.

        Every step after the request leaves the queue sits inside the
        try/finally, so a late _RequestInterrupt becomes that request's
        error instead of stranding a connection thread on ``done``.
        """
        try:
            request, box, done = self._work.get(timeout=self._timings.watchdog_poll)
        except queue.Empty:
            return
        try:
            if not self._begin_request(box):
                # The waiter gave up before we reached this request. Running it
                # would mutate the database on behalf of a caller that already
                # recorded the operation as failed.
                box["error"] = RuntimeError("request abandoned by its caller before execution")
                return
            box["response"] = self._runtime.execute_request(request)
        except BaseException as exc:  # noqa: BLE001 - async interrupts must still release the waiter.
            box["error"] = exc
        finally:
            # _begin_request lives inside this try on purpose: it takes
            # _state_lock, which is exactly where a late async interrupt lands,
            # and outside the try that would strand the waiter on ``done``.
            self._end_request(done)

    def _begin_request(self, box: dict[str, Any]) -> bool:
        """Start the budget clock, or report that the waiter already left.

        Publishing the dequeue time into the box is what lets execute_request
        charge the budget from execution rather than from enqueue; the
        abandonment check shares this lock so the two can never interleave.
        """
        with self._state_lock:
            if box.get("abandoned"):
                return False
            self._request_started = time.monotonic()
            box["started_at"] = self._request_started
            self._request_epoch += 1
            return True

    def _end_request(self, done: threading.Event) -> None:
        """Clear in-flight state and release the waiter, retrying past interrupts.

        The watchdog holds _state_lock across its ctypes call, so a serving
        thread that reaches this point mid-fire parks on that very lock and
        takes the exception the instant it acquires it. Retrying is safe:
        the assignments and ``done.set()`` are both idempotent, and once
        _request_started is None the watchdog cannot fire again.
        """
        while True:
            try:
                with self._state_lock:
                    self._request_started = None
                    self._request_epoch += 1
                done.set()
                return
            except _RequestInterrupt:
                continue

    def _answer_leftovers(self) -> None:
        """Fail every still-queued request so no connection thread hangs."""
        while True:
            try:
                _request, box, done = self._work.get_nowait()
            except queue.Empty:
                return
            box["error"] = RuntimeError("daemon executor stopped before executing the request")
            done.set()

    def _start_watchdog(self) -> None:
        """Start the execution-budget monitor thread (idempotent)."""
        if self._watchdog is not None:
            return
        self._watchdog = threading.Thread(
            target=self._watchdog_loop,
            name="ida-cli-daemon-watchdog",
            daemon=True,
        )
        self._watchdog.start()

    def _watchdog_loop(self) -> None:
        """Interrupt the serving thread while one request overruns its welcome.

        Two triggers: the execution budget, and stop() — a stopped executor
        has abandoned the in-flight request, so making it wait out the full
        budget would leave shutdown blocked behind a hung request. This loop
        must key off _watchdog_stop rather than _stop for exactly that
        reason; retiring on _stop would disarm the watchdog at the moment
        the daemon needs it to unwedge the serve loop.
        """
        while not self._watchdog_stop.wait(self._timings.watchdog_poll):
            with self._state_lock:
                started = self._request_started
                ident = self._serve_ident
                if started is None or ident is None:
                    continue
                now = time.monotonic()
                overdue = self._stop.is_set() or now - started >= self._exec_timeout
                if not overdue or now - self._last_interrupt_at < self._timings.watchdog_refire:
                    continue
                self._last_interrupt_at = now
                # The lock is held across the ctypes call on purpose: the
                # serving thread must take it to start or finish a request,
                # so the interrupt cannot land in the *next* request's work.
                if _raise_async_in_thread(ident, _RequestInterrupt):
                    print(
                        f"ida-cli daemon: interrupting request after "
                        f"{time.monotonic() - started:.1f}s (budget {self._exec_timeout:g}s)",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "ida-cli daemon: request exceeded its budget but this "
                        "Python cannot interrupt threads (no ctypes); logging only",
                        file=sys.stderr,
                    )

    def stop(self) -> None:
        """Ask serve() to return, interrupting any request still in flight."""
        self._stop.set()


class DaemonServer:
    """Accept client connections and serve the kernel runtime per connection."""

    def __init__(self, target_path: str, runtime: Any, *, timings: DaemonTimings = DEFAULT_TIMINGS) -> None:
        self._target_path = target_path
        self._timings = timings
        self._runtime = _MainThreadExecutor(runtime, timings)
        self._port_path = get_port_path(target_path)
        self._pid_path = get_pid_path(target_path)
        self._token_path = get_token_path(target_path)
        self._server: socket.socket | None = None
        self._port: int = 0
        self._token: str = ""
        self._registration_written = False

    def start(self) -> None:
        """Bind the listening socket and write token, PID, and port files.

        Binds 127.0.0.1:0 by default. Set IDA_CLI_DAEMON_HOST to bind another
        interface (e.g. 0.0.0.0 for WSL/Windows cross-access); any non-loopback
        bind prints a warning because it exposes kernel execution to the network.

        Registration files are created with O_EXCL and never pre-cleaned:
        deleting them first would let a second daemon orphan a live one. On
        FileExistsError the owner is probed — a live daemon means
        DaemonRunningError, stale files are removed and the write retried.
        """
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
        # Every liveness probe costs one connection and unauthenticated peers
        # linger for _AUTH_TIMEOUT, so a small backlog makes concurrent
        # clients time out on connect() against a perfectly healthy daemon.
        self._server.listen(socket.SOMAXCONN)
        self._token = secrets.token_hex(32)
        try:
            self._write_registration_files()
        except FileExistsError:
            self._handle_registration_conflict()
        except Exception:
            self._abort_start(cleanup=True)
            raise

    def _write_registration_files(self) -> None:
        """Write token, PID, and port files; O_EXCL guards every write."""
        _write_private_file(self._token_path, self._token)
        _write_private_file(self._pid_path, str(os.getpid()))
        _write_private_file(self._port_path, str(self._port))
        self._registration_written = True

    def _handle_registration_conflict(self) -> None:
        """Resolve a FileExistsError from the first registration write."""
        if _probe_owner_alive(self._target_path, self._timings):
            self._abort_start(cleanup=False)  # the files belong to the winner
            raise DaemonRunningError(f"Daemon already running for {self._target_path!r}")
        _cleanup_daemon_files(self._target_path)  # stale files from a dead daemon
        try:
            self._write_registration_files()
        except Exception:
            # No cleanup here: a third party may have won the fresh race, and
            # partial files of ours are taken over by the next stale sweep.
            self._abort_start(cleanup=False)
            raise

    def _abort_start(self, *, cleanup: bool) -> None:
        """Close the listening socket after a failed start()."""
        try:
            if self._server is not None:
                self._server.close()
        except OSError:
            pass
        finally:
            self._server = None
        if cleanup:
            _cleanup_daemon_files(self._target_path)

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
                except TimeoutError:
                    break
                except OSError as exc:
                    if exc.errno in _ACCEPT_RETRYABLE_ERRNOS:
                        # Out of file descriptors, not a dead listener. Killing
                        # the daemon here would turn transient fd pressure --
                        # which an unauthenticated peer can provoke -- into a
                        # lost IDA session. Back off and keep accepting.
                        print(
                            f"ida-cli daemon: accept deferred, out of descriptors ({exc})",
                            file=sys.stderr,
                        )
                        time.sleep(_ACCEPT_BACKOFF)
                        continue
                    break
                thread = threading.Thread(
                    target=self._serve_connection,
                    args=(conn,),
                    name="ida-cli-daemon-client",
                    daemon=True,
                )
                try:
                    thread.start()
                except RuntimeError as exc:
                    # "can't start new thread". This call sits outside the
                    # accept try on purpose, so without this guard the error
                    # escapes the loop and takes the whole daemon down; drop
                    # the one connection instead.
                    print(f"ida-cli daemon: cannot serve connection ({exc})", file=sys.stderr)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    time.sleep(_ACCEPT_BACKOFF)
        finally:
            self._runtime.stop()

    def _serve_connection(self, conn: socket.socket) -> None:
        """Send the protocol banner, authenticate, then run one _serve() loop."""
        try:
            accepted_at = time.monotonic()
            conn.settimeout(self._timings.auth_timeout)
            with conn.makefile(mode="r", encoding="utf-8", errors="replace") as stdin, \
                 conn.makefile(mode="w", encoding="utf-8", errors="replace") as stdout:
                from .protocol import write_jsonl
                write_jsonl(stdout, _banner_payload())
                if not self._authorize(stdin, stdout, accepted_at):
                    return
                conn.settimeout(None)
                from .__main__ import _serve
                try:
                    _serve(self._runtime, stdin, stdout, control_handler=self._handle_control_message)
                except (TimeoutError, RuntimeError) as exc:
                    # The executor gave up on this request (budget exhausted, or
                    # the kernel never dequeued it). Say so in the protocol
                    # instead of dropping the socket: in daemon mode the client
                    # cannot see our stderr, so a bare EOF is indistinguishable
                    # from a crashed kernel.
                    from .protocol import error_response

                    write_jsonl(
                        stdout,
                        error_response(
                            None,
                            error_type=type(exc).__name__,
                            message=str(exc),
                            traceback="",
                            stdout="",
                            stderr="",
                        ),
                    )
        except Exception as exc:  # noqa: BLE001 - thread boundary contains and logs handler failures.
            print(f"ida-cli daemon: connection handler failed: {exc!r}", file=sys.stderr)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def _handle_control_message(self, line: str, stdout: TextIO) -> bool:
        """Answer an authenticated shutdown message; True ends the session.

        Runs on the connection thread and must never queue work onto the
        executor — a hung request would otherwise block shutdown forever.
        Anything that is not exactly a shutdown request returns False so the
        normal request path parses (and validates) the line as before.

        The match is deliberately exact — sole key, literal ``true``. The
        control channel shares the request line format, so a loose check
        would let an ordinary ``{"id":..,"code":..,"shutdown":true}`` request
        silently kill the daemon instead of running, and ``1 == True`` in
        Python would let a bare equality test accept ``{"shutdown": 1}``.
        """
        try:
            payload = json.loads(line)
        except ValueError:
            return False
        if not isinstance(payload, dict) or set(payload) != {"shutdown"}:
            return False
        if payload["shutdown"] is not True:
            return False
        from .protocol import write_jsonl

        # Shut down *before* acknowledging: the ack is a promise that
        # teardown has begun, and --shutdown starts its process-exit
        # deadline the moment it reads this line. Acking first leaves a
        # window where the caller polls a daemon that has not stopped yet.
        # Closing the listener does not disturb this accepted connection.
        self._initiate_shutdown()
        write_jsonl(stdout, {"ok": True, "shutdown": True})
        return True

    def _initiate_shutdown(self) -> None:
        """Stop request execution and close the listening socket.

        Registration files are deliberately left for the serving thread's
        shutdown(), which removes them under the ownership rule once
        serve_forever() has unwound the session.
        """
        self._runtime.stop()
        server = self._server
        self._server = None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass

    def _authorize(self, stdin: TextIO, stdout: TextIO, accepted_at: float | None = None) -> bool:
        """Require the first client line to carry the daemon auth token.

        The read is bounded in size and in total elapsed time, because
        neither bound exists anywhere else on this path: the 16 MiB request
        cap lives past authentication, and conn.settimeout is a per-recv
        timeout, so a peer that drips one byte per half-timeout could hold a
        pre-auth connection -- and its buffer -- indefinitely. Measured
        before this bound: 1 GiB streamed pre-auth grew daemon RSS by
        ~1.1 GiB at 432 MiB/s, per connection, with one thread each.

        Residual: a single readline can still span several recvs, so a
        dripping peer can stretch one handshake past auth_timeout; the
        elapsed check below rejects it afterwards, and the size bound caps
        what it can buffer meanwhile.
        """
        line = stdin.readline(_MAX_AUTH_LINE_CHARS + 1)
        if line == "":
            return False  # banner probe or peer vanished before presenting a token
        if len(line) > _MAX_AUTH_LINE_CHARS:
            print(
                f"ida-cli daemon: rejecting pre-auth line over {_MAX_AUTH_LINE_CHARS} chars",
                file=sys.stderr,
            )
            return False
        if accepted_at is not None and time.monotonic() - accepted_at >= self._timings.auth_timeout:
            print("ida-cli daemon: rejecting connection that outlived the auth budget", file=sys.stderr)
            return False
        try:
            payload = json.loads(line)
        except ValueError:
            payload = None
        token = payload.get("auth") if isinstance(payload, dict) else None
        if isinstance(token, str) and hmac.compare_digest(token, self._token):
            return True
        from .protocol import error_response, write_jsonl
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
        """Stop accepting and executing, close the socket, remove runtime files.

        Registration files are removed only when the PID file names this
        process; after a lost start() race they belong to the surviving
        daemon and must be left in place.
        """
        self._runtime.stop()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._owns_daemon_files():
            _cleanup_daemon_files(self._target_path)

    def _owns_daemon_files(self) -> bool:
        """Return whether this server created the registration files.

        Requires both a fully completed start() — a race loser may have
        written its own PID file before failing, and must still not clean
        up — and a PID file that names this process.
        """
        if not self._registration_written:
            return False
        try:
            return int(Path(self._pid_path).read_text(encoding="utf-8").strip()) == os.getpid()
        except (OSError, ValueError):
            return False  # unreadable or foreign files are never ours to delete


class DaemonClient:
    """Connect to a daemon and provide a JSONL transport."""

    def __init__(self, target_path: str, *, timings: DaemonTimings = DEFAULT_TIMINGS) -> None:
        self._target_path = target_path
        self._timings = timings
        self._addr: tuple[str, int] | None = None
        self._sock: socket.socket | None = None
        self._stdin: TextIO | None = None
        self._stdout: TextIO | None = None

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
                if time.monotonic() - started > self._timings.startup_timeout:
                    raise TimeoutError(
                        f"Daemon did not become available within {self._timings.startup_timeout}s "
                        f"for {self._target_path!r}"
                    ) from None
                time.sleep(self._timings.startup_poll_interval)
        self._sock.settimeout(self._timings.auth_timeout)  # bound the banner read
        self._stdin = self._sock.makefile(mode="w", encoding="utf-8", errors="replace")
        self._stdout = self._sock.makefile(mode="r", encoding="utf-8", errors="replace")
        self._read_banner()
        self._sock.settimeout(None)
        self.write(json.dumps({"auth": self._read_token()}) + "\n")

    def _read_banner(self) -> None:
        """Require the peer's first line to be the ida-cli daemon banner."""
        try:
            line = self.readline()
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
        """Close the client connection without shutting down the daemon.

        Every handle is released even if an earlier one refuses to close, so
        a half-torn-down client never leaks the socket.
        """
        for attribute in ("_stdin", "_stdout", "_sock"):
            handle = getattr(self, attribute)
            if handle is None:
                continue
            try:
                handle.close()
            except OSError:
                pass
            setattr(self, attribute, None)

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
    "DEFAULT_TIMINGS",
    "DaemonClient",
    "DaemonRunningError",
    "DaemonServer",
    "DaemonTimings",
    "get_pid_path",
    "get_port_path",
    "get_token_path",
    "is_daemon_running",
)
