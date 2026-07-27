"""Agent-side bridge for driving one IDA-CLI JSONL kernel."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping, Sequence
from os import PathLike
from typing import IO, Any, Self

from .daemon import DaemonClient, is_daemon_running
from .protocol import encode_jsonl
from .wsl import find_ida_python, is_wsl, wsl_to_win

_CLOSE_TIMEOUT_SECONDS = 5
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0
_STDERR_TAIL_CHARS = 4096
_OMIT_ID = object()
_DAEMON_STARTUP_TIMEOUT = 15.0
_DAEMON_STDERR_TAIL_CHARS = 2048


class AgentBridgeError(RuntimeError):
    """Raised when an agent bridge cannot preserve the JSONL contract."""

    def __init__(self, message: str, *, response: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.response = None if response is None else dict(response)


class AgentBridgeTimeoutError(AgentBridgeError):
    """Raised when a kernel request does not produce a JSONL response in time."""


class AgentSession:
    """Own one long-lived kernel connection (subprocess or daemon)."""

    def __init__(
        self,
        process: subprocess.Popen[str] | None = None,
        stderr_file: IO[str] | None = None,
        *,
        request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
        daemon_client: DaemonClient | None = None,
        daemon_target: str | None = None,
    ) -> None:
        self._process = process
        self._stderr_file = stderr_file
        self._daemon_client = daemon_client
        # Only used to spell out the reconnect call in error messages; a
        # session built straight from a DaemonClient simply has no target.
        self._daemon_target = daemon_target
        self._daemon_poison: str | None = None
        self._request_timeout_s = _require_timeout("request_timeout_s", request_timeout_s)
        self._backend: dict[str, Any] | None = None
        self._stdout_lines: queue.Queue[str | None] = queue.Queue()
        self._stdout_thread: threading.Thread | None = None
        if process is not None:
            self._stdout_thread = _start_stdout_reader(self._require_stdout(), self._stdout_lines)

    @classmethod
    def start(
        cls,
        target_path: str | PathLike[str],
        command: Sequence[str] | None = None,
        *,
        request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
        probe_backend: bool = False,
        require_ida: bool = False,
        daemon: bool = False,
    ) -> AgentSession:
        """Launch one kernel and append the target path as the only runtime argument.

        In WSL, auto-detects Windows Python with idapro and converts WSL paths
        to Windows paths transparently. Set IDA_CLI_PYTHON to override detection.

        When daemon=True, spawns ida-ai --daemon and connects. Subsequent calls
        with daemon=True for the same target reuse the running daemon.
        """

        target = str(target_path)
        if command is None and is_wsl():
            command = (find_ida_python(), "-B", "-m", "ida_cli")
            target = wsl_to_win(target)

        if daemon:
            return cls._start_daemon(target, command, request_timeout_s=request_timeout_s,
                                     probe_backend=probe_backend, require_ida=require_ida)
        argv = tuple(command) if command is not None else (sys.executable, "-B", "-m", "ida_cli")
        if not argv:
            raise AgentBridgeError("agent bridge command must not be empty")
        stderr_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
        try:
            process = subprocess.Popen(
                (*argv, target),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception:
            stderr_file.close()
            raise
        session = cls(process, stderr_file, request_timeout_s=request_timeout_s)
        if probe_backend or require_ida:
            try:
                session.probe_backend(require_ida=require_ida)
            except Exception:
                session.close()
                raise
        return session

    @classmethod
    def connect(cls, target_path: str | PathLike[str], *, request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS) -> AgentSession:
        """Connect to an existing daemon without spawning a new kernel.

        DaemonClient answers a missing daemon, a bad banner, a missing token
        and a connect timeout with bare RuntimeError/TimeoutError. The bridge
        documents AgentBridgeError as the one thing callers must catch, so
        every daemon failure is translated here — see _daemon_transport_error.
        """
        target = str(target_path)
        client = DaemonClient(target)
        try:
            client.connect()
        except (OSError, RuntimeError) as exc:
            # connect() leaves the socket open when it gives up waiting for
            # the daemon, so release it before the client goes out of scope.
            client.close()
            raise _daemon_transport_error(f"could not connect to the daemon for {target!r}", exc) from exc
        return cls(None, None, request_timeout_s=request_timeout_s, daemon_client=client, daemon_target=target)

    @classmethod
    def _start_daemon(cls, target: str, command: Sequence[str] | None, *, request_timeout_s: float, probe_backend: bool, require_ida: bool) -> AgentSession:
        """Spawn ida-ai --daemon and connect, or connect to existing daemon."""
        import time as _time
        if is_daemon_running(target):
            session = cls.connect(target, request_timeout_s=request_timeout_s)
        else:
            argv = tuple(command) if command else (sys.executable, "-B", "-m", "ida_cli")
            # Daemon auto-detects WSL via WSLENV and uses /tmp/.ida-cli/
            # Keep the daemon's stderr so startup failures stay diagnosable.
            stderr_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
            try:
                subprocess.Popen(
                    (*argv, "--daemon", target),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr_file,
                )
            except Exception:
                stderr_file.close()
                raise
            deadline = _time.monotonic() + _DAEMON_STARTUP_TIMEOUT
            while not is_daemon_running(target):
                if _time.monotonic() > deadline:
                    tail = _stream_tail(stderr_file, _DAEMON_STDERR_TAIL_CHARS)
                    stderr_file.close()
                    raise AgentBridgeError(
                        f"Daemon did not start within {_DAEMON_STARTUP_TIMEOUT}s for {target!r}; "
                        f"daemon stderr tail: {tail!r}"
                    )
                _time.sleep(0.1)
            stderr_file.close()
            session = cls.connect(target, request_timeout_s=request_timeout_s)
        if probe_backend or require_ida:
            try:
                session.probe_backend(require_ida=require_ida)
            except Exception:
                session.close()
                raise
        return session

    @property
    def backend(self) -> dict[str, Any] | None:
        """Return cached backend metadata when `probe_backend()` has run."""

        return None if self._backend is None else dict(self._backend)

    def probe_backend(self, *, require_ida: bool = False) -> dict[str, Any]:
        """Fetch backend metadata once and optionally require a real IDA backend."""
        if self._backend is None:
            backend = self.result("__result__ = __backend__", request_id="probe.backend")
            if not isinstance(backend, Mapping):
                raise AgentBridgeError("backend probe did not return a metadata object")
            self._backend = dict(backend)
        if require_ida and self._backend.get("ida_available") is not True:
            raise AgentBridgeError(f"IDA backend required: {self._backend!r}")
        return dict(self._backend)

    def execute(self, code: str, request_id: Any = _OMIT_ID, *, timeout_s: float | None = None) -> dict[str, Any]:
        """Send one Python request and return the raw protocol response."""

        if not isinstance(code, str):
            raise AgentBridgeError("request code must be text")
        if self._daemon_poison is not None:
            # Fail before writing: a poisoned connection still accepts bytes
            # and the daemon would still execute them (see _poison_daemon).
            raise AgentBridgeError(self._daemon_poison)
        if self._process is not None and self._process.poll() is not None:
            raise AgentBridgeError(self._dead_process_message())
        request: dict[str, Any] = {"code": code}
        if request_id is not _OMIT_ID:
            request["id"] = request_id
        self._write_request(request)
        response = self._read_response(self._request_timeout_s if timeout_s is None else timeout_s)
        _validate_response_id(request, response)
        return response

    def result(self, code: str, request_id: Any = _OMIT_ID, *, timeout_s: float | None = None) -> Any:
        """Execute one request and return `result`, raising on protocol errors."""

        response = self.execute(code, request_id, timeout_s=timeout_s)
        if response.get("ok") is not True:
            raise AgentBridgeError(_response_error_message(response), response=response)
        return response.get("result")

    def close(self) -> None:
        """Close the connection (subprocess or daemon client)."""

        if self._daemon_client is not None:
            self._daemon_client.close()
            self._daemon_client = None
            return
        process = self._process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=_CLOSE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        _join_thread(self._stdout_thread)
        if self._stderr_file is not None:
            self._stderr_file.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def _write_request(self, request: Mapping[str, Any]) -> None:
        if self._daemon_client is not None:
            try:
                self._daemon_client.write(encode_jsonl(dict(request)))
            except (OSError, RuntimeError) as exc:
                # A half-written request line leaves the daemon parsing our
                # next request as the tail of this one, so the connection is
                # finished either way — poison it instead of retrying.
                self._poison_daemon(f"sending a request failed: {exc}")
                raise _daemon_transport_error("daemon request write failed", exc) from exc
            return
        if self._process is None or self._process.stdin is None:
            raise AgentBridgeError("agent bridge stdin pipe is unavailable")
        try:
            self._process.stdin.write(encode_jsonl(dict(request)))
            self._process.stdin.flush()
        except BrokenPipeError as exc:
            raise AgentBridgeError(self._dead_process_message()) from exc

    def _read_response(self, timeout_s: float) -> dict[str, Any]:
        if self._daemon_client is not None:
            effective = _require_timeout("timeout_s", timeout_s)
            try:
                line = self._read_daemon_line(effective)
            except TimeoutError as exc:
                self._poison_daemon(f"a response timed out after {effective:.3f}s")
                raise AgentBridgeTimeoutError(
                    f"daemon response timed out after {effective:.3f}s; {self._daemon_reconnect_hint()}"
                ) from exc
            except (OSError, RuntimeError) as exc:
                self._poison_daemon(f"reading a response failed: {exc}")
                raise _daemon_transport_error("daemon response read failed", exc) from exc
            if not line:
                self._poison_daemon("the daemon closed the connection")
                raise AgentBridgeError(
                    f"daemon connection closed unexpectedly; {self._daemon_reconnect_hint()}"
                )
            return self._parse_response(line)
        try:
            # Distinct name: the daemon branch above yields str, this queue
            # yields str | None with None meaning "reader hit EOF".
            queued = self._stdout_lines.get(timeout=_require_timeout("timeout_s", timeout_s))
        except queue.Empty as exc:
            if self._process is not None:
                self._process.kill()
                try:
                    self._process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            raise AgentBridgeTimeoutError(
                f"kernel response timed out after {timeout_s:.3f}s; stderr_tail={self._stderr_tail()!r}"
            ) from exc
        if queued is None:
            raise AgentBridgeError(self._dead_process_message())
        return self._parse_response(queued)

    def _read_daemon_line(self, timeout_s: float) -> str:
        """Read one daemon line under a read timeout, restoring blocking mode."""
        client = self._daemon_client
        if client is None:
            raise AgentBridgeError("daemon connection is unavailable")
        client.set_read_timeout(timeout_s)
        try:
            return client.readline()
        finally:
            # Restoring blocking mode must never mask the read's own failure:
            # a client closed underneath us answers with RuntimeError here,
            # which would replace the AgentBridgeTimeoutError the caller needs.
            try:
                client.set_read_timeout(None)
            except (OSError, RuntimeError):
                pass

    def _poison_daemon(self, reason: str) -> None:
        """Mark a daemon session unusable so no later request is ever sent.

        Why the session cannot simply carry on: CPython's SocketIO latches
        _timeout_occurred the first time a read times out, so every later
        readline() on that makefile raises a bare OSError — outside the
        AgentBridgeError hierarchy, so callers' `except AgentBridgeError`
        misses it — while _write_request still succeeds and the daemon still
        EXECUTES the code. A loop of ai.rename() calls then reports renames
        as failed that in fact landed in the database.

        Why not rebuild the makefile and resynchronise: the timed-out
        response is still in flight, and requests sent without an id make
        _validate_response_id a no-op, so that stale answer would silently be
        handed to the *next* request. A loud dead session beats a quiet
        desync; the caller reconnects with AgentSession.connect().

        The first reason wins — it is the root cause the caller must see —
        and the socket is deliberately left open: the flag already stops
        every further byte, and close()/__exit__ still releases it.
        """
        if self._daemon_poison is None:
            self._daemon_poison = f"daemon session is unusable ({reason}); {self._daemon_reconnect_hint()}"

    def _daemon_reconnect_hint(self) -> str:
        """Say why nothing more will be sent and exactly how to get a live session."""
        target = "<target path>" if self._daemon_target is None else repr(self._daemon_target)
        return (
            "this session sends nothing further because the daemon may still be "
            f"executing that request; reconnect with AgentSession.connect({target})"
        )

    def _parse_response(self, line: str) -> dict[str, Any]:
        try:
            response = json.loads(line, object_pairs_hook=_object_without_duplicate_keys, parse_constant=_reject_json_constant)
        except ValueError as exc:
            raise AgentBridgeError(f"kernel emitted invalid JSON protocol output: {exc}") from exc
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise AgentBridgeError("kernel response is not a protocol object")
        return response

    def _require_stdout(self) -> IO[str]:
        process = self._process
        if process is None:
            raise AgentBridgeError("agent bridge subprocess is unavailable")
        stdout = process.stdout
        if stdout is None:
            raise AgentBridgeError("agent bridge stdout pipe is unavailable")
        return stdout

    def _dead_process_message(self) -> str:
        if self._process is None:
            return "kernel daemon connection lost"
        return f"kernel process exited with code {self._process.poll()}; stderr_tail={self._stderr_tail()!r}"

    def _stderr_tail(self) -> str:
        if self._stderr_file is None:
            return "(daemon mode — no stderr)"
        return _stream_tail(self._stderr_file, _STDERR_TAIL_CHARS)


def _daemon_transport_error(message: str, exc: BaseException) -> AgentBridgeError:
    """Map one daemon transport failure onto the documented bridge hierarchy.

    daemon.py answers transport problems with bare RuntimeError, TimeoutError
    and OSError, none of which a caller's `except AgentBridgeError` catches,
    so every DaemonClient call an AgentSession makes is translated here. A
    TimeoutError keeps its timeout identity so "the daemon was too slow"
    stays distinguishable from "the transport broke".
    """
    if isinstance(exc, AgentBridgeError):
        return exc  # already in the hierarchy; re-wrapping would drop .response
    error_type = AgentBridgeTimeoutError if isinstance(exc, TimeoutError) else AgentBridgeError
    return error_type(f"{message}: {type(exc).__name__}: {exc}")


def _stream_tail(stream: IO[str], max_chars: int) -> str:
    """Return the last max_chars of a seekable text stream."""
    stream.flush()
    end = stream.tell()
    stream.seek(max(0, end - max_chars))
    tail = stream.read()
    stream.seek(end)
    return tail


def _response_error_message(response: Mapping[str, Any]) -> str:
    error = response.get("error")
    if not isinstance(error, Mapping):
        return "kernel request failed without a structured error"
    error_type = error.get("type", "Error")
    message = error.get("message", "")
    return f"{error_type}: {message}"


def _start_stdout_reader(stream: IO[str], output: queue.Queue[str | None]) -> threading.Thread:
    thread = threading.Thread(target=_read_stdout_lines, args=(stream, output), daemon=True)
    thread.start()
    return thread


def _read_stdout_lines(stream: IO[str], output: queue.Queue[str | None]) -> None:
    try:
        for line in stream:
            output.put(line)
    finally:
        output.put(None)


def _join_thread(thread: threading.Thread | None) -> None:
    if thread is not None and thread.is_alive():
        thread.join(timeout=1.0)


def _validate_response_id(request: Mapping[str, Any], response: Mapping[str, Any]) -> None:
    # Startup/out-of-band errors have no request id — surface the real error
    if "id" in request and "id" not in response and response.get("ok") is False:
        raise AgentBridgeError(_response_error_message(response), response=dict(response))
    if "id" in request and response.get("id") != request["id"]:
        raise AgentBridgeError("kernel response id does not match request id")
    if "id" not in request and "id" in response:
        raise AgentBridgeError("kernel response included an unexpected id")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError(f"duplicate JSON object key: {key}")
        decoded[key] = value
    return decoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _require_timeout(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise TypeError(f"{name} must be a positive number")
    timeout = float(value)
    if timeout <= 0:
        raise ValueError(f"{name} must be positive")
    return timeout


__all__ = ("AgentBridgeError", "AgentBridgeTimeoutError", "AgentSession")
