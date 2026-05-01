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
from typing import Any, TextIO

from .daemon import DaemonClient, is_daemon_running
from .protocol import encode_jsonl
from .wsl import find_ida_python, is_wsl, wsl_to_win

_CLOSE_TIMEOUT_SECONDS = 5
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0
_STDERR_TAIL_CHARS = 4096
_OMIT_ID = object()
_DAEMON_STARTUP_TIMEOUT = 15.0


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
        stderr_file: TextIO | None = None,
        *,
        request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
        daemon_client: DaemonClient | None = None,
    ) -> None:
        self._process = process
        self._stderr_file = stderr_file
        self._daemon_client = daemon_client
        self._request_timeout_s = _require_timeout("request_timeout_s", request_timeout_s)
        self._backend: dict[str, Any] | None = None
        self._stdout_lines: queue.Queue[str | None] = queue.Queue()
        if process is not None:
            self._stdout_thread = _start_stdout_reader(self._require_stdout(), self._stdout_lines)
        else:
            self._stdout_thread = None

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
    ) -> "AgentSession":
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
    def connect(cls, target_path: str | PathLike[str], *, request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS) -> "AgentSession":
        """Connect to an existing daemon without spawning a new kernel."""
        target = str(target_path)
        client = DaemonClient(target)
        client.connect()
        session = cls(None, None, request_timeout_s=request_timeout_s, daemon_client=client)
        return session

    @classmethod
    def _start_daemon(cls, target: str, command: Sequence[str] | None, *, request_timeout_s: float, probe_backend: bool, require_ida: bool) -> "AgentSession":
        """Spawn ida-ai --daemon and connect, or connect to existing daemon."""
        import time as _time
        if is_daemon_running(target):
            session = cls.connect(target, request_timeout_s=request_timeout_s)
        else:
            argv = tuple(command) if command else (sys.executable, "-B", "-m", "ida_cli")
            # On WSL, tell daemon to use /tmp/ so both sides find the same files
            env = None
            if is_wsl():
                import os as _os
                env = dict(_os.environ)
                env["IDA_CLI_DAEMON_DIR"] = "/tmp/.ida-cli/daemons"
            subprocess.Popen(
                (*argv, "--daemon", target),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env,
            )
            deadline = _time.monotonic() + _DAEMON_STARTUP_TIMEOUT
            while not is_daemon_running(target):
                if _time.monotonic() > deadline:
                    raise AgentBridgeError(f"Daemon did not start within {_DAEMON_STARTUP_TIMEOUT}s for {target!r}")
                _time.sleep(0.1)
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
        self._stderr_file.close()

    def __enter__(self) -> "AgentSession":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def _write_request(self, request: Mapping[str, Any]) -> None:
        if self._daemon_client is not None:
            self._daemon_client.write(encode_jsonl(dict(request)))
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
            line = self._daemon_client.readline()
            if not line:
                raise AgentBridgeError("daemon connection closed unexpectedly")
            return self._parse_response(line)
        try:
            line = self._stdout_lines.get(timeout=_require_timeout("timeout_s", timeout_s))
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
        if line is None:
            raise AgentBridgeError(self._dead_process_message())
        return self._parse_response(line)

    def _parse_response(self, line: str) -> dict[str, Any]:
        try:
            response = json.loads(line, object_pairs_hook=_object_without_duplicate_keys, parse_constant=_reject_json_constant)
        except ValueError as exc:
            raise AgentBridgeError(f"kernel emitted invalid JSON protocol output: {exc}") from exc
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise AgentBridgeError("kernel response is not a protocol object")
        return response

    def _require_stdout(self) -> TextIO:
        stdout = self._process.stdout
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
        self._stderr_file.flush()
        end = self._stderr_file.tell()
        self._stderr_file.seek(max(0, end - _STDERR_TAIL_CHARS))
        tail = self._stderr_file.read()
        self._stderr_file.seek(end)
        return tail


def _response_error_message(response: Mapping[str, Any]) -> str:
    error = response.get("error")
    if not isinstance(error, Mapping):
        return "kernel request failed without a structured error"
    error_type = error.get("type", "Error")
    message = error.get("message", "")
    return f"{error_type}: {message}"


def _start_stdout_reader(stream: TextIO, output: queue.Queue[str | None]) -> threading.Thread:
    thread = threading.Thread(target=_read_stdout_lines, args=(stream, output), daemon=True)
    thread.start()
    return thread


def _read_stdout_lines(stream: TextIO, output: queue.Queue[str | None]) -> None:
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
