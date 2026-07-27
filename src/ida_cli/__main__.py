"""Pure JSONL entry point for the AI-only IDA runtime."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Protocol, TextIO

from . import __version__
from . import runtime as runtime_mod
from .daemon import DaemonRunningError, DaemonServer, is_daemon_running
from .kernel import KernelSession, create_session
from .protocol import (
    BadJsonError,
    RequestFormatError,
    bad_json_response,
    error_response,
    parse_request,
    write_jsonl,
)

_MAX_REQUEST_LINE_CHARS = 16 * 1024 * 1024  # 16 MiB per-line cap for _serve
_SHUTDOWN_TIMEOUT = 5.0  # seconds to wait for a SIGTERMed daemon to die
_SHUTDOWN_POLL_INTERVAL = 0.05  # seconds between process-exit polls
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # Win32 OpenProcess access right
_STILL_ACTIVE = 259  # Win32 exit code for a process that has not exited
# Executor of the currently serving daemon; the signal handler stops it so a
# SIGTERM delivered while a request runs still unwinds the serve loop.
_ACTIVE_EXECUTOR: Any | None = None

class _RequestExecutor(Protocol):
    """The one method _serve needs: the kernel runtime and the daemon
    executor both satisfy it, and neither is importable as a common base."""

    def execute_request(self, request: Any) -> dict[str, Any]:
        """Execute one decoded protocol request and return its envelope."""


_USAGE = """\
usage: ida-ai [--daemon] <target>
       ida-ai --shutdown [--force] <target>

AI-only IDA runtime: speaks JSONL on stdin/stdout, one request per line.
Humans should drive it through an agent skill (Kimi Code / Codex), not by hand.

arguments:
  <target>     path to a binary or an existing .i64 database

options:
  --daemon     run as a reusable background kernel for <target>
  --shutdown   gracefully stop the daemon serving <target>
  --force      with --shutdown: kill a daemon that ignores the shutdown
               protocol, even on Windows where that skips the IDA database
               unload (last resort for a wedged native IDA call)
  -h, --help   print this help and exit
  --version    print the installed ida-cli version and exit

docs: https://github.com/ze-mu-zhou/IDACLI (README.md, docs/AI_INSTALL.md)
"""


def main(argv: list[str] | None = None, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run `ida-ai [--daemon] target` as a long-lived JSONL Python kernel."""
    args = list(sys.argv[1:] if argv is None else argv)
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = _guarded_protocol_stdout() if stdout is None else stdout
    if stdin is None:
        _pin_request_stdin_codec(input_stream)

    if args and args[0] in ("-h", "--help"):
        output_stream.write(_USAGE)  # plain text for humans; not a JSONL envelope
        return 0
    if args and args[0] == "--version":
        output_stream.write(f"ida-ai {__version__}\n")
        return 0

    daemon_mode = False
    if args and args[0] == "--daemon":
        daemon_mode = True
        args.pop(0)
    if args and args[0] == "--shutdown":
        rest = args[1:]
        force = "--force" in rest
        targets = [item for item in rest if item != "--force"]
        return _shutdown_daemon(targets[0] if targets else None, output_stream, force=force)

    if len(args) != 1:
        write_jsonl(
            output_stream,
            _startup_error("CLIArgumentError", "expected exactly one target path (or --daemon target)"),
        )
        return 2

    target = args[0]

    if daemon_mode and is_daemon_running(target):
        write_jsonl(
            output_stream,
            _startup_error("DaemonRunningError", f"Daemon already running for {target!r}"),
        )
        return 1

    try:
        session = create_session(target)
    except KeyboardInterrupt:
        return 130  # Ctrl+C during IDA load: exit quietly, no traceback
    except Exception as exc:
        write_jsonl(output_stream, _startup_exception(exc))
        return 1

    try:
        if daemon_mode:
            return _serve_daemon(target, session)
        return _serve_stdio(session, input_stream, output_stream)
    except DaemonRunningError as exc:
        # start() lost the O_EXCL race after the CLI-level is_daemon_running
        # check; the winner owns the target, so report instead of crashing.
        write_jsonl(output_stream, _startup_error("DaemonRunningError", str(exc)))
        return 1
    finally:
        if not daemon_mode:
            session.close()


def _serve_daemon(target: str, session: KernelSession) -> int:
    """Run kernel as a daemon; SIGTERM takes the same graceful path as Ctrl+C."""
    global _ACTIVE_EXECUTOR
    server = DaemonServer(target, session.runtime)
    previous_sigterm: Any = None
    sigterm_installed = False
    try:
        previous_sigterm = signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
        sigterm_installed = True
    except (OSError, RuntimeError, ValueError):
        pass  # signal handlers only install on the main thread of the main interpreter
    runtime_mod._SIGNAL_INTERRUPT.clear()  # never inherit a stale flag
    try:
        # getattr tolerates DaemonServer doubles that carry no executor.
        _ACTIVE_EXECUTOR = getattr(server, "_runtime", None)
        try:
            server.start()
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            _ACTIVE_EXECUTOR = None
    finally:
        if sigterm_installed:
            signal.signal(signal.SIGTERM, previous_sigterm)
        runtime_mod._SIGNAL_INTERRUPT.clear()  # keep one-shot state out of later runs
        server.shutdown()
        session.close()
    return 0


def _serve_stdio(session: KernelSession, stdin: TextIO, stdout: TextIO) -> int:
    """Run the stdio JSONL loop; Ctrl+C escapes the runtime's error envelope.

    Without the SIGINT handler below, a KeyboardInterrupt raised inside
    executed code would be wrapped into an error envelope and the loop would
    keep serving, making the kernel unkillable from the keyboard. With the
    flag set, the runtime re-raises the KI and it is caught here for a clean
    exit without a traceback.
    """
    previous_sigint: Any = None
    sigint_installed = False
    try:
        previous_sigint = signal.signal(signal.SIGINT, _raise_keyboard_interrupt)
        sigint_installed = True
    except (OSError, RuntimeError, ValueError):
        pass  # not the main thread (embedded/tests); default handling applies
    runtime_mod._SIGNAL_INTERRUPT.clear()
    try:
        return _serve(session.runtime, stdin, stdout)
    except KeyboardInterrupt:
        return 0
    finally:
        if sigint_installed:
            signal.signal(signal.SIGINT, previous_sigint)
        runtime_mod._SIGNAL_INTERRUPT.clear()


def _raise_keyboard_interrupt(signum: int, frame: object) -> None:
    """Translate a process signal into a graceful kernel shutdown.

    Sets the signal-interrupt flag so the runtime lets this KeyboardInterrupt
    escape the error envelope, stops the daemon executor so the serve loop
    unwinds even when raised mid-request, then raises the KI itself.
    """
    runtime_mod._SIGNAL_INTERRUPT.set()
    executor = _ACTIVE_EXECUTOR
    if executor is not None:
        executor.stop()
    raise KeyboardInterrupt


def _is_windows() -> bool:
    """Return whether this host is Windows.

    A seam so tests can select the branch without touching ``os.name``:
    pathlib binds its PosixPath/WindowsPath platform guard at import time
    (``class PosixPath: if os.name == 'nt': def __new__(...): raise``), so a
    patched ``os.name`` makes every Path operation raise UnsupportedOperation
    on one platform or the other.
    """
    return os.name == "nt"


def _shutdown_daemon(target: str | None, output_stream: TextIO, *, force: bool = False) -> int:
    """Shut down a running daemon; remove its files only after it actually dies.

    The graceful path is the daemon's shutdown control message (port + token
    from the registration files), which lets the daemon close its IDA
    session itself. Only when that protocol fails does POSIX fall back to
    SIGTERM; Windows does not hard-kill by default, because there SIGTERM
    *is* TerminateProcess and would skip session.close() and the IDA
    database unload — the survivor would keep the license and a corrupt
    database. ``force=True`` (``--shutdown --force``) accepts that damage so
    an operator always has an escape hatch for a daemon wedged inside an
    uninterruptible native IDA call.

    Exit codes: 0 on confirmed shutdown (files removed), 2 for a missing
    target argument, 1 for NoDaemonError, an unreadable/garbage pid file
    (ValueError envelope), a failed kill (OSError envelope), or a daemon
    that will not die (DaemonShutdownError envelope; files kept).
    """
    from .daemon import _cleanup_daemon_files, get_pid_path

    if target is None:
        write_jsonl(
            output_stream,
            _startup_error("CLIArgumentError", "--shutdown requires a target path"),
        )
        return 2
    pid_path = Path(get_pid_path(target))
    if not pid_path.is_file():
        write_jsonl(
            output_stream,
            _startup_error("NoDaemonError", f"No daemon running for {target!r}"),
        )
        return 1
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        write_jsonl(output_stream, _startup_exception(exc))
        return 1
    if not is_daemon_running(target):
        write_jsonl(
            output_stream,
            _startup_error("NoDaemonError", f"No daemon running for {target!r}"),
        )
        return 1
    if _request_protocol_shutdown(target):
        if not _wait_for_process_exit(pid):
            write_jsonl(
                output_stream,
                _startup_error(
                    "DaemonShutdownError",
                    f"daemon PID {pid} acknowledged shutdown but is still alive; keeping daemon files",
                ),
            )
            return 1
        _cleanup_daemon_files(target)
        write_jsonl(output_stream, {"ok": True, "message": f"Daemon PID {pid} shut down gracefully"})
        return 0
    if _is_windows() and not force:
        write_jsonl(
            output_stream,
            _startup_error(
                "DaemonShutdownError",
                f"daemon PID {pid} did not answer the shutdown protocol; "
                "refusing to force-kill on Windows (SIGTERM there is TerminateProcess "
                "and skips the IDA database unload). Rerun with --force to kill anyway",
            ),
        )
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        write_jsonl(output_stream, _startup_exception(exc))
        return 1
    if not _wait_for_process_exit(pid):
        write_jsonl(
            output_stream,
            _startup_error(
                "DaemonShutdownError",
                f"daemon PID {pid} is still alive after SIGTERM; keeping daemon files",
            ),
        )
        return 1
    _cleanup_daemon_files(target)
    write_jsonl(output_stream, {"ok": True, "message": f"Sent SIGTERM to daemon PID {pid}"})
    return 0


def _request_protocol_shutdown(target: str) -> bool:
    """Ask the daemon to shut itself down via the authenticated control message.

    Returns True only on an explicit {"ok": true, "shutdown": true}
    acknowledgement; every transport or protocol failure returns False so
    the caller can pick the platform fallback.
    """
    from .daemon import DaemonClient  # noqa: PLC0415

    client = DaemonClient(target)
    try:
        client.connect()
        client.set_read_timeout(_SHUTDOWN_TIMEOUT)
        client.write('{"shutdown": true}\n')
        payload = json.loads(client.readline())
    except Exception:
        return False  # connection, timeout, EOF, or garbage — no ack received
    finally:
        client.close()
    return isinstance(payload, dict) and payload.get("ok") is True and payload.get("shutdown") is True


def _wait_for_process_exit(pid: int) -> bool:
    """Poll until the PID dies, reporting False if it outlives the timeout."""
    deadline = time.monotonic() + _SHUTDOWN_TIMEOUT
    while True:
        if not _pid_alive(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(_SHUTDOWN_POLL_INTERVAL)


def _pid_alive(pid: int) -> bool:
    """Return whether the PID refers to a live process on this platform."""
    if os.name == "nt":
        # os.kill(pid, 0) is not a probe on Windows (it calls TerminateProcess),
        # and a terminated process still answers OpenProcess while any handle
        # to it remains open — check the exit code instead.
        import ctypes
        import ctypes.wintypes

        kernel32 = getattr(ctypes, "windll").kernel32
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == _STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        os.waitpid(pid, getattr(os, "WNOHANG", 0))  # reap our own child so zombies count as dead
    except (AttributeError, ChildProcessError, OSError):
        return True  # not our child; the existence probe above already succeeded
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _pin_request_stdin_codec(stream: TextIO) -> None:
    """Decode requests as UTF-8, replacing bytes that are not.

    The wire is UTF-8 in every direction: encode_jsonl emits it, the agent
    bridge writes it, the daemon transport pins it on both makefiles, and
    the protocol stdout below opens it. Only this stdio path was left to the
    host locale, so on a non-UTF-8 codepage (cp936, cp1252, ...) requests
    decoded into *different, valid* characters and the kernel answered
    ok=true with silently rewritten text -- a comment or rename would land
    in the database as mojibake, and mutations.py's read-back check compares
    against the already-corrupted value, so it passes.

    errors="replace" is kept so one undecodable byte still cannot kill the
    serve loop.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return  # StringIO and similar test doubles cannot be reconfigured
    try:
        reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        pass


def _guarded_protocol_stdout() -> TextIO:
    """Reserve the inherited stdout for JSONL and reroute fd 1 to stderr.

    IDA plugins and idalib write banners straight to file descriptor 1 (for
    example Keypatch prints on database open). When modifying this, keep
    protocol JSONL on the saved descriptor so every fd-1 write — C level or
    Python level — lands on stderr instead of corrupting the protocol stream.
    """
    try:
        protocol_fd = os.dup(1)
    except OSError:
        return sys.stdout  # stdout already redirected or closed; serve as-is
    try:
        os.dup2(2, 1)
    except OSError:
        os.close(protocol_fd)
        return sys.stdout
    return os.fdopen(protocol_fd, "w", encoding="utf-8", errors="replace", newline="\n")


def _serve(
    runtime: _RequestExecutor,
    stdin: TextIO,
    stdout: TextIO,
    *,
    control_handler: Any | None = None,
) -> int:
    """Process JSONL requests until EOF; malformed or oversized lines get envelopes.

    control_handler (daemon mode only) inspects each well-sized line before
    request parsing; returning True means the line was a control message —
    the handler owns its response — and ends the serve loop. Stdio mode
    passes no handler, so control messages stay ordinary format errors.
    """

    while True:
        line, oversized = _read_request_line(stdin, _MAX_REQUEST_LINE_CHARS)
        if line is None:
            break
        started_ns = time.perf_counter_ns()
        if oversized:
            write_jsonl(
                stdout,
                _startup_error(
                    "RequestFormatError",
                    "request line exceeds the 16 MiB size limit "
                    f"({_MAX_REQUEST_LINE_CHARS} bytes)",
                    elapsed_ms=_elapsed_ms(started_ns),
                ),
            )
            continue
        if line.strip() == "":
            continue
        if control_handler is not None and control_handler(line, stdout):
            break
        try:
            request = parse_request(line)
        except BadJsonError as exc:
            write_jsonl(stdout, bad_json_response(exc, elapsed_ms=_elapsed_ms(started_ns)))
            continue
        except RequestFormatError as exc:
            envelope = _startup_error(type(exc).__name__, str(exc), elapsed_ms=_elapsed_ms(started_ns))
            if exc.has_id:
                envelope["id"] = exc.request_id
            write_jsonl(stdout, envelope)
            continue
        response = runtime.execute_request(request)
        write_jsonl(stdout, response)
    return 0


def _read_request_line(stream: TextIO, limit: int) -> tuple[str | None, bool]:
    """Read one line bounded by limit; drain and flag lines exceeding it."""
    chunk = stream.readline(limit + 1)
    if chunk == "":
        return None, False
    if len(chunk) <= limit or chunk.endswith("\n"):
        return chunk, False
    while True:  # drain the remainder of the oversized line
        remainder = stream.readline(limit + 1)
        if remainder == "" or remainder.endswith("\n"):
            break
    return "", True


def _startup_exception(exc: BaseException) -> dict[str, object]:
    """Convert startup failures into protocol JSON instead of human logs."""
    return _startup_error(type(exc).__name__, str(exc))


def _startup_error(error_type: str, message: str, *, elapsed_ms: int = 0) -> dict[str, object]:
    """Build a request-less error envelope for CLI or backend startup failures."""
    return error_response(
        None,
        error_type=error_type,
        message=message,
        traceback="",
        stdout="",
        stderr="",
        elapsed_ms=elapsed_ms,
    )


def _elapsed_ms(started_ns: int) -> int:
    """Measure protocol parse latency in milliseconds."""
    return (time.perf_counter_ns() - started_ns) // 1_000_000


if __name__ == "__main__":
    raise SystemExit(main())
