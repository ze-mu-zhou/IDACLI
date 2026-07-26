"""Pure JSONL entry point for the AI-only IDA runtime."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .daemon import DaemonServer, is_daemon_running
from .kernel import create_session
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

_USAGE = """\
usage: ida-ai [--daemon] <target>
       ida-ai --shutdown <target>

AI-only IDA runtime: speaks JSONL on stdin/stdout, one request per line.
Humans should drive it through an agent skill (Kimi Code / Codex), not by hand.

arguments:
  <target>     path to a binary or an existing .i64 database

options:
  --daemon     run as a reusable background kernel for <target>
  --shutdown   gracefully stop the daemon serving <target> (SIGTERM)
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
        _tolerate_undecodable_stdin(input_stream)

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
        return _shutdown_daemon(args[1] if len(args) > 1 else None, output_stream)

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
    except Exception as exc:
        write_jsonl(output_stream, _startup_exception(exc))
        return 1

    try:
        if daemon_mode:
            return _serve_daemon(target, session)
        return _serve(session.runtime, input_stream, output_stream)
    finally:
        if not daemon_mode:
            session.close()


def _serve_daemon(target: str, session: object) -> int:
    """Run kernel as a daemon; SIGTERM takes the same graceful path as Ctrl+C."""
    server = DaemonServer(target, session.runtime)
    previous_sigterm: Any = None
    sigterm_installed = False
    try:
        previous_sigterm = signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
        sigterm_installed = True
    except (OSError, RuntimeError, ValueError):
        pass  # signal handlers only install on the main thread of the main interpreter
    try:
        server.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if sigterm_installed:
            signal.signal(signal.SIGTERM, previous_sigterm)
        server.shutdown()
        session.close()
    return 0


def _raise_keyboard_interrupt(signum: int, frame: object) -> None:
    """Translate SIGTERM into KeyboardInterrupt so graceful cleanup runs."""
    raise KeyboardInterrupt


def _shutdown_daemon(target: str | None, output_stream: TextIO) -> int:
    """Shut down a running daemon; remove its files only after it actually dies.

    Exit codes: 0 on confirmed shutdown (files removed), 2 for a missing
    target argument, 1 for NoDaemonError, an unreadable/garbage pid file
    (ValueError envelope), a failed kill (OSError envelope), or a daemon
    that survives SIGTERM (DaemonShutdownError envelope; files kept).
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

        handle = ctypes.windll.kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.wintypes.DWORD()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == _STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        os.waitpid(pid, os.WNOHANG)  # reap our own child so zombies count as dead
    except (AttributeError, ChildProcessError, OSError):
        return True  # not our child; the existence probe above already succeeded
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _tolerate_undecodable_stdin(stream: TextIO) -> None:
    """Replace undecodable stdin bytes so one bad byte cannot kill the loop."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return  # StringIO and similar test doubles cannot be reconfigured
    try:
        reconfigure(errors="replace")
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


def _serve(runtime: object, stdin: TextIO, stdout: TextIO) -> int:
    """Process JSONL requests until EOF; malformed or oversized lines get envelopes."""

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
