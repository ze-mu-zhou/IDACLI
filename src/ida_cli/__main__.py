"""Pure JSONL entry point for the AI-only IDA runtime."""

from __future__ import annotations

import os
import sys
import time
from typing import TextIO

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


def main(argv: list[str] | None = None, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run `ida-ai [--daemon] target` as a long-lived JSONL Python kernel."""
    args = list(sys.argv[1:] if argv is None else argv)
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout

    daemon_mode = False
    if args and args[0] == "--daemon":
        daemon_mode = True
        args.pop(0)
    if args and args[0] == "--shutdown":
        _shutdown_daemon(args[1] if len(args) > 1 else None, output_stream)
        return 0

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
    """Run kernel as a daemon, accepting client connections on a Unix socket."""
    server = DaemonServer(target, session.runtime)
    try:
        server.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        session.close()
    return 0


def _shutdown_daemon(target: str | None, output_stream: TextIO) -> None:
    """Shut down a running daemon and clean up its files."""
    from .daemon import _cleanup_daemon_files, get_pid_path

    if target is None:
        write_jsonl(
            output_stream,
            _startup_error("CLIArgumentError", "--shutdown requires a target path"),
        )
        return
    if not is_daemon_running(target):
        write_jsonl(
            output_stream,
            _startup_error("NoDaemonError", f"No daemon running for {target!r}"),
        )
        return
    try:
        pid = int(open(get_pid_path(target)).read().strip())
        os.kill(pid, 15)  # SIGTERM
        write_jsonl(output_stream, {"ok": True, "message": f"Sent SIGTERM to daemon PID {pid}"})
    except OSError as exc:
        write_jsonl(output_stream, _startup_exception(exc))
    finally:
        _cleanup_daemon_files(target)

def _serve(runtime: object, stdin: TextIO, stdout: TextIO) -> int:
    """Process JSONL requests until EOF, skipping malformed lines."""

    for line in stdin:
        if line.strip() == "":
            continue
        started_ns = time.perf_counter_ns()
        try:
            request = parse_request(line)
        except BadJsonError as exc:
            write_jsonl(stdout, bad_json_response(exc, elapsed_ms=_elapsed_ms(started_ns)))
            continue
        except RequestFormatError as exc:
            write_jsonl(
                stdout,
                _startup_error(type(exc).__name__, str(exc), elapsed_ms=_elapsed_ms(started_ns)),
            )
            continue
        response = runtime.execute_request(request)
        write_jsonl(stdout, response)
    return 0


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
