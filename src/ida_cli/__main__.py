"""Pure JSONL entry point for the AI-only IDA runtime."""

from __future__ import annotations

import sys
import time
from typing import TextIO

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
    """Run `ida-ai target` as a long-lived JSONL Python kernel."""
    args = list(sys.argv[1:] if argv is None else argv)
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    if len(args) != 1:
        write_jsonl(
            output_stream,
            _startup_error("CLIArgumentError", "expected exactly one target path"),
        )
        return 2
    try:
        session = create_session(args[0])
    except Exception as exc:
        write_jsonl(output_stream, _startup_exception(exc))
        return 1

    try:
        return _serve(session.runtime, input_stream, output_stream)
    finally:
        session.close()


def _serve(runtime: object, stdin: TextIO, stdout: TextIO) -> int:
    """Process JSONL requests until EOF or a fail-fast protocol error."""
    for line in stdin:
        if line.strip() == "":
            continue
        started_ns = time.perf_counter_ns()
        try:
            request = parse_request(line)
        except BadJsonError as exc:
            write_jsonl(stdout, bad_json_response(exc, elapsed_ms=_elapsed_ms(started_ns)))
            return 1
        except RequestFormatError as exc:
            write_jsonl(
                stdout,
                _startup_error(type(exc).__name__, str(exc), elapsed_ms=_elapsed_ms(started_ns)),
            )
            return 1
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
