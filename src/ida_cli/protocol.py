"""Deterministic JSONL protocol primitives for the AI-only runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional, TextIO, Tuple

JsonObject = Dict[str, Any]

__all__ = (
    "BadJsonError",
    "ProtocolRequest",
    "RequestFormatError",
    "bad_json_response",
    "encode_jsonl",
    "error_response",
    "parse_request",
    "success_response",
    "write_jsonl",
)


class BadJsonError(ValueError):
    """Report malformed JSONL input. When modifying this, obey fail-fast parse handling."""

    def __init__(self, message: str, line: int, column: int, position: int) -> None:
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column
        self.position = position


class RequestFormatError(ValueError):
    """Report decoded requests with invalid protocol shape. When changing this, obey the ida-cli skill."""


class _DuplicateKeyError(ValueError):
    """Reject ambiguous JSON objects. When modifying this, obey deterministic request decoding."""

    def __init__(self, key: str) -> None:
        super().__init__(f"duplicate JSON object key: {key}")
        self.key = key


@dataclass(frozen=True)
class ProtocolRequest:
    """Decoded Python execution request. When using this, preserve id passthrough exactly."""

    code: str
    request_id: Any = None
    has_id: bool = False
    bindings: JsonObject = field(default_factory=dict)


def parse_request(line: str) -> ProtocolRequest:
    """Decode one JSONL request. When modifying this, obey strict JSON and request validation."""
    if not isinstance(line, str):
        raise TypeError("request line must be text")

    try:
        payload = json.loads(
            line,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda constant: _reject_json_constant(line, constant),
        )
    except json.JSONDecodeError as exc:
        raise BadJsonError(exc.msg, exc.lineno, exc.colno, exc.pos) from exc
    except _DuplicateKeyError as exc:
        raise BadJsonError(str(exc), 1, 1, 0) from exc

    if not isinstance(payload, dict):
        raise RequestFormatError("request must be a JSON object")
    if "code" not in payload:
        raise RequestFormatError("request missing required field: code")

    code = payload["code"]
    if not isinstance(code, str):
        raise RequestFormatError("request field code must be a string")
    bindings = payload.get("bindings", {})
    if not isinstance(bindings, dict):
        raise RequestFormatError("request field bindings must be a JSON object")

    return ProtocolRequest(code=code, request_id=payload.get("id"), has_id="id" in payload, bindings=bindings)


def success_response(
    request: ProtocolRequest,
    *,
    result: Any = None,
    stdout: str = "",
    stderr: str = "",
    elapsed_ms: int = 0,
) -> JsonObject:
    """Build a success envelope. When using this, keep stdout/stderr captured as fields only."""
    envelope = _base_response(request, stdout=stdout, stderr=stderr, elapsed_ms=elapsed_ms)
    envelope["ok"] = True
    envelope["result"] = result
    return envelope


def error_response(
    request: Optional[ProtocolRequest],
    *,
    error_type: str,
    message: str,
    traceback: str = "",
    stdout: str = "",
    stderr: str = "",
    elapsed_ms: int = 0,
) -> JsonObject:
    """Build an error envelope. When using this, report the failure instead of retrying silently."""
    envelope = _base_response(request, stdout=stdout, stderr=stderr, elapsed_ms=elapsed_ms)
    envelope["ok"] = False
    envelope["error"] = {
        "message": _require_text("message", message),
        "traceback": _require_text("traceback", traceback),
        "type": _require_text("error_type", error_type),
    }
    return envelope


def bad_json_response(error: BadJsonError, *, elapsed_ms: int = 0) -> JsonObject:
    """Build a bad-JSON envelope. When using this, emit it once and let the caller fail fast."""
    envelope = error_response(
        None,
        error_type="JSONDecodeError",
        message=error.message,
        traceback="",
        elapsed_ms=elapsed_ms,
    )
    envelope["error"]["column"] = error.column
    envelope["error"]["line"] = error.line
    envelope["error"]["position"] = error.position
    return envelope


def encode_jsonl(message: JsonObject) -> str:
    """Serialize one protocol line. When modifying this, preserve compact sorted-key JSON."""
    if not isinstance(message, dict):
        raise TypeError("protocol message must be a JSON object")
    raw = json.dumps(
        message,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    # json.dumps guarantees single-line output, but Windows Python
    # can inject \r in text-mode pipes; strip defensively.
    return raw.replace("\r", "") + "\n"


def write_jsonl(stream: TextIO, message: JsonObject) -> None:
    """Write one protocol line. When using this, never mix human logs into the same stream."""
    stream.write(encode_jsonl(message))
    stream.flush()


def _base_response(
    request: Optional[ProtocolRequest],
    *,
    stdout: str,
    stderr: str,
    elapsed_ms: int,
) -> JsonObject:
    """Create shared envelope fields. When modifying this, keep id omitted unless present."""
    envelope: JsonObject = {
        "elapsed_ms": _require_elapsed_ms(elapsed_ms),
        "stderr": _require_text("stderr", stderr),
        "stdout": _require_text("stdout", stdout),
    }
    if request is not None and request.has_id:
        envelope["id"] = request.request_id
    return envelope


def _object_without_duplicate_keys(pairs: Iterable[Tuple[str, Any]]) -> JsonObject:
    """Decode JSON objects without ambiguity. When modifying this, reject duplicate keys."""
    decoded: JsonObject = {}
    for key, value in pairs:
        if key in decoded:
            raise _DuplicateKeyError(key)
        decoded[key] = value
    return decoded


def _reject_json_constant(source: str, constant: str) -> None:
    """Reject non-standard JSON constants. When modifying this, keep JSON parsing strict."""
    position = source.find(constant)
    safe_position = max(position, 0)
    line, column = _line_column(source, safe_position)
    raise BadJsonError(f"invalid JSON constant: {constant}", line, column, safe_position)


def _line_column(source: str, position: int) -> Tuple[int, int]:
    """Map a byte-like character offset to line and column. When modifying this, keep it bounded."""
    bounded_position = min(max(position, 0), len(source))
    prefix = source[:bounded_position]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    if last_newline < 0:
        return line, bounded_position + 1
    return line, bounded_position - last_newline


def _require_elapsed_ms(value: int) -> int:
    """Validate elapsed milliseconds. When modifying this, keep bools out of numeric fields."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError("elapsed_ms must be a non-negative integer")
    return value


def _require_text(name: str, value: str) -> str:
    """Validate protocol text fields. When modifying this, keep captured streams textual."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    return value
