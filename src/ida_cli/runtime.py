"""Unrestricted Python execution runtime for one persistent kernel."""

from __future__ import annotations

import contextlib
import io
import json
import math
import reprlib
import time
import traceback
from collections.abc import Mapping
from types import TracebackType
from typing import Any

REQUEST_FILENAME = "<ida-cli-request>"


class RuntimeRequestError(ValueError):
    """Raised when a runtime request lacks executable Python source."""


class RuntimeAiHelper:
    """Minimal helper placeholder; keep raw Python and future helpers unrestricted."""


class PythonRuntime:
    """Execute AI-provided Python in one persistent global namespace."""

    def __init__(
        self,
        *,
        initial_globals: Mapping[str, Any] | None = None,
        ai: Any | None = None,
        database_path: str | None = None,
        run_dir: str | None = None,
    ) -> None:
        """Create persistent globals; when changing names here, preserve raw imports."""
        self.globals: dict[str, Any] = {
            "__builtins__": __builtins__,
            "ai": RuntimeAiHelper() if ai is None else ai,
            "__database_path__": database_path,
            "__run_dir__": run_dir,
        }
        if initial_globals is not None:
            self.globals.update(initial_globals)

    def execute(
        self,
        code: str,
        *,
        request_id: Any | None = None,
        has_request_id: bool | None = None,
        bindings: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run one unrestricted request; when editing this, keep capture process-local."""
        include_id = request_id is not None if has_request_id is None else has_request_id
        if not isinstance(code, str):
            return self._error_response(
                request_id,
                include_id,
                RuntimeRequestError("request code must be a string"),
                "",
                "",
                0,
            )

        stdout = io.StringIO()
        stderr = io.StringIO()
        start_ns = time.perf_counter_ns()
        try:
            request_bindings = _request_bindings(bindings)
            compiled = compile(code, REQUEST_FILENAME, "exec")
            self.globals.pop("__result__", None)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with _RequestBindings(self.globals, request_bindings):
                    exec(compiled, self.globals, self.globals)
        except Exception as exc:
            elapsed_ms = _elapsed_ms(start_ns)
            return self._error_response(
                request_id,
                include_id,
                exc,
                stdout.getvalue(),
                stderr.getvalue(),
                elapsed_ms,
            )

        try:
            result = prepare_result(self.globals.get("__result__"))
        except Exception as exc:
            elapsed_ms = _elapsed_ms(start_ns)
            return self._error_response(
                request_id,
                include_id,
                exc,
                stdout.getvalue(),
                stderr.getvalue(),
                elapsed_ms,
            )

        elapsed_ms = _elapsed_ms(start_ns)
        response: dict[str, Any] = {
            "ok": True,
            "result": result,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "elapsed_ms": elapsed_ms,
        }
        if include_id:
            response["id"] = request_id
        return response

    def execute_request(self, request: Mapping[str, Any] | Any) -> dict[str, Any]:
        """Run a protocol-shaped mapping; when protocol.py grows, keep IDs identical."""
        if hasattr(request, "code") and hasattr(request, "request_id") and hasattr(request, "has_id"):
            return self.execute(
                request.code,
                request_id=request.request_id,
                has_request_id=bool(request.has_id),
                bindings=getattr(request, "bindings", {}),
            )
        request_id = request.get("id")
        return self.execute(
            request.get("code"),
            request_id=request_id,
            has_request_id="id" in request,
            bindings=request.get("bindings"),
        )

    @staticmethod
    def _error_response(
        request_id: Any | None,
        include_id: bool,
        exc: BaseException,
        stdout: str,
        stderr: str,
        elapsed_ms: int,
    ) -> dict[str, Any]:
        """Build one structured failure envelope; when extending, keep JSON strict."""
        response: dict[str, Any] = {
            "ok": False,
            "error": exception_data(exc),
            "stdout": stdout,
            "stderr": stderr,
            "elapsed_ms": elapsed_ms,
        }
        if include_id:
            response["id"] = request_id
        return response


class _RequestBindings:
    """Inject request-scoped globals without leaking them into later requests."""

    def __init__(self, runtime_globals: dict[str, Any], bindings: Mapping[str, Any]) -> None:
        self._runtime_globals = runtime_globals
        self._bindings = bindings
        self._previous: dict[str, Any] = {}
        self._missing: set[str] = set()

    def __enter__(self) -> "_RequestBindings":
        for name, value in self._bindings.items():
            if name in self._runtime_globals:
                self._previous[name] = self._runtime_globals[name]
            else:
                self._missing.add(name)
            self._runtime_globals[name] = value
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        for name, value in self._previous.items():
            self._runtime_globals[name] = value
        for name in self._missing:
            self._runtime_globals.pop(name, None)


def prepare_result(value: Any) -> Any:
    """Return a strict JSON-compatible value; tagged metadata marks conversions."""
    prepared = _prepare_json_value(value, set())
    json.dumps(prepared, allow_nan=False, separators=(",", ":"))
    return prepared


def exception_data(exc: BaseException) -> dict[str, Any]:
    """Convert exceptions for protocol responses; when editing, preserve traceback text."""
    exc_type = type(exc)
    return {
        "type": exc_type.__name__,
        "module": exc_type.__module__,
        "message": str(exc),
        "traceback": "".join(traceback.format_exception(exc_type, exc, exc.__traceback__)),
        "frames": _traceback_frames(exc.__traceback__),
    }


def _prepare_json_value(value: Any, active: set[int]) -> Any:
    """Prepare one value recursively; when modifying, avoid lossy untagged coercion."""
    if value is None or isinstance(value, bool | str | int):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return {"__type__": "float", "value": repr(value)}
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        return {"__type__": "bytes", "length": len(raw), "encoding": "hex", "data": raw.hex()}

    value_id = id(value)
    if isinstance(value, list | tuple | set | frozenset | dict):
        if value_id in active:
            return {"__type__": "cycle", "python_type": _python_type(value)}
        active.add(value_id)
        try:
            if isinstance(value, dict):
                return _prepare_dict(value, active)
            if isinstance(value, set | frozenset):
                return _prepare_set(value, active)
            return [_prepare_json_value(item, active) for item in value]
        finally:
            active.remove(value_id)

    return {"__type__": "repr", "python_type": _python_type(value), "repr": _safe_repr(value)}


def _prepare_dict(value: Mapping[Any, Any], active: set[int]) -> Any:
    """Prepare mappings; when keys are not strings, preserve key values explicitly."""
    if all(isinstance(key, str) for key in value):
        return {key: _prepare_json_value(item, active) for key, item in value.items()}
    return {
        "__type__": "dict",
        "items": [
            [_prepare_json_value(key, active), _prepare_json_value(item, active)]
            for key, item in value.items()
        ],
    }


def _prepare_set(value: set[Any] | frozenset[Any], active: set[int]) -> dict[str, Any]:
    """Prepare unordered sets deterministically; when changing, keep stable ordering."""
    items = [_prepare_json_value(item, active) for item in value]
    items.sort(key=_json_sort_key)
    return {"__type__": type(value).__name__, "items": items}


def _json_sort_key(value: Any) -> str:
    """Sort prepared values by canonical JSON; when editing, keep allow_nan disabled."""
    return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _traceback_frames(tb: TracebackType | None) -> list[dict[str, Any]]:
    """Return traceback frames as data; when extending, keep file and line fields stable."""
    return [
        {"filename": frame.filename, "lineno": frame.lineno, "name": frame.name, "line": frame.line}
        for frame in traceback.extract_tb(tb)
    ]


def _python_type(value: Any) -> str:
    """Name Python values for tagged metadata; when changing, keep module-qualified form."""
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _safe_repr(value: Any) -> str:
    """Bound object repr output; when changing, avoid executing user code twice."""
    try:
        return reprlib.Repr().repr(value)
    except Exception as exc:
        return f"<repr failed: {_python_type(exc)}: {exc}>"


def _elapsed_ms(start_ns: int) -> int:
    """Measure request latency; when changing, keep response units in milliseconds."""
    return (time.perf_counter_ns() - start_ns) // 1_000_000


def _request_bindings(bindings: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """Validate optional request-scoped globals without widening the protocol."""
    if bindings is None:
        return {}
    if not isinstance(bindings, Mapping):
        raise RuntimeRequestError("request bindings must be a mapping")
    normalized: dict[str, Any] = {}
    for name, value in bindings.items():
        if not isinstance(name, str):
            raise RuntimeRequestError("request binding names must be strings")
        normalized[name] = value
    return normalized


__all__ = (
    "PythonRuntime",
    "RuntimeAiHelper",
    "RuntimeRequestError",
    "exception_data",
    "prepare_result",
)
