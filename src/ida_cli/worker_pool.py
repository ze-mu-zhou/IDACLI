"""IDA-free local worker-pool primitives for multi-kernel fanout."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import json
from time import perf_counter_ns
import traceback as traceback_module
from typing import Any

_STATUS_IDLE = "idle"
_STATUS_RUNNING = "running"
_RESULT_OK = "ok"
_RESULT_ERROR = "error"
_RESULT_CRASH = "crash"


def _require_text(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not allow_empty and value == "":
        raise ValueError(f"{name} must not be empty")
    return value


def _require_int(name: str, value: Any, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _reject_non_json_dict_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON-compatible dictionaries must use string keys")
            _reject_non_json_dict_keys(child)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _reject_non_json_dict_keys(child)


def json_compatible_value(value: Any) -> Any:
    """Return a normalized JSON value; callers must not substitute on failure."""
    _reject_non_json_dict_keys(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise TypeError("value must be JSON-compatible") from exc
    return json.loads(encoded)


def canonical_json(value: Any) -> str:
    """Return deterministic compact JSON for IDs, hashes, and test fixtures."""
    return json.dumps(
        json_compatible_value(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _string_tuple(name: str, values: Iterable[Any]) -> tuple[str, ...]:
    if isinstance(values, (bytes, str)):
        raise TypeError(f"{name} must be an iterable of strings")
    items = tuple(values)
    for item in items:
        _require_text(name, item, allow_empty=True)
    return items


def _env_tuple(values: Iterable[tuple[Any, Any]] | Mapping[Any, Any]) -> tuple[tuple[str, str], ...]:
    entries = values.items() if isinstance(values, Mapping) else values
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, value in entries:
        env_key = _require_text("env key", key)
        env_value = _require_text("env value", value, allow_empty=True)
        if env_key in seen:
            raise ValueError(f"duplicate env key: {env_key}")
        seen.add(env_key)
        normalized.append((env_key, env_value))
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    """Immutable launch/open contract for one isolated IDA worker kernel."""

    worker_id: str
    index: int
    target_path: str
    database_path: str
    role: str = "read"
    argv: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "index", _require_int("index", self.index, minimum=0))
        object.__setattr__(self, "target_path", _require_text("target_path", self.target_path))
        object.__setattr__(self, "database_path", _require_text("database_path", self.database_path))
        object.__setattr__(self, "role", _require_text("role", self.role))
        object.__setattr__(self, "argv", _string_tuple("argv", self.argv))
        object.__setattr__(self, "env", _env_tuple(self.env))

    @classmethod
    def create(
        cls,
        *,
        index: int,
        target_path: str,
        database_path: str | None = None,
        role: str = "read",
        worker_prefix: str = "worker",
        argv: Iterable[str] = (),
        env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
    ) -> "WorkerSpec":
        worker_index = _require_int("index", index, minimum=0)
        prefix = _require_text("worker_prefix", worker_prefix)
        target = _require_text("target_path", target_path)
        database = target if database_path is None else _require_text("database_path", database_path)
        return cls(
            worker_id=f"{prefix}-{worker_index:03d}",
            index=worker_index,
            target_path=target,
            database_path=database,
            role=role,
            argv=_string_tuple("argv", argv),
            env=_env_tuple(env),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "index": self.index,
            "target_path": self.target_path,
            "database_path": self.database_path,
            "role": self.role,
            "argv": list(self.argv),
            "env": dict(self.env),
        }


@dataclass(frozen=True, slots=True)
class WorkerError:
    """Structured Python exception report for one worker shard."""

    worker_id: str
    shard_id: str
    error_type: str
    message: str
    traceback: str

    @classmethod
    def from_exception(cls, worker_id: str, shard_id: str, exc: Exception) -> "WorkerError":
        return cls(
            worker_id=worker_id,
            shard_id=shard_id,
            error_type=type(exc).__name__,
            message=str(exc),
            traceback="".join(traceback_module.format_exception(type(exc), exc, exc.__traceback__)),
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "worker_id": self.worker_id,
            "shard_id": self.shard_id,
            "type": self.error_type,
            "message": self.message,
            "traceback": self.traceback,
        }


@dataclass(frozen=True, slots=True)
class WorkerCrash:
    """Structured process-crash report for one worker shard."""

    worker_id: str
    shard_id: str
    returncode: int
    message: str
    stderr_tail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "shard_id", _require_text("shard_id", self.shard_id))
        object.__setattr__(self, "returncode", _require_int("returncode", self.returncode))
        object.__setattr__(self, "message", _require_text("message", self.message))
        object.__setattr__(self, "stderr_tail", _require_text("stderr_tail", self.stderr_tail, allow_empty=True))

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "shard_id": self.shard_id,
            "type": "WorkerCrash",
            "message": self.message,
            "returncode": self.returncode,
            "stderr_tail": self.stderr_tail,
        }


class WorkerProcessCrash(RuntimeError):
    """Exception adapter used by local tests or future subprocess runners."""

    def __init__(self, returncode: int, message: str, stderr_tail: str = "") -> None:
        self.returncode = _require_int("returncode", returncode)
        self.message = _require_text("message", message)
        self.stderr_tail = _require_text("stderr_tail", stderr_tail, allow_empty=True)
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class WorkerResult:
    """JSON-compatible fanout result for one worker shard."""

    worker_id: str
    shard_id: str
    ok: bool
    status: str
    item_count: int
    elapsed_ms: int
    result: Any = None
    error: WorkerError | None = None
    crash: WorkerCrash | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "shard_id", _require_text("shard_id", self.shard_id))
        if type(self.ok) is not bool:
            raise TypeError("ok must be a boolean")
        if self.status not in {_RESULT_OK, _RESULT_ERROR, _RESULT_CRASH}:
            raise ValueError("status must be ok, error, or crash")
        object.__setattr__(self, "item_count", _require_int("item_count", self.item_count, minimum=0))
        object.__setattr__(self, "elapsed_ms", _require_int("elapsed_ms", self.elapsed_ms, minimum=0))
        if self.status == _RESULT_OK:
            if not self.ok or self.error is not None or self.crash is not None:
                raise ValueError("ok results cannot contain error or crash reports")
            object.__setattr__(self, "result", json_compatible_value(self.result))
        elif self.status == _RESULT_ERROR:
            if self.ok or not isinstance(self.error, WorkerError) or self.crash is not None:
                raise ValueError("error results must contain exactly one WorkerError")
        elif self.ok or not isinstance(self.crash, WorkerCrash) or self.error is not None:
            raise ValueError("crash results must contain exactly one WorkerCrash")

    @classmethod
    def success(
        cls,
        *,
        worker_id: str,
        shard_id: str,
        item_count: int,
        elapsed_ms: int,
        result: Any,
    ) -> "WorkerResult":
        return cls(worker_id, shard_id, True, _RESULT_OK, item_count, elapsed_ms, result=result)

    @classmethod
    def from_error(
        cls,
        *,
        worker_id: str,
        shard_id: str,
        item_count: int,
        elapsed_ms: int,
        error: WorkerError,
    ) -> "WorkerResult":
        return cls(worker_id, shard_id, False, _RESULT_ERROR, item_count, elapsed_ms, error=error)

    @classmethod
    def from_crash(
        cls,
        *,
        worker_id: str,
        shard_id: str,
        item_count: int,
        elapsed_ms: int,
        crash: WorkerCrash,
    ) -> "WorkerResult":
        return cls(worker_id, shard_id, False, _RESULT_CRASH, item_count, elapsed_ms, crash=crash)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "worker_id": self.worker_id,
            "shard_id": self.shard_id,
            "ok": self.ok,
            "status": self.status,
            "item_count": self.item_count,
            "elapsed_ms": self.elapsed_ms,
        }
        if self.status == _RESULT_OK:
            payload["result"] = self.result
        elif self.status == _RESULT_ERROR and self.error is not None:
            payload["error"] = self.error.as_dict()
        elif self.crash is not None:
            payload["crash"] = self.crash.as_dict()
        return payload


@dataclass(frozen=True, slots=True)
class FanoutResult:
    """Aggregate metadata for a local fanout run."""

    ok: bool
    worker_count: int
    shard_count: int
    item_count: int
    success_count: int
    error_count: int
    crash_count: int
    elapsed_ms: int
    results: tuple[WorkerResult, ...]

    @classmethod
    def from_results(
        cls,
        *,
        worker_count: int,
        results: Iterable[WorkerResult],
        elapsed_ms: int,
    ) -> "FanoutResult":
        records = tuple(results)
        errors = sum(1 for record in records if record.status == _RESULT_ERROR)
        crashes = sum(1 for record in records if record.status == _RESULT_CRASH)
        successes = sum(1 for record in records if record.status == _RESULT_OK)
        return cls(
            ok=errors == 0 and crashes == 0,
            worker_count=_require_int("worker_count", worker_count, minimum=0),
            shard_count=len(records),
            item_count=sum(record.item_count for record in records),
            success_count=successes,
            error_count=errors,
            crash_count=crashes,
            elapsed_ms=_require_int("elapsed_ms", elapsed_ms, minimum=0),
            results=records,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "worker_count": self.worker_count,
            "shard_count": self.shard_count,
            "item_count": self.item_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "crash_count": self.crash_count,
            "elapsed_ms": self.elapsed_ms,
            "results": [result.as_dict() for result in self.results],
        }


@dataclass(frozen=True, slots=True)
class WorkerState:
    """Current local scheduler state for one worker slot."""

    worker_id: str
    index: int
    state: str
    active_shard_id: str | None
    completed_shards: int
    failed_shards: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "index": self.index,
            "state": self.state,
            "active_shard_id": self.active_shard_id,
            "completed_shards": self.completed_shards,
            "failed_shards": self.failed_shards,
        }


@dataclass(frozen=True, slots=True)
class _PoolShard:
    shard_id: str
    worker_id: str
    items: tuple[Any, ...]


def _coerce_shard(shard: Any) -> _PoolShard:
    if isinstance(shard, Mapping):
        shard_id = shard.get("shard_id")
        worker_id = shard.get("worker_id")
        items = shard.get("items")
    else:
        shard_id = getattr(shard, "shard_id")
        worker_id = getattr(shard, "worker_id")
        items = getattr(shard, "items")
    if isinstance(items, (bytes, str)):
        raise TypeError("shard items must be an iterable of JSON-compatible values")
    return _PoolShard(
        shard_id=_require_text("shard_id", shard_id),
        worker_id=_require_text("worker_id", worker_id),
        items=tuple(json_compatible_value(item) for item in items),
    )


def _elapsed_ms_since(start_ns: int) -> int:
    return max(0, (perf_counter_ns() - start_ns) // 1_000_000)


class LocalWorkerPool:
    """Deterministic local scheduler facade; it does not import or launch IDA."""

    def __init__(self, worker_specs: Iterable[WorkerSpec]) -> None:
        specs = tuple(worker_specs)
        if not specs:
            raise ValueError("worker_specs must not be empty")
        ids: set[str] = set()
        indexes: set[int] = set()
        for spec in specs:
            if not isinstance(spec, WorkerSpec):
                raise TypeError("worker_specs must contain WorkerSpec instances")
            if spec.worker_id in ids:
                raise ValueError(f"duplicate worker_id: {spec.worker_id}")
            if spec.index in indexes:
                raise ValueError(f"duplicate worker index: {spec.index}")
            ids.add(spec.worker_id)
            indexes.add(spec.index)
        self._specs = specs
        self._by_id = {spec.worker_id: spec for spec in specs}
        self._active = {spec.worker_id: None for spec in specs}
        self._completed = {spec.worker_id: 0 for spec in specs}
        self._failed = {spec.worker_id: 0 for spec in specs}

    @property
    def worker_specs(self) -> tuple[WorkerSpec, ...]:
        return self._specs

    def states(self) -> tuple[WorkerState, ...]:
        return tuple(
            WorkerState(
                worker_id=spec.worker_id,
                index=spec.index,
                state=_STATUS_RUNNING if self._active[spec.worker_id] is not None else _STATUS_IDLE,
                active_shard_id=self._active[spec.worker_id],
                completed_shards=self._completed[spec.worker_id],
                failed_shards=self._failed[spec.worker_id],
            )
            for spec in self._specs
        )

    def fanout(
        self,
        shards: Iterable[Any],
        task: Callable[[WorkerSpec, tuple[Any, ...]], Any],
    ) -> FanoutResult:
        if not callable(task):
            raise TypeError("task must be callable")
        shard_records = tuple(_coerce_shard(shard) for shard in shards)
        fanout_start = perf_counter_ns()
        results: list[WorkerResult] = []
        for shard in shard_records:
            spec = self._by_id.get(shard.worker_id)
            if spec is None:
                raise ValueError(f"unknown worker_id: {shard.worker_id}")
            self._active[spec.worker_id] = shard.shard_id
            shard_start = perf_counter_ns()
            try:
                payload = task(spec, shard.items)
                record = WorkerResult.success(
                    worker_id=spec.worker_id,
                    shard_id=shard.shard_id,
                    item_count=len(shard.items),
                    elapsed_ms=_elapsed_ms_since(shard_start),
                    result=payload,
                )
                self._completed[spec.worker_id] += 1
            except WorkerProcessCrash as exc:
                crash = WorkerCrash(spec.worker_id, shard.shard_id, exc.returncode, exc.message, exc.stderr_tail)
                record = WorkerResult.from_crash(
                    worker_id=spec.worker_id,
                    shard_id=shard.shard_id,
                    item_count=len(shard.items),
                    elapsed_ms=_elapsed_ms_since(shard_start),
                    crash=crash,
                )
                self._failed[spec.worker_id] += 1
            except Exception as exc:
                error = WorkerError.from_exception(spec.worker_id, shard.shard_id, exc)
                record = WorkerResult.from_error(
                    worker_id=spec.worker_id,
                    shard_id=shard.shard_id,
                    item_count=len(shard.items),
                    elapsed_ms=_elapsed_ms_since(shard_start),
                    error=error,
                )
                self._failed[spec.worker_id] += 1
            finally:
                self._active[spec.worker_id] = None
            results.append(record)
        return FanoutResult.from_results(
            worker_count=len(self._specs),
            results=results,
            elapsed_ms=_elapsed_ms_since(fanout_start),
        )


__all__ = (
    "FanoutResult",
    "LocalWorkerPool",
    "WorkerCrash",
    "WorkerError",
    "WorkerProcessCrash",
    "WorkerResult",
    "WorkerSpec",
    "WorkerState",
    "canonical_json",
    "json_compatible_value",
)
