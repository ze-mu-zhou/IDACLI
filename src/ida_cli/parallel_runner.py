"""Local subprocess execution primitives for isolated IDA worker kernels."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, TextIO

from .protocol import encode_jsonl
from .supervisor import FanoutPlan, WorkShard
from .worker_pool import (
    FanoutResult,
    WorkerCrash,
    WorkerError,
    WorkerProcessCrash,
    WorkerResult,
    WorkerSpec,
    canonical_json,
    json_compatible_value,
)

SNAPSHOT_COPY = "copy"
WORKER_TIMEOUT_RETURN_CODE = -1
_DEFAULT_TIMEOUT_S = 30.0
_MAX_STDERR_TAIL = 8192


class WorkerProtocolError(RuntimeError):
    """Report malformed worker JSONL; when modifying this, preserve fail-fast behavior."""


class WorkerTimeoutError(TimeoutError):
    """Report a request timeout; when using this, kill the owning process."""

    def __init__(self, worker_id: str, timeout_s: float) -> None:
        self.worker_id = _require_text("worker_id", worker_id)
        self.timeout_s = _require_timeout("timeout_s", timeout_s)
        super().__init__(f"worker {self.worker_id} timed out after {self.timeout_s:.3f}s")


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotPlan:
    """One deterministic database copy plan for an isolated worker."""

    worker_id: str
    index: int
    source_path: str
    snapshot_path: str
    mode: str = SNAPSHOT_COPY

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "index", _require_int("index", self.index, minimum=0))
        object.__setattr__(self, "source_path", _require_text("source_path", self.source_path))
        object.__setattr__(self, "snapshot_path", _require_text("snapshot_path", self.snapshot_path))
        if self.mode != SNAPSHOT_COPY:
            raise ValueError(f"unsupported database snapshot mode: {self.mode}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "index": self.index,
            "source_path": self.source_path,
            "snapshot_path": self.snapshot_path,
            "mode": self.mode,
        }


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotManifest:
    """Metadata for database copies prepared before worker launch."""

    snapshot_count: int
    byte_count: int
    snapshots: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "snapshot_count": self.snapshot_count,
            "byte_count": self.byte_count,
            "snapshots": list(self.snapshots),
        }


@dataclass(frozen=True, slots=True)
class WorkerLaunchPlan:
    """Subprocess command and environment for one worker kernel."""

    worker_id: str
    index: int
    database_path: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    cwd: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "index", _require_int("index", self.index, minimum=0))
        object.__setattr__(self, "database_path", _require_text("database_path", self.database_path))
        object.__setattr__(self, "argv", _string_tuple("argv", self.argv))
        if not self.argv:
            raise ValueError("argv must not be empty")
        object.__setattr__(self, "env", _env_tuple(self.env))
        if self.cwd is not None:
            object.__setattr__(self, "cwd", _require_text("cwd", self.cwd))

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "index": self.index,
            "database_path": self.database_path,
            "argv": list(self.argv),
            "env": dict(self.env),
            "cwd": self.cwd,
        }


@dataclass(frozen=True, slots=True)
class WorkerTimeoutRecord:
    """Structured timeout evidence that can be aggregated as a worker crash."""

    worker_id: str
    shard_id: str
    timeout_ms: int
    stderr_tail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "shard_id", _require_text("shard_id", self.shard_id))
        object.__setattr__(self, "timeout_ms", _require_int("timeout_ms", self.timeout_ms, minimum=1))
        object.__setattr__(self, "stderr_tail", _require_text("stderr_tail", self.stderr_tail, allow_empty=True))

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "shard_id": self.shard_id,
            "type": "WorkerTimeout",
            "message": self.message,
            "timeout_ms": self.timeout_ms,
            "stderr_tail": self.stderr_tail,
        }

    @property
    def message(self) -> str:
        return f"worker timed out after {self.timeout_ms}ms"

    def as_crash(self) -> WorkerCrash:
        return WorkerCrash(
            self.worker_id,
            self.shard_id,
            WORKER_TIMEOUT_RETURN_CODE,
            self.message,
            self.stderr_tail,
        )


class JsonlWorkerProcess:
    """Own one subprocess worker and exchange strict JSONL protocol messages."""

    def __init__(self, launch_plan: WorkerLaunchPlan, *, stderr_tail_chars: int = _MAX_STDERR_TAIL) -> None:
        if not isinstance(launch_plan, WorkerLaunchPlan):
            raise TypeError("launch_plan must be a WorkerLaunchPlan")
        self._launch_plan = launch_plan
        self._stderr_tail = _TextTail(stderr_tail_chars)
        self._stdout_lines: queue.Queue[str | None] = queue.Queue()
        self._process: subprocess.Popen[str] | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    @property
    def launch_plan(self) -> WorkerLaunchPlan:
        return self._launch_plan

    def start(self) -> "JsonlWorkerProcess":
        if self._process is not None:
            raise RuntimeError("worker process is already started")
        env = os.environ.copy()
        env.update(dict(self._launch_plan.env))
        self._process = subprocess.Popen(
            self._launch_plan.argv,
            cwd=self._launch_plan.cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._stdout_thread = _start_stdout_reader(self._require_stdout(), self._stdout_lines)
        self._stderr_thread = _start_stderr_reader(self._require_stderr(), self._stderr_tail)
        return self

    def request(self, request: Mapping[str, Any], *, timeout_s: float = _DEFAULT_TIMEOUT_S) -> dict[str, Any]:
        payload = _request_payload(request)
        line = encode_jsonl(payload)
        process = self._require_process()
        stdin = self._require_stdin()
        try:
            stdin.write(line)
            stdin.flush()
        except OSError as exc:
            raise self._process_crash("worker stdin write failed") from exc
        response = parse_worker_response(self._read_response_line(process, _require_timeout("timeout_s", timeout_s)))
        _validate_response_id(payload, response)
        return response

    def stderr_tail(self) -> str:
        return self._stderr_tail.value()

    def kill(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=1.0)

    def close(self, *, timeout_s: float = 1.0) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            try:
                process.wait(timeout=_require_timeout("timeout_s", timeout_s))
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)
        _close_stream(process.stdout)
        _close_stream(process.stderr)
        _join_thread(self._stdout_thread)
        _join_thread(self._stderr_thread)

    def __enter__(self) -> "JsonlWorkerProcess":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _read_response_line(self, process: subprocess.Popen[str], timeout_s: float) -> str:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.kill()
                raise WorkerTimeoutError(self._launch_plan.worker_id, timeout_s)
            try:
                line = self._stdout_lines.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if process.poll() is not None:
                    raise self._process_crash("worker exited before response")
                continue
            if line is None:
                if process.poll() is None:
                    continue
                raise self._process_crash("worker closed stdout before response")
            return line

    def _process_crash(self, message: str) -> WorkerProcessCrash:
        process = self._require_process()
        returncode = process.poll()
        return WorkerProcessCrash(
            WORKER_TIMEOUT_RETURN_CODE if returncode is None else returncode,
            message,
            self.stderr_tail(),
        )

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None:
            raise RuntimeError("worker process is not started")
        return self._process

    def _require_stdin(self) -> TextIO:
        stdin = self._require_process().stdin
        if stdin is None:
            raise RuntimeError("worker stdin is unavailable")
        return stdin

    def _require_stdout(self) -> TextIO:
        stdout = self._require_process().stdout
        if stdout is None:
            raise RuntimeError("worker stdout is unavailable")
        return stdout

    def _require_stderr(self) -> TextIO:
        stderr = self._require_process().stderr
        if stderr is None:
            raise RuntimeError("worker stderr is unavailable")
        return stderr


class LocalParallelRunner:
    """Run one fanout plan through real local subprocess workers."""

    def __init__(self, launch_plans: Iterable[WorkerLaunchPlan], *, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        plans = tuple(launch_plans)
        if not plans:
            raise ValueError("launch_plans must not be empty")
        ids: set[str] = set()
        for plan in plans:
            if not isinstance(plan, WorkerLaunchPlan):
                raise TypeError("launch_plans must contain WorkerLaunchPlan instances")
            if plan.worker_id in ids:
                raise ValueError(f"duplicate worker_id: {plan.worker_id}")
            ids.add(plan.worker_id)
        self._launch_plans = plans
        self._launch_by_worker = {plan.worker_id: plan for plan in plans}
        self._timeout_s = _require_timeout("timeout_s", timeout_s)

    def run(self, plan: FanoutPlan, code: str, *, timeout_s: float | None = None) -> FanoutResult:
        if not isinstance(plan, FanoutPlan):
            raise TypeError("plan must be a FanoutPlan")
        code_text = _require_text("code", code, allow_empty=True)
        selected_timeout = self._timeout_s if timeout_s is None else _require_timeout("timeout_s", timeout_s)
        specs = {spec.worker_id: spec for spec in plan.worker_specs}
        for shard in plan.shards:
            if shard.worker_id not in self._launch_by_worker:
                raise ValueError(f"missing launch plan for worker_id: {shard.worker_id}")
        records: list[WorkerResult | None] = [None for _ in plan.shards]
        started_ns = time.perf_counter_ns()
        threads = tuple(
            threading.Thread(
                target=self._run_one_shard,
                args=(index, specs[shard.worker_id], shard, code_text, selected_timeout, records),
                daemon=False,
            )
            for index, shard in enumerate(plan.shards)
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return FanoutResult.from_results(
            worker_count=plan.worker_count,
            results=tuple(_require_record(record) for record in records),
            elapsed_ms=_elapsed_ms_since(started_ns),
        )

    def _run_one_shard(
        self,
        index: int,
        spec: WorkerSpec,
        shard: WorkShard,
        code: str,
        timeout_s: float,
        records: list[WorkerResult | None],
    ) -> None:
        launch = self._launch_by_worker.get(shard.worker_id)
        if launch is None:
            raise ValueError(f"missing launch plan for worker_id: {shard.worker_id}")
        started_ns = time.perf_counter_ns()
        worker = JsonlWorkerProcess(launch)
        try:
            worker.start()
            request = build_worker_request(shard=shard, code=code)
            response = worker.request(request, timeout_s=timeout_s)
            records[index] = worker_response_to_result(
                spec=spec,
                shard=shard,
                response=response,
                elapsed_ms=_elapsed_ms_since(started_ns),
            )
        except WorkerTimeoutError:
            timeout = WorkerTimeoutRecord(
                spec.worker_id,
                shard.shard_id,
                max(1, int(timeout_s * 1000)),
                worker.stderr_tail(),
            )
            records[index] = WorkerResult.from_crash(
                worker_id=spec.worker_id,
                shard_id=shard.shard_id,
                item_count=shard.item_count,
                elapsed_ms=_elapsed_ms_since(started_ns),
                crash=timeout.as_crash(),
            )
        except WorkerProcessCrash as exc:
            records[index] = WorkerResult.from_crash(
                worker_id=spec.worker_id,
                shard_id=shard.shard_id,
                item_count=shard.item_count,
                elapsed_ms=_elapsed_ms_since(started_ns),
                crash=WorkerCrash(spec.worker_id, shard.shard_id, exc.returncode, exc.message, exc.stderr_tail),
            )
        except Exception as exc:
            records[index] = WorkerResult.from_error(
                worker_id=spec.worker_id,
                shard_id=shard.shard_id,
                item_count=shard.item_count,
                elapsed_ms=_elapsed_ms_since(started_ns),
                error=WorkerError.from_exception(spec.worker_id, shard.shard_id, exc),
            )
        finally:
            worker.close()


def plan_database_snapshots(
    *,
    target_path: str | os.PathLike[str],
    worker_count: int,
    snapshot_dir: str | os.PathLike[str],
    worker_prefix: str = "worker",
) -> tuple[DatabaseSnapshotPlan, ...]:
    target = Path(_require_text("target_path", os.fspath(target_path)))
    root = Path(_require_text("snapshot_dir", os.fspath(snapshot_dir)))
    count = _require_int("worker_count", worker_count, minimum=1)
    prefix = _require_text("worker_prefix", worker_prefix)
    return tuple(
        DatabaseSnapshotPlan(
            worker_id=f"{prefix}-{index:03d}",
            index=index,
            source_path=str(target),
            snapshot_path=str(root / _snapshot_name(target, prefix, index)),
        )
        for index in range(count)
    )


def prepare_database_snapshots(
    plans: Iterable[DatabaseSnapshotPlan],
    *,
    overwrite: bool = False,
) -> DatabaseSnapshotManifest:
    records: list[dict[str, Any]] = []
    byte_count = 0
    for plan in _snapshot_plan_tuple(plans):
        source = Path(plan.source_path)
        destination = Path(plan.snapshot_path)
        if not source.is_file():
            raise FileNotFoundError(plan.source_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not overwrite:
            raise FileExistsError(plan.snapshot_path)
        shutil.copy2(source, destination)
        size = destination.stat().st_size
        byte_count += size
        records.append(
            {
                "worker_id": plan.worker_id,
                "index": plan.index,
                "source_path": plan.source_path,
                "snapshot_path": plan.snapshot_path,
                "byte_count": size,
                "mode": plan.mode,
            }
        )
    return DatabaseSnapshotManifest(len(records), byte_count, tuple(records))


def worker_specs_from_snapshots(
    plans: Iterable[DatabaseSnapshotPlan],
    *,
    role: str = "read",
    argv: Iterable[str] = (),
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
) -> tuple[WorkerSpec, ...]:
    argv_values = _string_tuple("argv", argv)
    env_values = _env_tuple(env)
    return tuple(
        WorkerSpec(
            worker_id=plan.worker_id,
            index=plan.index,
            target_path=plan.source_path,
            database_path=plan.snapshot_path,
            role=role,
            argv=argv_values,
            env=env_values,
        )
        for plan in _snapshot_plan_tuple(plans)
    )


def plan_worker_launch(
    spec: WorkerSpec,
    *,
    base_command: Iterable[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
) -> WorkerLaunchPlan:
    if not isinstance(spec, WorkerSpec):
        raise TypeError("spec must be a WorkerSpec")
    command = _default_base_command() if base_command is None else _string_tuple("base_command", base_command)
    if not command:
        raise ValueError("base_command must not be empty")
    cwd_text = None if cwd is None else _require_text("cwd", os.fspath(cwd))
    return WorkerLaunchPlan(
        worker_id=spec.worker_id,
        index=spec.index,
        database_path=spec.database_path,
        argv=command + spec.argv + (spec.database_path,),
        env=_merge_env(spec.env, _env_tuple(env)),
        cwd=cwd_text,
    )


def plan_worker_launches(
    specs: Iterable[WorkerSpec],
    *,
    base_command: Iterable[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
) -> tuple[WorkerLaunchPlan, ...]:
    return tuple(plan_worker_launch(spec, base_command=base_command, cwd=cwd, env=env) for spec in specs)


def build_worker_request(*, shard: WorkShard, code: str) -> dict[str, Any]:
    if not isinstance(shard, WorkShard):
        raise TypeError("shard must be a WorkShard")
    code_text = _require_text("code", code, allow_empty=True)
    prelude = "\n".join(
        (
            f"__worker_id__ = {json.dumps(shard.worker_id, ensure_ascii=True)}",
            f"__shard_id__ = {json.dumps(shard.shard_id, ensure_ascii=True)}",
            f"__shard_index__ = {shard.index}",
            f"__shard_items__ = {canonical_json(list(shard.items))}",
            f"__shard_item_count__ = {shard.item_count}",
            "",
        )
    )
    return {"id": shard.shard_id, "code": prelude + code_text}


def parse_worker_response(line: str) -> dict[str, Any]:
    if not isinstance(line, str):
        raise TypeError("response line must be text")
    try:
        payload = json.loads(
            line,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ValueError as exc:
        raise WorkerProtocolError(f"invalid worker JSONL response: {exc}") from exc
    if not isinstance(payload, dict):
        raise WorkerProtocolError("worker response must be a JSON object")
    if type(payload.get("ok")) is not bool:
        raise WorkerProtocolError("worker response field ok must be a boolean")
    if payload["ok"] and "result" not in payload:
        raise WorkerProtocolError("successful worker response missing result")
    if not payload["ok"] and not isinstance(payload.get("error"), dict):
        raise WorkerProtocolError("failed worker response missing error object")
    return json_compatible_value(payload)


def worker_response_to_result(
    *,
    spec: WorkerSpec,
    shard: WorkShard,
    response: Mapping[str, Any],
    elapsed_ms: int,
) -> WorkerResult:
    if not isinstance(spec, WorkerSpec):
        raise TypeError("spec must be a WorkerSpec")
    if not isinstance(shard, WorkShard):
        raise TypeError("shard must be a WorkShard")
    payload = _response_payload(response)
    if payload["ok"]:
        return WorkerResult.success(
            worker_id=spec.worker_id,
            shard_id=shard.shard_id,
            item_count=shard.item_count,
            elapsed_ms=_require_int("elapsed_ms", elapsed_ms, minimum=0),
            result=_success_payload(payload),
        )
    error = _error_from_response(spec.worker_id, shard.shard_id, payload)
    return WorkerResult.from_error(
        worker_id=spec.worker_id,
        shard_id=shard.shard_id,
        item_count=shard.item_count,
        elapsed_ms=_require_int("elapsed_ms", elapsed_ms, minimum=0),
        error=error,
    )


def run_fanout_plan(
    plan: FanoutPlan,
    code: str,
    *,
    base_command: Iterable[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> FanoutResult:
    launches = plan_worker_launches(plan.worker_specs, base_command=base_command, cwd=cwd, env=env)
    return LocalParallelRunner(launches, timeout_s=timeout_s).run(plan, code)


class _TextTail:
    """Bound stderr evidence without risking unbounded memory growth."""

    def __init__(self, max_chars: int) -> None:
        self._max_chars = _require_int("max_chars", max_chars, minimum=1)
        self._text = ""
        self._lock = threading.Lock()

    def append(self, text: str) -> None:
        value = _require_text("text", text, allow_empty=True)
        with self._lock:
            self._text = (self._text + value)[-self._max_chars :]

    def value(self) -> str:
        with self._lock:
            return self._text


def _snapshot_name(target: Path, prefix: str, index: int) -> str:
    stem = target.stem if target.name else "database"
    suffix = target.suffix
    return f"{stem}.{prefix}-{index:03d}{suffix}"


def _snapshot_plan_tuple(plans: Iterable[DatabaseSnapshotPlan]) -> tuple[DatabaseSnapshotPlan, ...]:
    if isinstance(plans, DatabaseSnapshotPlan):
        raise TypeError("plans must be an iterable of DatabaseSnapshotPlan instances")
    values = tuple(plans)
    for plan in values:
        if not isinstance(plan, DatabaseSnapshotPlan):
            raise TypeError("plans must contain DatabaseSnapshotPlan instances")
    return values


def _start_stdout_reader(stream: TextIO, output: queue.Queue[str | None]) -> threading.Thread:
    thread = threading.Thread(target=_read_stdout_lines, args=(stream, output), daemon=True)
    thread.start()
    return thread


def _start_stderr_reader(stream: TextIO, tail: _TextTail) -> threading.Thread:
    thread = threading.Thread(target=_read_stderr_tail, args=(stream, tail), daemon=True)
    thread.start()
    return thread


def _read_stdout_lines(stream: TextIO, output: queue.Queue[str | None]) -> None:
    try:
        for line in stream:
            output.put(line)
    finally:
        output.put(None)


def _read_stderr_tail(stream: TextIO, tail: _TextTail) -> None:
    for chunk in stream:
        tail.append(chunk)


def _close_stream(stream: TextIO | None) -> None:
    if stream is None or stream.closed:
        return
    try:
        stream.close()
    except OSError:
        pass


def _join_thread(thread: threading.Thread | None) -> None:
    if thread is not None and thread.is_alive():
        thread.join(timeout=1.0)


def _request_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise TypeError("request must be a mapping")
    return json_compatible_value(dict(request))


def _validate_response_id(request: Mapping[str, Any], response: Mapping[str, Any]) -> None:
    if "id" in request and response.get("id") != request["id"]:
        raise WorkerProtocolError("worker response id does not match request id")
    if "id" not in request and "id" in response:
        raise WorkerProtocolError("worker response included an unexpected id")


def _response_payload(response: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        raise TypeError("response must be a mapping")
    return parse_worker_response(canonical_json(dict(response)))


def _success_payload(response: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "result": response.get("result"),
        "stdout": _optional_text(response, "stdout"),
        "stderr": _optional_text(response, "stderr"),
        "worker_elapsed_ms": _optional_elapsed(response.get("elapsed_ms", 0)),
    }
    if "id" in response:
        payload["id"] = response["id"]
    return payload


def _error_from_response(worker_id: str, shard_id: str, response: Mapping[str, Any]) -> WorkerError:
    error = response.get("error")
    if not isinstance(error, Mapping):
        raise WorkerProtocolError("worker error response must contain an error object")
    return WorkerError(
        worker_id=worker_id,
        shard_id=shard_id,
        error_type=_require_text("error.type", error.get("type")),
        message=_require_text("error.message", error.get("message"), allow_empty=True),
        traceback=_require_text("error.traceback", error.get("traceback", ""), allow_empty=True),
    )


def _optional_text(response: Mapping[str, Any], key: str) -> str:
    value = response.get(key, "")
    return _require_text(key, value, allow_empty=True)


def _optional_elapsed(value: Any) -> int:
    return _require_int("elapsed_ms", value, minimum=0)


def _object_without_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError(f"duplicate JSON object key: {key}")
        decoded[key] = value
    return decoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _default_base_command() -> tuple[str, ...]:
    return (sys.executable, "-m", "ida_cli")


def _merge_env(first: Iterable[tuple[str, str]], second: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    merged = dict(_env_tuple(first))
    merged.update(dict(_env_tuple(second)))
    return tuple(sorted(merged.items()))


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


def _require_record(record: WorkerResult | None) -> WorkerResult:
    if record is None:
        raise RuntimeError("worker thread did not produce a result")
    return record


def _require_timeout(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise TypeError(f"{name} must be a positive number")
    timeout = float(value)
    if timeout <= 0:
        raise ValueError(f"{name} must be positive")
    return timeout


def _require_int(name: str, value: Any, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _require_text(name: str, value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not allow_empty and value == "":
        raise ValueError(f"{name} must not be empty")
    return value


def _elapsed_ms_since(start_ns: int) -> int:
    return max(0, (time.perf_counter_ns() - start_ns) // 1_000_000)


__all__ = (
    "DatabaseSnapshotManifest",
    "DatabaseSnapshotPlan",
    "JsonlWorkerProcess",
    "LocalParallelRunner",
    "SNAPSHOT_COPY",
    "WORKER_TIMEOUT_RETURN_CODE",
    "WorkerLaunchPlan",
    "WorkerProtocolError",
    "WorkerTimeoutError",
    "WorkerTimeoutRecord",
    "build_worker_request",
    "parse_worker_response",
    "plan_database_snapshots",
    "plan_worker_launch",
    "plan_worker_launches",
    "prepare_database_snapshots",
    "run_fanout_plan",
    "worker_response_to_result",
    "worker_specs_from_snapshots",
)
