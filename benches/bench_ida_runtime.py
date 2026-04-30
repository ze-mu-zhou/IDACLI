"""Stdlib benchmarks for the IDA-CLI runtime surface."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.ai_helpers import AIHelpers
from ida_cli.artifacts import ArtifactStore
from ida_cli.kernel import IdaLibBackend, KernelSession, PythonOnlyBackend, create_session
from ida_cli.runtime import PythonRuntime
from ida_cli.supervisor import SHARD_CONTIGUOUS, SHARD_STABLE_HASH, make_fanout_plan

_BENCHMARK_NAME = "ida_runtime"
_DEFAULT_TARGET = "python-only-target.i64"


class BenchmarkError(RuntimeError):
    """Report benchmark setup failures as structured JSON."""


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark and print exactly one strict JSON object."""
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        payload = run_benchmark(args)
        exit_code = 0
    except Exception as exc:  # pragma: no cover - validated through subprocess shape.
        payload = _error_payload(exc)
        exit_code = 1
    print(json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return exit_code


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    """Return all runtime benchmark measurements as JSON-compatible data."""
    with tempfile.TemporaryDirectory(prefix="ida-cli-bench-") as temp_dir:
        session, startup_open = _startup_open(args.mode, args.target, Path(temp_dir) / "runs")
        try:
            request = _request_latency(session.runtime, args.iterations)
            artifact = _artifact_throughput(session.artifact_store, args.artifact_rows)
            helper = _helper_latency(session, args.iterations)
            fanout = _fanout_planning(args.target, args.fanout_items, args.workers, args.iterations)
        finally:
            session.close()
    return {
        "ok": True,
        "benchmark": _BENCHMARK_NAME,
        "requested_mode": args.mode,
        "selected_backend": session.backend_info.name,
        "target": str(Path(args.target)),
        "parameters": {
            "artifact_rows": args.artifact_rows,
            "fanout_items": args.fanout_items,
            "iterations": args.iterations,
            "workers": args.workers,
        },
        "measurements": {
            "artifact_throughput": artifact,
            "fanout_planning": fanout,
            "helper_latency": helper,
            "request_latency": request,
            "startup_open": startup_open,
        },
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
        },
    }


def _startup_open(mode: str, target: str, runs_dir: Path) -> tuple[KernelSession, dict[str, Any]]:
    """Measure backend startup and database-open work for the requested mode."""
    started = time.perf_counter_ns()
    if mode == "python":
        session = _python_only_session(target, runs_dir)
    elif mode == "idalib":
        if not IdaLibBackend.available():
            raise BenchmarkError("idalib mode requested but idapro is unavailable")
        session = create_session(target, runs_dir=runs_dir, backend=IdaLibBackend())
    else:
        backend = IdaLibBackend() if IdaLibBackend.available() else PythonOnlyBackend()
        if isinstance(backend, PythonOnlyBackend):
            session = _python_only_session(target, runs_dir)
        else:
            session = create_session(target, runs_dir=runs_dir, backend=backend)
    elapsed_ns = time.perf_counter_ns() - started
    return session, {"elapsed_ns": elapsed_ns, "backend": session.backend_info.as_dict()}


def _python_only_session(target: str, runs_dir: Path) -> KernelSession:
    """Build a kernel session that does not probe, import, or open IDA."""
    backend_info = PythonOnlyBackend().open(target)
    artifact_store = ArtifactStore.create(runs_dir)
    ai = AIHelpers(artifact_store.artifact_dir, auto_import=False)
    runtime = PythonRuntime(
        initial_globals={
            "__artifact_store__": artifact_store,
            "__backend__": backend_info.as_dict(),
        },
        ai=ai,
        database_path=target,
        run_dir=str(artifact_store.run_dir),
    )
    return KernelSession(target, backend_info, artifact_store, ai, runtime)


def _request_latency(runtime: PythonRuntime, iterations: int) -> dict[str, Any]:
    """Measure persistent runtime request latency and validate responses."""
    runtime.execute("_bench_counter = 0")

    def execute(index: int) -> None:
        response = runtime.execute("_bench_counter += 1\n__result__ = _bench_counter", request_id=index)
        if response.get("ok") is not True:
            raise BenchmarkError(f"request benchmark failed at iteration {index}")

    return {"iterations": iterations, "elapsed_ns": _summary(_measure(iterations, execute))}


def _artifact_throughput(store: ArtifactStore, row_count: int) -> dict[str, Any]:
    """Measure JSONL artifact throughput, size, row count, and hash metadata."""
    rows = ({"ea": 0x401000 + index, "name": f"sub_{index:04x}"} for index in range(row_count))
    started = time.perf_counter_ns()
    metadata = store.write_jsonl("bench/artifact_rows.jsonl", rows)
    elapsed_ns = time.perf_counter_ns() - started
    seconds = max(elapsed_ns / 1_000_000_000, 1e-9)
    return {
        "elapsed_ns": elapsed_ns,
        "bytes_per_second": int(metadata["size"] / seconds),
        "rows_per_second": int(row_count / seconds),
        "metadata": metadata,
    }


def _helper_latency(session: KernelSession, iterations: int) -> dict[str, Any]:
    """Measure helper calls that are valid without IDA plus IDA-only helpers when open."""
    helper = session.ai
    result: dict[str, Any] = {
        "get_ea_int_ns": _summary(_measure(iterations, lambda index: helper.get_ea(0x401000 + index)))
    }
    if session.backend_info.ida_available:
        ida_iterations = min(iterations, 16)
        functions_seen: list[dict[str, Any]] = []

        def enumerate_functions(_: int) -> None:
            functions_seen[:] = helper.functions()

        result["functions_ns"] = _summary(_measure(ida_iterations, enumerate_functions))
        result["function_count"] = len(functions_seen)
        if functions_seen:
            first_ea = int(functions_seen[0]["ea"])
            first_name = functions_seen[0].get("name") or f"0x{first_ea:x}"
            result["segments_ns"] = _summary(_measure(ida_iterations, lambda _: helper.segments()))
            result["entries_ns"] = _summary(_measure(ida_iterations, lambda _: helper.entries()))
            result["names_ns"] = _summary(_measure(ida_iterations, lambda _: helper.names()))
            result["function_record_ns"] = _summary(_measure(ida_iterations, lambda _: helper.function(first_ea)))
            result["disasm_16_ns"] = _summary(_measure(ida_iterations, lambda _: helper.disasm(first_ea, 16)))
            result["bytes_hex_16_ns"] = _summary(_measure(ida_iterations, lambda _: helper.bytes_hex(first_ea, 16)))
            result["comments_ns"] = _summary(_measure(ida_iterations, lambda _: helper.comments(first_ea)))
            result["type_at_ns"] = _summary(_measure(ida_iterations, lambda _: helper.type_at(first_ea)))
            result["operand_value_ns"] = _summary(_measure(ida_iterations, lambda _: helper.operand_value(first_ea, 0)))
            result["callers_ns"] = _summary(_measure(ida_iterations, lambda _: helper.callers(first_ea)))
            result["callees_ns"] = _summary(_measure(ida_iterations, lambda _: helper.callees(first_ea)))
            result["cfg_ns"] = _summary(_measure(ida_iterations, lambda _: helper.cfg(first_ea)))
            result["demangle_ns"] = _summary(_measure(ida_iterations, lambda _: helper.demangle(str(first_name))))
    return result


def _fanout_planning(target: str, item_count: int, workers: int, iterations: int) -> dict[str, Any]:
    """Measure deterministic multi-kernel fanout plan construction."""
    items = tuple({"ea": 0x401000 + index * 16, "ordinal": index} for index in range(item_count))
    contiguous = lambda _index: make_fanout_plan(
        target_path=target,
        items=items,
        worker_count=workers,
        strategy=SHARD_CONTIGUOUS,
    )
    stable_hash = lambda _index: make_fanout_plan(
        target_path=target,
        items=items,
        worker_count=workers,
        strategy=SHARD_STABLE_HASH,
    )
    sample = contiguous(0)
    return {
        "item_count": item_count,
        "workers": workers,
        "contiguous_ns": _summary(_measure(iterations, contiguous)),
        "stable_hash_ns": _summary(_measure(iterations, stable_hash)),
        "sample_plan": {
            "plan_id": sample.plan_id,
            "shard_counts": [shard.item_count for shard in sample.shards],
            "strategy": sample.strategy,
        },
    }


def _measure(iterations: int, call: Callable[[int], object]) -> list[int]:
    """Return nanosecond timings for one bounded benchmark loop."""
    values: list[int] = []
    for index in range(iterations):
        started = time.perf_counter_ns()
        call(index)
        values.append(time.perf_counter_ns() - started)
    return values


def _summary(values: list[int]) -> dict[str, int]:
    """Summarize non-empty nanosecond timings with strict integer fields."""
    if not values:
        raise BenchmarkError("cannot summarize an empty benchmark sample")
    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))
    return {
        "min": ordered[0],
        "median": int(statistics.median(ordered)),
        "p95": ordered[p95_index],
        "max": ordered[-1],
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse bounded stdlib-only benchmark arguments."""
    parser = argparse.ArgumentParser(description="Run IDA-CLI runtime benchmarks.")
    parser.add_argument("--mode", choices=("python", "auto", "idalib"), default="python")
    parser.add_argument("--target", default=_DEFAULT_TARGET)
    parser.add_argument("--iterations", type=_positive_int, default=500)
    parser.add_argument("--artifact-rows", type=_positive_int, default=2_000)
    parser.add_argument("--fanout-items", type=_positive_int, default=512)
    parser.add_argument("--workers", type=_positive_int, default=4)
    return parser.parse_args(argv)


def _positive_int(raw: str) -> int:
    """Accept positive decimal CLI counts and reject zero-length benchmark loops."""
    value = int(raw, 10)
    if value < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return value


def _error_payload(exc: BaseException) -> dict[str, Any]:
    """Return a strict JSON failure object without writing routine stderr logs."""
    return {
        "ok": False,
        "benchmark": _BENCHMARK_NAME,
        "error": {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
