"""Stdlib benchmark for the IDA-CLI protocol/runtime path."""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.artifacts import ArtifactStore
from ida_cli.protocol import encode_jsonl, parse_request
from ida_cli.runtime import PythonRuntime


def main() -> int:
    """Print JSON benchmark results for AI-side regression checks."""
    iterations = 2_000
    runtime = PythonRuntime()
    runtime.execute("counter = 0")
    direct_ns = _measure(
        iterations,
        lambda index: runtime.execute("counter += 1\n__result__ = counter", request_id=index),
    )
    protocol_ns = _measure(
        iterations,
        lambda index: parse_request(encode_jsonl({"id": index, "code": "__result__ = 1"})),
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        store = ArtifactStore.create(Path(temp_dir) / "runs", run_id="bench")
        started = time.perf_counter_ns()
        metadata = store.write_jsonl("rows.jsonl", ({"index": index} for index in range(iterations)))
        artifact_ns = time.perf_counter_ns() - started
    result = {
        "iterations": iterations,
        "runtime_request_ns": _summary(direct_ns),
        "protocol_roundtrip_ns": _summary(protocol_ns),
        "artifact_jsonl": {
            "elapsed_ns": artifact_ns,
            "rows_per_second": int(iterations / max(artifact_ns / 1_000_000_000, 1e-9)),
            "metadata": metadata,
        },
    }
    print(json.dumps(result, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return 0


def _measure(iterations: int, call: object) -> list[int]:
    """Return per-iteration nanosecond timings for a callable."""
    values: list[int] = []
    for index in range(iterations):
        started = time.perf_counter_ns()
        call(index)
        values.append(time.perf_counter_ns() - started)
    return values


def _summary(values: list[int]) -> dict[str, int]:
    """Summarize timings without non-JSON numeric edge cases."""
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "median": int(statistics.median(ordered)),
        "p95": ordered[int(len(ordered) * 0.95)],
        "max": ordered[-1],
    }


if __name__ == "__main__":
    raise SystemExit(main())
