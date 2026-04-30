"""Tests for stdlib benchmark scripts; none require IDA."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benches" / "bench_ida_runtime.py"


def _load_benchmark_module() -> object:
    """Import the benchmark script by path without making benches a package."""
    spec = importlib.util.spec_from_file_location("bench_ida_runtime", BENCH)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load benchmark module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IdaRuntimeBenchmarkTests(unittest.TestCase):
    """Validate the runtime benchmark output using Python-only mode."""

    def test_python_only_benchmark_emits_one_strict_json_payload(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(BENCH),
                "--mode",
                "python",
                "--iterations",
                "4",
                "--artifact-rows",
                "3",
                "--fanout-items",
                "5",
                "--workers",
                "2",
            ],
            capture_output=True,
            check=True,
            cwd=ROOT,
            text=True,
        )

        self.assertEqual(completed.stderr, "")
        lines = completed.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        json.dumps(payload, allow_nan=False, sort_keys=True)

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["benchmark"], "ida_runtime")
        self.assertEqual(payload["selected_backend"], "python")
        backend = payload["measurements"]["startup_open"]["backend"]
        self.assertEqual(backend["name"], "python")
        self.assertFalse(backend["database_opened"])
        self.assertFalse(backend["ida_available"])

        request = payload["measurements"]["request_latency"]
        self.assertEqual(request["iterations"], 4)
        self.assertGreaterEqual(request["elapsed_ns"]["min"], 0)
        artifact = payload["measurements"]["artifact_throughput"]
        self.assertEqual(artifact["metadata"]["count"], 3)
        self.assertEqual(len(artifact["metadata"]["sha256"]), 64)
        helper = payload["measurements"]["helper_latency"]
        self.assertIn("get_ea_int_ns", helper)
        fanout = payload["measurements"]["fanout_planning"]
        self.assertEqual(fanout["sample_plan"]["shard_counts"], [3, 2])

    def test_explicit_idalib_mode_fails_fast_when_unavailable(self) -> None:
        bench = _load_benchmark_module()
        original_available = bench.IdaLibBackend.available
        bench.IdaLibBackend.available = staticmethod(lambda: False)
        args = SimpleNamespace(
            artifact_rows=1,
            fanout_items=1,
            iterations=1,
            mode="idalib",
            target="sample.i64",
            workers=1,
        )
        try:
            with self.assertRaisesRegex(bench.BenchmarkError, "idapro is unavailable"):
                bench.run_benchmark(args)
        finally:
            bench.IdaLibBackend.available = original_available


if __name__ == "__main__":
    unittest.main()
