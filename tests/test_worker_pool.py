"""Tests for IDA-free local worker-pool abstractions."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.worker_pool import (  # noqa: E402
    LocalWorkerPool,
    WorkerProcessCrash,
    WorkerSpec,
)


def _specs() -> tuple[WorkerSpec, WorkerSpec]:
    return (
        WorkerSpec.create(index=0, target_path="sample.i64", database_path="sample.0.i64"),
        WorkerSpec.create(index=1, target_path="sample.i64", database_path="sample.1.i64"),
    )


class WorkerPoolTests(unittest.TestCase):
    def test_fanout_success_metadata_is_json_compatible(self) -> None:
        pool = LocalWorkerPool(_specs())
        shards = (
            {"shard_id": "shard-000", "worker_id": "worker-000", "items": [{"ea": 1}, {"ea": 2}]},
            {"shard_id": "shard-001", "worker_id": "worker-001", "items": [{"ea": 3}]},
        )

        result = pool.fanout(
            shards,
            lambda spec, items: {"worker_id": spec.worker_id, "count": len(items)},
        )

        payload = result.as_dict()
        json.dumps(payload, allow_nan=False, sort_keys=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.worker_count, 2)
        self.assertEqual(result.shard_count, 2)
        self.assertEqual(result.item_count, 3)
        self.assertEqual(result.success_count, 2)
        self.assertEqual([state.completed_shards for state in pool.states()], [1, 1])

    def test_python_exception_becomes_worker_error(self) -> None:
        pool = LocalWorkerPool(_specs())

        def task(_: WorkerSpec, __: tuple[object, ...]) -> dict[str, object]:
            raise ValueError("bad shard")

        result = pool.fanout(
            ({"shard_id": "shard-000", "worker_id": "worker-000", "items": [1]},),
            task,
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.error_count, 1)
        error = result.results[0].error
        self.assertIsNotNone(error)
        self.assertEqual(error.as_dict()["type"], "ValueError")
        self.assertIn("bad shard", error.as_dict()["traceback"])
        self.assertEqual(pool.states()[0].failed_shards, 1)

    def test_worker_process_crash_becomes_crash_record(self) -> None:
        pool = LocalWorkerPool(_specs())

        def task(_: WorkerSpec, __: tuple[object, ...]) -> dict[str, object]:
            raise WorkerProcessCrash(137, "worker exited", "fatal tail")

        result = pool.fanout(
            ({"shard_id": "shard-001", "worker_id": "worker-001", "items": [1, 2]},),
            task,
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.crash_count, 1)
        crash = result.results[0].crash
        self.assertIsNotNone(crash)
        self.assertEqual(crash.as_dict()["returncode"], 137)
        self.assertEqual(crash.as_dict()["stderr_tail"], "fatal tail")

    def test_non_json_success_payload_becomes_worker_error(self) -> None:
        pool = LocalWorkerPool(_specs())

        result = pool.fanout(
            ({"shard_id": "shard-000", "worker_id": "worker-000", "items": [1]},),
            lambda _spec, _items: {1, 2},
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.error_count, 1)
        self.assertEqual(result.results[0].status, "error")

    def test_unknown_worker_id_fails_fast(self) -> None:
        pool = LocalWorkerPool(_specs())

        with self.assertRaises(ValueError):
            pool.fanout(
                ({"shard_id": "shard-404", "worker_id": "worker-404", "items": []},),
                lambda _spec, _items: None,
            )

    def test_worker_spec_rejects_string_argv(self) -> None:
        with self.assertRaises(TypeError):
            WorkerSpec.create(index=0, target_path="sample.i64", argv="abc")


if __name__ == "__main__":
    unittest.main()
