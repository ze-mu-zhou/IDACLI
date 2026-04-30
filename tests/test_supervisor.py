"""Tests for IDA-free supervisor planning primitives."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_cli.supervisor import (  # noqa: E402
    SHARD_STABLE_HASH,
    make_fanout_plan,
    shard_items,
)


class SupervisorTests(unittest.TestCase):
    def test_contiguous_shards_are_balanced_and_stable(self) -> None:
        items = list(range(10))

        first = shard_items(items, 3)
        second = shard_items(items, 3)

        self.assertEqual(first, second)
        self.assertEqual(first, ((0, 1, 2, 3), (4, 5, 6), (7, 8, 9)))

    def test_stable_hash_shards_keep_same_item_assignments(self) -> None:
        items = [{"ea": 0x401000}, {"ea": 0x402000}, {"ea": 0x403000}]

        forward = shard_items(items, 4, strategy=SHARD_STABLE_HASH)
        reverse = shard_items(reversed(items), 4, strategy=SHARD_STABLE_HASH)

        def assignments(shards: tuple[tuple[object, ...], ...]) -> dict[str, int]:
            return {
                json.dumps(item, sort_keys=True): index
                for index, shard in enumerate(shards)
                for item in shard
            }

        self.assertEqual(assignments(forward), assignments(reverse))

    def test_fanout_plan_is_deterministic_and_json_compatible(self) -> None:
        items = [{"ea": 0x401000}, {"ea": 0x402000}, {"ea": 0x403000}]

        plan = make_fanout_plan(
            target_path="sample.i64",
            items=items,
            worker_count=2,
            database_paths=("sample.worker0.i64", "sample.worker1.i64"),
            argv=("--headless",),
            env={"B": "2", "A": "1"},
        )
        repeat = make_fanout_plan(
            target_path="sample.i64",
            items=items,
            worker_count=2,
            database_paths=("sample.worker0.i64", "sample.worker1.i64"),
            argv=("--headless",),
            env={"B": "2", "A": "1"},
        )

        payload = plan.as_dict()
        json.dumps(payload, allow_nan=False, sort_keys=True)
        self.assertEqual(plan.plan_id, repeat.plan_id)
        self.assertEqual(payload["worker_count"], 2)
        self.assertEqual(payload["item_count"], 3)
        self.assertEqual(payload["workers"][0]["worker_id"], "worker-000")
        self.assertEqual(payload["workers"][0]["env"], {"A": "1", "B": "2"})
        self.assertEqual(payload["shards"][0]["item_count"], 2)

    def test_invalid_inputs_fail_fast(self) -> None:
        with self.assertRaises(ValueError):
            shard_items([1], 0)

        with self.assertRaises(TypeError):
            shard_items([object()], 1)

        with self.assertRaises(ValueError):
            make_fanout_plan(
                target_path="sample.i64",
                items=[],
                worker_count=2,
                database_paths=("only-one.i64",),
            )


if __name__ == "__main__":
    unittest.main()
