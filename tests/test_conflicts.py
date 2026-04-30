"""Tests for deterministic mutation conflict merging."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_cli.conflicts import ConflictMergeError, merge_change_sets, merge_changes


def rename(after: str) -> dict[str, object]:
    """Return one rename change record."""

    return {
        "kind": "rename",
        "target": {"ea": 0x1000},
        "before": {"name": "start"},
        "after": {"name": after},
        "changed_addresses": [0x1000],
        "changed_names": [{"ea": 0x1000, "before": "start", "after": after}],
    }


def patch(byte_hex: str) -> dict[str, object]:
    """Return one byte-patch change record."""

    return {
        "kind": "patch_bytes",
        "target": {"ea": 0x2000, "length": 1},
        "before": {"bytes": "90"},
        "after": {"bytes": byte_hex},
        "changed_addresses": [0x2000],
        "changed_names": [],
    }


class ConflictMergeTests(unittest.TestCase):
    """Verify branch merge behavior without requiring IDA."""

    def test_identical_records_are_deduped(self) -> None:
        result = merge_changes([rename("better"), rename("better")])

        self.assertTrue(result["ok"])
        self.assertEqual(result["merged_count"], 1)
        self.assertEqual(result["conflict_count"], 0)
        json.dumps(result, allow_nan=False, sort_keys=True)

    def test_different_renames_conflict_on_same_resource(self) -> None:
        result = merge_change_sets(
            (
                {"branch": "left", "changes": [rename("left_name")]},
                {"branch": "right", "changes": [rename("right_name")]},
            )
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["merged_count"], 1)
        self.assertEqual(result["conflicts"][0]["resource"], ["name", 0x1000])
        self.assertEqual(result["conflicts"][0]["first"]["branch"], "left")
        self.assertEqual(result["conflicts"][0]["second"]["branch"], "right")

    def test_byte_patch_conflicts_per_changed_address(self) -> None:
        result = merge_change_sets(
            (
                {"branch": "left", "changes": [patch("cc")]},
                {"branch": "right", "changes": [patch("90")]},
            )
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["conflicts"][0]["resource"], ["byte", 0x2000])

    def test_invalid_change_shape_fails_fast(self) -> None:
        with self.assertRaisesRegex(ConflictMergeError, "change.kind"):
            merge_changes([{"target": {"ea": 1}}])


if __name__ == "__main__":
    unittest.main()
