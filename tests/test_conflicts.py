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


def noop_patch() -> dict[str, object]:
    """Return one no-op patch record, as produced when old and new bytes match."""

    return {
        "kind": "patch_bytes",
        "target": {"ea": 0x2000, "length": 1},
        "before": {"bytes": "90"},
        "after": {"bytes": "90"},
        "changed_addresses": [],
        "changed_names": [],
    }


def patch_span(start: int, byte_hex: str, changed: list[int]) -> dict[str, object]:
    """Return one multi-byte patch change record."""

    payload = bytes.fromhex(byte_hex)
    return {
        "kind": "patch_bytes",
        "target": {"ea": start, "length": len(payload)},
        "before": {"bytes": "90" * len(payload)},
        "after": {"bytes": byte_hex},
        "changed_addresses": changed,
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

    def test_noop_patch_with_empty_changed_addresses_merges(self) -> None:
        result = merge_changes([noop_patch()])

        self.assertTrue(result["ok"])
        self.assertEqual(result["merged_count"], 1)
        self.assertEqual(result["conflict_count"], 0)

    def test_noop_patch_does_not_conflict_with_real_patch(self) -> None:
        result = merge_change_sets(
            (
                {"branch": "left", "changes": [noop_patch()]},
                {"branch": "right", "changes": [patch("cc")]},
            )
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["merged_count"], 2)
        self.assertEqual(result["conflict_count"], 0)

    def test_unmerged_record_does_not_claim_resources(self) -> None:
        first = patch("cc")
        second = patch_span(0x2000, "aabb", [0x2000, 0x2001])
        third = patch_span(0x2001, "ee", [0x2001])

        result = merge_change_sets(
            (
                {"branch": "A", "changes": [first]},
                {"branch": "B", "changes": [second]},
                {"branch": "C", "changes": [third]},
            )
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["conflict_count"], 1)
        conflict = result["conflicts"][0]
        self.assertEqual(conflict["resource"], ["byte", 0x2000])
        self.assertEqual(conflict["first"]["branch"], "A")
        self.assertEqual(conflict["second"]["branch"], "B")
        self.assertEqual(result["merged_count"], 2)
        self.assertIn(first, result["merged"])
        self.assertIn(third, result["merged"])
        json.dumps(result, allow_nan=False, sort_keys=True)

    def test_patch_missing_changed_addresses_field_fails_fast(self) -> None:
        record = patch("cc")
        del record["changed_addresses"]

        with self.assertRaisesRegex(ConflictMergeError, "changed_addresses"):
            merge_changes([record])


if __name__ == "__main__":
    unittest.main()
