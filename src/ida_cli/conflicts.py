"""Deterministic merge and conflict detection for mutation change records."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any


class ConflictMergeError(RuntimeError):
    """Raised when change records cannot be merged deterministically."""


def merge_changes(changes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge one flat sequence of mutation records and report conflicts."""

    return merge_change_sets(({"branch": "default", "changes": list(changes)},))


def merge_change_sets(change_sets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge branch change sets into JSON-compatible records and conflicts."""

    merged: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    by_resource: dict[tuple[Any, ...], dict[str, Any]] = {}
    seen_records: set[str] = set()
    for branch_index, change_set in enumerate(change_sets):
        branch = _branch_name(change_set, branch_index)
        for ordinal, change in enumerate(_change_rows(change_set)):
            record = _record(change, branch, ordinal)
            canonical = _canonical(record["change"])
            if canonical in seen_records:
                continue
            seen_records.add(canonical)
            resources = _resources(record["change"])
            collided = False
            for resource in resources:
                previous = by_resource.get(resource)
                if previous is None:
                    by_resource[resource] = record
                    continue
                if _same_effect(previous["change"], record["change"], resource):
                    continue
                conflicts.append(_conflict(resource, previous, record))
                collided = True
            if not collided:
                merged.append(record["change"])
    return {
        "ok": not conflicts,
        "merged": merged,
        "merged_count": len(merged),
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
    }


def _branch_name(change_set: Mapping[str, Any], index: int) -> str:
    """Return a deterministic branch name for conflict reports."""

    branch = change_set.get("branch", f"branch-{index:03d}")
    if not isinstance(branch, str) or branch == "":
        raise ConflictMergeError("change set branch must be a non-empty string")
    return branch


def _change_rows(change_set: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Validate a branch change list."""

    rows = change_set.get("changes")
    if isinstance(rows, (str, bytes, bytearray)) or not isinstance(rows, Iterable):
        raise ConflictMergeError("change set requires an iterable changes field")
    records = list(rows)
    if not all(isinstance(record, Mapping) for record in records):
        raise ConflictMergeError("each change must be an object")
    return records


def _record(change: Mapping[str, Any], branch: str, ordinal: int) -> dict[str, Any]:
    """Attach source metadata without mutating the original record."""

    copied = json.loads(_canonical(change))
    return {"branch": branch, "ordinal": ordinal, "change": copied}


def _resources(change: Mapping[str, Any]) -> tuple[tuple[Any, ...], ...]:
    """Return resources touched by a mutation change record."""

    kind = _kind(change)
    target = _target(change)
    if kind == "rename":
        return (("name", _ea(target)),)
    if kind == "comment":
        return (("comment", _ea(target), bool(target.get("repeatable", False))),)
    if kind == "type":
        return (("type", _ea(target)),)
    if kind == "patch_bytes":
        return tuple(("byte", address) for address in _changed_addresses(change))
    if kind == "save_database":
        return (("save_database", str(target.get("path"))),)
    raise ConflictMergeError(f"unsupported change kind: {kind!r}")


def _same_effect(first: Mapping[str, Any], second: Mapping[str, Any], resource: tuple[Any, ...]) -> bool:
    """Return whether two records make the same final change to one resource."""

    kind = resource[0]
    if kind == "byte":
        return _byte_after(first, int(resource[1])) == _byte_after(second, int(resource[1]))
    return _canonical(first.get("after")) == _canonical(second.get("after"))


def _conflict(resource: tuple[Any, ...], first: Mapping[str, Any], second: Mapping[str, Any]) -> dict[str, Any]:
    """Build one conflict report for two incompatible branch records."""

    return {
        "resource": list(resource),
        "reason": "different final values for same resource",
        "first": _source_record(first),
        "second": _source_record(second),
    }


def _source_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return compact source and effect evidence for conflict reports."""

    change = record["change"]
    return {
        "branch": record["branch"],
        "ordinal": record["ordinal"],
        "kind": _kind(change),
        "before": change.get("before", {}),
        "after": change.get("after", {}),
    }


def _kind(change: Mapping[str, Any]) -> str:
    """Return the normalized mutation kind."""

    kind = change.get("kind")
    if not isinstance(kind, str) or kind == "":
        raise ConflictMergeError("change.kind must be a non-empty string")
    return kind


def _target(change: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the normalized mutation target."""

    target = change.get("target")
    if not isinstance(target, Mapping):
        raise ConflictMergeError("change.target must be an object")
    return target


def _ea(target: Mapping[str, Any]) -> int:
    """Return a target effective address."""

    value = target.get("ea")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConflictMergeError("target.ea must be a non-negative integer")
    return value


def _changed_addresses(change: Mapping[str, Any]) -> list[int]:
    """Return changed byte addresses for byte patch conflict detection."""

    values = change.get("changed_addresses")
    if not isinstance(values, list) or not values:
        raise ConflictMergeError("patch_bytes changes require changed_addresses")
    if not all(isinstance(value, int) and value >= 0 for value in values):
        raise ConflictMergeError("changed_addresses must be non-negative integers")
    return values


def _byte_after(change: Mapping[str, Any], address: int) -> str:
    """Return the target byte value at one changed address as two hex digits."""

    target = _target(change)
    start = _ea(target)
    after = change.get("after")
    if not isinstance(after, Mapping) or not isinstance(after.get("bytes"), str):
        raise ConflictMergeError("patch_bytes.after.bytes must be a hex string")
    offset = address - start
    hex_text = after["bytes"]
    index = offset * 2
    if offset < 0 or index + 2 > len(hex_text):
        raise ConflictMergeError("changed byte address is outside patch range")
    return hex_text[index : index + 2].lower()


def _canonical(value: Any) -> str:
    """Return strict deterministic JSON for dedupe and comparisons."""

    return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


__all__ = ("ConflictMergeError", "merge_change_sets", "merge_changes")
