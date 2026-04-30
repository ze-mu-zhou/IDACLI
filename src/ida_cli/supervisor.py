"""Multi-kernel planning primitives that do not require IDA at import time."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
from typing import Any

from .worker_pool import WorkerSpec, canonical_json, json_compatible_value

SHARD_CONTIGUOUS = "contiguous"
SHARD_STABLE_HASH = "stable_hash"
_SHARD_STRATEGIES = frozenset((SHARD_CONTIGUOUS, SHARD_STABLE_HASH))


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if value == "":
        raise ValueError(f"{name} must not be empty")
    return value


def _require_count(name: str, value: Any) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < 1:
        raise ValueError(f"{name} must be at least 1")
    return value


def _require_strategy(strategy: str) -> str:
    value = _require_text("strategy", strategy)
    if value not in _SHARD_STRATEGIES:
        raise ValueError(f"unsupported sharding strategy: {value}")
    return value


def _normalize_items(items: Iterable[Any]) -> tuple[Any, ...]:
    if isinstance(items, (bytes, str)):
        raise TypeError("items must be an iterable of JSON-compatible values")
    return tuple(json_compatible_value(item) for item in items)


def _database_paths(
    *,
    target_path: str,
    worker_count: int,
    database_paths: Iterable[str] | None,
) -> tuple[str, ...]:
    if database_paths is None:
        return tuple(target_path for _ in range(worker_count))
    if isinstance(database_paths, (bytes, str)):
        raise TypeError("database_paths must be an iterable of strings")
    paths = tuple(_require_text("database_path", path) for path in database_paths)
    if len(paths) != worker_count:
        raise ValueError("database_paths length must match worker_count")
    return paths


def _stable_bucket(item: Any, worker_count: int) -> int:
    digest = hashlib.sha256(canonical_json(item).encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % worker_count


def shard_items(
    items: Iterable[Any],
    worker_count: int,
    *,
    strategy: str = SHARD_CONTIGUOUS,
) -> tuple[tuple[Any, ...], ...]:
    """Split JSON-compatible work items into deterministic worker buckets."""
    count = _require_count("worker_count", worker_count)
    selected_strategy = _require_strategy(strategy)
    normalized = _normalize_items(items)
    buckets: list[list[Any]] = [[] for _ in range(count)]
    if selected_strategy == SHARD_CONTIGUOUS:
        base, extra = divmod(len(normalized), count)
        cursor = 0
        for index, bucket in enumerate(buckets):
            size = base + (1 if index < extra else 0)
            bucket.extend(normalized[cursor : cursor + size])
            cursor += size
    else:
        for item in normalized:
            buckets[_stable_bucket(item, count)].append(item)
    return tuple(tuple(bucket) for bucket in buckets)


@dataclass(frozen=True, slots=True)
class WorkShard:
    """A deterministic work assignment for one worker spec."""

    shard_id: str
    index: int
    worker_id: str
    strategy: str
    items: tuple[Any, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "shard_id", _require_text("shard_id", self.shard_id))
        if type(self.index) is not int:
            raise TypeError("index must be an integer")
        if self.index < 0:
            raise ValueError("index must be at least 0")
        object.__setattr__(self, "worker_id", _require_text("worker_id", self.worker_id))
        object.__setattr__(self, "strategy", _require_strategy(self.strategy))
        object.__setattr__(self, "items", _normalize_items(self.items))

    @property
    def item_count(self) -> int:
        return len(self.items)

    def as_dict(self) -> dict[str, Any]:
        return {
            "shard_id": self.shard_id,
            "index": self.index,
            "worker_id": self.worker_id,
            "strategy": self.strategy,
            "item_count": self.item_count,
            "items": list(self.items),
        }


@dataclass(frozen=True, slots=True)
class FanoutPlan:
    """JSON-compatible plan tying worker specs to deterministic shards."""

    plan_id: str
    target_path: str
    strategy: str
    worker_specs: tuple[WorkerSpec, ...]
    shards: tuple[WorkShard, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _require_text("plan_id", self.plan_id))
        object.__setattr__(self, "target_path", _require_text("target_path", self.target_path))
        object.__setattr__(self, "strategy", _require_strategy(self.strategy))
        if len(self.worker_specs) != len(self.shards):
            raise ValueError("worker_specs and shards must have the same length")
        for spec, shard in zip(self.worker_specs, self.shards):
            if not isinstance(spec, WorkerSpec):
                raise TypeError("worker_specs must contain WorkerSpec instances")
            if not isinstance(shard, WorkShard):
                raise TypeError("shards must contain WorkShard instances")
            if spec.worker_id != shard.worker_id:
                raise ValueError("worker spec and shard worker_id mismatch")

    @property
    def worker_count(self) -> int:
        return len(self.worker_specs)

    @property
    def item_count(self) -> int:
        return sum(shard.item_count for shard in self.shards)

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target_path": self.target_path,
            "strategy": self.strategy,
            "worker_count": self.worker_count,
            "item_count": self.item_count,
            "workers": [spec.as_dict() for spec in self.worker_specs],
            "shards": [shard.as_dict() for shard in self.shards],
        }


def make_worker_specs(
    *,
    target_path: str,
    worker_count: int,
    database_paths: Iterable[str] | None = None,
    role: str = "read",
    worker_prefix: str = "worker",
    argv: Iterable[str] = (),
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
) -> tuple[WorkerSpec, ...]:
    """Create deterministic worker specs for isolated database paths."""
    target = _require_text("target_path", target_path)
    count = _require_count("worker_count", worker_count)
    paths = _database_paths(target_path=target, worker_count=count, database_paths=database_paths)
    if isinstance(argv, (bytes, str)):
        raise TypeError("argv must be an iterable of strings")
    if isinstance(env, (bytes, str)):
        raise TypeError("env must be a mapping or iterable of pairs")
    argv_values = tuple(argv)
    env_values = dict(env) if isinstance(env, Mapping) else tuple(env)
    return tuple(
        WorkerSpec.create(
            index=index,
            target_path=target,
            database_path=database_path,
            role=role,
            worker_prefix=worker_prefix,
            argv=argv_values,
            env=env_values,
        )
        for index, database_path in enumerate(paths)
    )


def make_work_shards(
    *,
    items: Iterable[Any],
    worker_specs: Iterable[WorkerSpec],
    strategy: str = SHARD_CONTIGUOUS,
) -> tuple[WorkShard, ...]:
    """Bind deterministic item shards to worker IDs."""
    specs = tuple(worker_specs)
    if not specs:
        raise ValueError("worker_specs must not be empty")
    for spec in specs:
        if not isinstance(spec, WorkerSpec):
            raise TypeError("worker_specs must contain WorkerSpec instances")
    selected_strategy = _require_strategy(strategy)
    parts = shard_items(items, len(specs), strategy=selected_strategy)
    return tuple(
        WorkShard(
            shard_id=f"shard-{index:03d}",
            index=index,
            worker_id=spec.worker_id,
            strategy=selected_strategy,
            items=part,
        )
        for index, (spec, part) in enumerate(zip(specs, parts))
    )


def _fanout_plan_id(target_path: str, strategy: str, specs: Iterable[WorkerSpec], shards: Iterable[WorkShard]) -> str:
    payload = {
        "target_path": target_path,
        "strategy": strategy,
        "workers": [spec.as_dict() for spec in specs],
        "shards": [shard.as_dict() for shard in shards],
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"fanout-{digest[:16]}"


def make_fanout_plan(
    *,
    target_path: str,
    items: Iterable[Any],
    worker_count: int,
    database_paths: Iterable[str] | None = None,
    strategy: str = SHARD_CONTIGUOUS,
    role: str = "read",
    worker_prefix: str = "worker",
    argv: Iterable[str] = (),
    env: Iterable[tuple[str, str]] | Mapping[str, str] = (),
) -> FanoutPlan:
    """Create a complete multi-kernel fanout plan without touching IDA."""
    selected_strategy = _require_strategy(strategy)
    specs = make_worker_specs(
        target_path=target_path,
        worker_count=worker_count,
        database_paths=database_paths,
        role=role,
        worker_prefix=worker_prefix,
        argv=argv,
        env=env,
    )
    shards = make_work_shards(items=items, worker_specs=specs, strategy=selected_strategy)
    plan_id = _fanout_plan_id(target_path, selected_strategy, specs, shards)
    return FanoutPlan(plan_id, target_path, selected_strategy, specs, shards)


__all__ = (
    "FanoutPlan",
    "SHARD_CONTIGUOUS",
    "SHARD_STABLE_HASH",
    "WorkShard",
    "make_fanout_plan",
    "make_work_shards",
    "make_worker_specs",
    "shard_items",
)
