"""Per-run artifact storage for protocol-safe large outputs."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable

_ARTIFACT_DIR = "artifacts"
_TMP_SUFFIX = ".tmp"
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{idx}" for idx in range(1, 10)),
        *(f"LPT{idx}" for idx in range(1, 10)),
    }
)


class ArtifactStore:
    """Manage one run directory and its safe artifact files."""

    def __init__(self, run_dir: str | os.PathLike[str], *, metadata_prefix: str | os.PathLike[str] | None = None) -> None:
        # Keep storage rooted in one run; future changes must not write outside it.
        self._run_dir = Path(run_dir)
        self._artifact_dir = self._run_dir / _ARTIFACT_DIR
        self._metadata_prefix = _safe_relative_path(metadata_prefix or _ARTIFACT_DIR)
        self._artifact_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def create(cls, runs_dir: str | os.PathLike[str], run_id: str | None = None) -> "ArtifactStore":
        """Create a per-run artifact store under ``runs_dir``."""
        # Allocate once per kernel run; future changes must keep IDs path-safe.
        safe_run_id = _safe_run_id(run_id) if run_id is not None else _new_run_id()
        runs_path = Path(runs_dir)
        prefix_parts = _safe_relative_path(runs_path.name or "runs").parts
        metadata_prefix = PurePosixPath(*prefix_parts, safe_run_id, _ARTIFACT_DIR)
        return cls(runs_path / safe_run_id, metadata_prefix=metadata_prefix)

    @property
    def run_dir(self) -> Path:
        """Return the run directory path."""
        return self._run_dir

    @property
    def artifact_dir(self) -> Path:
        """Return the concrete artifact directory path."""
        return self._artifact_dir

    def write_json(self, name: str | os.PathLike[str], value: Any) -> dict[str, Any]:
        """Write one deterministic UTF-8 JSON artifact and return metadata."""
        # Serialize before opening the final path; future changes must fail before replacing old data.
        data = _json_bytes(value)
        return self._write_bytes(name, data, count=None)

    def write_jsonl(self, name: str | os.PathLike[str], rows: Iterable[Any]) -> dict[str, Any]:
        """Write newline-delimited JSON rows and return metadata."""
        # Stream rows into a temporary file; future changes must keep stdout untouched.
        target = self._artifact_path(name)
        metadata_path = self._metadata_path(name)
        digest = hashlib.sha256()
        byte_count = 0
        row_count = 0
        temp = self._temp_path(target)
        try:
            with temp.open("wb") as handle:
                for row in rows:
                    line = _json_bytes(row) + b"\n"
                    handle.write(line)
                    digest.update(line)
                    byte_count += len(line)
                    row_count += 1
            os.replace(temp, target)
        except Exception:
            _remove_if_present(temp)
            raise
        return _metadata(metadata_path, byte_count, digest.hexdigest(), row_count)

    def write_binary(self, name: str | os.PathLike[str], data: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Write an exact binary artifact and return metadata."""
        # Accept bytes-like inputs only; future changes must not coerce text into binary.
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("binary artifact data must be bytes-like")
        return self._write_bytes(name, bytes(data), count=None)

    def _write_bytes(self, name: str | os.PathLike[str], data: bytes, *, count: int | None) -> dict[str, Any]:
        """Atomically write bytes and return protocol-ready metadata."""
        # Hash exactly what reaches disk; future changes must keep metadata byte-for-byte accurate.
        target = self._artifact_path(name)
        temp = self._temp_path(target)
        try:
            with temp.open("wb") as handle:
                handle.write(data)
            os.replace(temp, target)
        except Exception:
            _remove_if_present(temp)
            raise
        digest = hashlib.sha256(data).hexdigest()
        return _metadata(self._metadata_path(name), len(data), digest, count)

    def _artifact_path(self, name: str | os.PathLike[str]) -> Path:
        """Resolve a safe relative artifact name under the store root."""
        # Validate before joining; future changes must reject absolute paths and traversal.
        relative = _safe_relative_path(name)
        target = self._artifact_dir.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        _ensure_inside(self._artifact_dir, target)
        return target

    def _metadata_path(self, name: str | os.PathLike[str]) -> str:
        """Return a POSIX relative path suitable for JSON protocol metadata."""
        relative = _safe_relative_path(name)
        return PurePosixPath(self._metadata_prefix, relative).as_posix()

    def _temp_path(self, target: Path) -> Path:
        """Return a hidden temporary path beside the final artifact."""
        token = secrets.token_hex(8)
        temp = target.with_name(f".{target.name}.{token}{_TMP_SUFFIX}")
        _ensure_inside(self._artifact_dir, temp)
        return temp


def _new_run_id() -> str:
    """Create a sortable, path-safe run identifier."""
    # Use UTC plus entropy; future changes must avoid clock-only collisions.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(4)}"


def _safe_run_id(run_id: str) -> str:
    """Validate a caller-provided run identifier."""
    # Reuse artifact path validation; future changes must keep run IDs single-directory names.
    safe = _safe_relative_path(run_id)
    if len(safe.parts) != 1:
        raise ValueError("run id must be one safe path component")
    (only_part,) = safe.parts
    return only_part


def _safe_relative_path(path: str | os.PathLike[str]) -> PurePosixPath:
    """Return a normalized safe relative POSIX path."""
    # Treat both separators as path boundaries; future changes must not allow traversal variants.
    raw = os.fspath(path)
    if not raw or "\0" in raw:
        raise ValueError("artifact path must be a non-empty relative path")
    if PureWindowsPath(raw).is_absolute() or PureWindowsPath(raw).drive:
        raise ValueError("artifact path must be relative")
    normalized = raw.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError("artifact path must be relative")
    parts = tuple(normalized.split("/"))
    if not parts:
        raise ValueError("artifact path must be a non-empty relative path")
    for part in parts:
        _validate_part(part)
    return PurePosixPath(*parts)


def _validate_part(part: str) -> None:
    """Reject path components that escape, collapse, or break on Windows."""
    # Keep metadata portable; future changes must preserve cross-platform artifact paths.
    if part in {"", ".", ".."}:
        raise ValueError("artifact path must not contain empty, current, or parent parts")
    device_name = part.split(".", 1)[0].upper()
    if device_name in _WINDOWS_RESERVED:
        raise ValueError("artifact path contains a reserved Windows device name")


def _json_bytes(value: Any) -> bytes:
    """Serialize JSON-compatible data deterministically as UTF-8."""
    # Disallow NaN and Infinity; future changes must keep artifacts strict JSON.
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def _metadata(path: str, size: int, sha256: str, count: int | None) -> dict[str, Any]:
    """Build JSON-compatible artifact metadata."""
    # Keep response fields stable; future changes must add fields without renaming these.
    result: dict[str, Any] = {"artifact": path, "size": size, "sha256": sha256}
    if count is not None:
        result["count"] = count
    return result


def _ensure_inside(root: Path, target: Path) -> None:
    """Fail if a resolved target escapes the artifact directory."""
    # Resolve existing parents to catch symlink escapes; future changes must keep this guard.
    root_resolved = root.resolve(strict=False)
    target_resolved = target.resolve(strict=False)
    try:
        target_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("artifact path escapes the artifact directory") from exc


def _remove_if_present(path: Path) -> None:
    """Remove a failed temporary artifact when it exists."""
    # Cleanup is best-effort for temp files only; future changes must not delete final artifacts here.
    try:
        path.unlink()
    except FileNotFoundError:
        return
