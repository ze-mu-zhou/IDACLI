"""Backend lifecycle for the unrestricted IDA CLI runtime."""

from __future__ import annotations

import importlib
import importlib.util
import os
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ai_helpers import AIHelpers
from .artifacts import ArtifactStore
from .runtime import PythonRuntime

_DEEP_DISCOVERY_ENV = "IDA_CLI_DEEP_IDA_DISCOVERY"
_CACHED_IDA_ROOT: Path | None = None


class KernelError(RuntimeError):
    """Raised when the kernel cannot satisfy an exact backend operation."""


@dataclass(frozen=True, slots=True)
class BackendInfo:
    """JSON-compatible backend status exposed to the AI runtime."""

    name: str
    target_path: str
    database_opened: bool
    ida_available: bool
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Return protocol-ready metadata for runtime globals."""
        return {
            "name": self.name,
            "target_path": self.target_path,
            "database_opened": self.database_opened,
            "ida_available": self.ida_available,
            "message": self.message,
        }


@dataclass(slots=True)
class KernelSession:
    """Own one backend, artifact store, helper object, and Python runtime."""

    target_path: str
    backend_info: BackendInfo
    artifact_store: ArtifactStore
    ai: AIHelpers
    runtime: PythonRuntime
    backend: Any | None = None
    closed: bool = False

    def close(self) -> None:
        """Close backend-owned resources exactly once when the kernel exits."""
        if self.closed:
            return
        self.closed = True
        if self.backend is not None and hasattr(self.backend, "close"):
            self.backend.close()


class PythonOnlyBackend:
    """Protocol-test backend that does not import IDA or open databases."""

    name = "python"

    def open(self, target_path: str) -> BackendInfo:
        """Expose a transparent non-IDA backend for protocol/runtime operation."""
        return BackendInfo(
            name=self.name,
            target_path=target_path,
            database_opened=False,
            ida_available=False,
            message="idapro is unavailable; running Python-only kernel",
        )


class IdaLibBackend:
    """Minimal idalib backend using Hex-Rays' `idapro` module when available."""

    name = "idalib"

    def __init__(self, idapro: Any | None = None) -> None:
        """Allow tests to inject an idapro-shaped object without importing IDA."""
        self._idapro = idapro
        self._database_opened = False

    @classmethod
    def available(cls) -> bool:
        """Return whether the `idapro` module can be imported now."""
        _prepare_idalib_import_path()
        try:
            importlib.import_module("idapro")
        except ModuleNotFoundError:
            return False
        return True

    def open(self, target_path: str) -> BackendInfo:
        """Open the target database through idalib and wait for auto-analysis."""
        _prepare_idalib_import_path()
        idapro = self._idapro if self._idapro is not None else importlib.import_module("idapro")
        self._idapro = idapro
        try:
            status = idapro.open_database(target_path, True)
        except Exception as exc:
            raise KernelError(f"idapro.open_database failed for {target_path!r}: {exc}") from exc
        _require_open_database_success(target_path, status)
        self._database_opened = True
        try:
            _wait_for_auto_analysis()
        except Exception:
            self.close()
            raise
        return BackendInfo(
            name=self.name,
            target_path=target_path,
            database_opened=True,
            ida_available=True,
        )

    def close(self) -> None:
        """Close one opened database without silently discarding the contract."""
        if not self._database_opened:
            return
        idapro = self._idapro if self._idapro is not None else importlib.import_module("idapro")
        if not hasattr(idapro, "close_database"):
            raise KernelError("idapro.close_database is unavailable after opening a database")
        try:
            idapro.close_database(False)
        except Exception as exc:
            raise KernelError(f"idapro.close_database failed: {exc}") from exc
        self._database_opened = False


def create_session(
    target_path: str | os.PathLike[str],
    *,
    runs_dir: str | os.PathLike[str] = "runs",
    backend: Any | None = None,
) -> KernelSession:
    """Create one long-lived Python runtime session for the target."""
    target = _target_text(target_path)
    selected = _select_backend() if backend is None else backend
    backend_info = selected.open(target)
    try:
        artifact_store = ArtifactStore.create(runs_dir)
        ai = AIHelpers(artifact_store.artifact_dir)
        initial_globals = _ida_modules()
        initial_globals.update(
            {
                "__artifact_store__": artifact_store,
                "__backend__": backend_info.as_dict(),
            }
        )
        runtime = PythonRuntime(
            initial_globals=initial_globals,
            ai=ai,
            database_path=target,
            run_dir=str(artifact_store.run_dir),
        )
    except Exception:
        if hasattr(selected, "close"):
            selected.close()
        raise
    return KernelSession(
        target_path=target,
        backend_info=backend_info,
        artifact_store=artifact_store,
        ai=ai,
        runtime=runtime,
        backend=selected,
    )


def _select_backend() -> Any:
    """Select idalib when present; otherwise expose the transparent Python backend."""
    if IdaLibBackend.available():
        return IdaLibBackend()
    return PythonOnlyBackend()


def _prepare_idalib_import_path() -> None:
    """Expose bundled `idapro` through cheap probes before any slow fallback."""
    global _CACHED_IDA_ROOT
    if _idapro_importable():
        return
    if _CACHED_IDA_ROOT is not None and _activate_idalib_root(_CACHED_IDA_ROOT):
        return
    for root in _ida_install_candidates():
        if _activate_idalib_root(root):
            _CACHED_IDA_ROOT = root
            return
    if not _deep_discovery_enabled():
        return
    discovered = _discover_ida_install_root()
    if discovered is not None and _activate_idalib_root(discovered):
        _CACHED_IDA_ROOT = discovered


def _ida_install_candidates() -> tuple[Path, ...]:
    """Return IDA roots worth probing without requiring registry access."""
    candidates: list[Path] = []
    env_root = os.environ.get("IDADIR")
    if env_root:
        candidates.append(Path(env_root))
    if os.name == "nt":
        for drive in _local_drive_roots():
            candidates.extend(
                (
                    drive / "IDA",
                    drive / "IDA Pro",
                    drive / "IDA Professional",
                    drive / "Hex-Rays",
                )
            )
            for container_name in ("Program Files", "Program Files (x86)", "Tools", "Apps", "Applications"):
                candidates.extend(_matching_ida_children(drive / container_name))
        for key in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            container = os.environ.get(key)
            if container:
                candidates.extend(_matching_ida_children(Path(container)))
    return _dedupe_paths(candidates)


def _idapro_importable() -> bool:
    """Prefer officially installed or activated idapro before path injection."""
    return importlib.util.find_spec("idapro") is not None


def _activate_idalib_root(root: Path) -> bool:
    """Add one discovered IDA install to `sys.path` and publish `IDADIR`."""
    package_dir = root / "idalib" / "python"
    if not (package_dir / "idapro").is_dir():
        return False
    if str(package_dir) not in sys.path:
        sys.path.insert(0, str(package_dir))
    os.environ["IDADIR"] = str(root)
    return True


def _discover_ida_install_root() -> Path | None:
    """Recursively search local Windows drives for an install root as an opt-in fallback."""
    for root in _local_drive_roots():
        discovered = _scan_tree_for_ida_install(root)
        if discovered is not None:
            return discovered
    return None


def _deep_discovery_enabled() -> bool:
    """Keep full-drive discovery explicit because it is slow and Windows-specific."""
    value = os.environ.get(_DEEP_DISCOVERY_ENV, "")
    return value.lower() in {"1", "on", "true", "yes"}


def _local_drive_roots() -> tuple[Path, ...]:
    """Return existing Windows drive roots worth probing."""
    if os.name != "nt":
        return ()
    roots: list[Path] = []
    for letter in string.ascii_uppercase:
        drive = Path(f"{letter}:/")
        if drive.exists():
            roots.append(drive)
    return tuple(roots)


def _matching_ida_children(container: Path) -> tuple[Path, ...]:
    """Return direct child directories whose names look like IDA installs."""
    try:
        entries = tuple(os.scandir(container))
    except OSError:
        return ()
    matches: list[Path] = []
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        name = entry.name.lower()
        if "ida" in name or "hex-rays" in name:
            matches.append(Path(entry.path))
    return tuple(matches)


def _dedupe_paths(paths: list[Path]) -> tuple[Path, ...]:
    """Keep candidate order stable while removing duplicates."""
    seen: set[str] = set()
    ordered: list[Path] = []
    for path in paths:
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    return tuple(ordered)


def _scan_tree_for_ida_install(root: Path) -> Path | None:
    """Walk one drive tree until an `idalib/python/idapro` install is found."""
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = tuple(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            child = Path(entry.path)
            if _activate_idalib_root(child):
                return child
            if entry.name.lower() == "idalib" and (child / "python" / "idapro").is_dir():
                return child.parent
            stack.append(child)
    return None


def _target_text(target_path: str | os.PathLike[str]) -> str:
    """Validate and normalize a target path string without requiring existence."""
    target = os.fspath(target_path)
    if not target:
        raise KernelError("target path must not be empty")
    return str(Path(target))


def _wait_for_auto_analysis() -> None:
    """Wait for IDA auto-analysis when the module exists in the backend runtime."""
    try:
        ida_auto = importlib.import_module("ida_auto")
    except ModuleNotFoundError:
        return
    if hasattr(ida_auto, "auto_wait"):
        result = ida_auto.auto_wait()
        if result is False:
            raise KernelError("ida_auto.auto_wait reported an incomplete analysis state")


def _require_open_database_success(target_path: str, status: Any) -> None:
    """Validate the idalib open_database contract instead of guessing success."""
    if type(status) is bool:
        if status:
            return
        raise KernelError(f"idapro.open_database returned false for {target_path!r}")
    if type(status) is int:
        if status == 0:
            return
        raise KernelError(f"idapro.open_database returned error code {status} for {target_path!r}")
    raise KernelError(f"idapro.open_database returned unsupported status {status!r} for {target_path!r}")


def _ida_modules() -> dict[str, Any]:
    """Pre-import only the hottest IDAPython modules and leave the rest lazy."""
    modules: dict[str, Any] = {}
    for name in ("idaapi", "idautils", "idc"):
        try:
            modules[name] = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    return modules


__all__ = (
    "BackendInfo",
    "IdaLibBackend",
    "KernelError",
    "KernelSession",
    "PythonOnlyBackend",
    "create_session",
)
